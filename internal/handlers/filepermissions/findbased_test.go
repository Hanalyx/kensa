package filepermissions_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/filepermissions"
)

// findCaptureCmd is the exact capture command the handler builds for the
// round-trip fixture, so the FakeTransport can return programmed stat output.
const findCaptureCmd = `find '/var/log' -type f -perm /o+r -exec stat -c '%n|%a|%U|%u|%G|%g' {} +`

// TestFindBased_RoundTrip exercises the new capability end to end: Capture runs
// the find + per-file stat, Apply touches exactly the captured set, and
// Rollback restores each file's OWN prior owner/group/mode. This is the fix for
// the 29 find-based file_permissions rules whose remediation previously errored
// at capture with "missing required 'path'".
//
// @spec handler-file-permissions
// @ac AC-01
func TestFindBased_RoundTrip(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	// Two world-readable log files with DIFFERENT prior perms/groups.
	tp.Results[findCaptureCmd] = &api.CommandResult{ExitCode: 0, Stdout: "/var/log/foo|0644|root|0|root|0\n/var/log/bar|640|root|0|adm|4"}

	h := filepermissions.New()
	params := api.Params{
		"find_paths": []interface{}{"/var/log"},
		"find_type":  "f",
		"find_args":  "-perm /o+r",
		"mode":       "o-r", // symbolic mode — remove world-read
	}

	pre, err := h.Capture(context.Background(), tp, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	files, _ := pre.Data["files"].([]interface{})
	if len(files) != 2 {
		t.Fatalf("captured %d files, want 2", len(files))
	}

	if _, err := h.Apply(context.Background(), tp, params, pre); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Apply must chmod BOTH captured paths in one command (mode-only rule).
	if !ranContaining(tp, "chmod o-r '/var/log/foo' '/var/log/bar'") {
		t.Errorf("apply must chmod both captured paths; Runs=%v", tp.Runs)
	}

	if _, err := h.Rollback(context.Background(), tp, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	// Rollback restores EACH file to its own prior mode + owner:group.
	for _, want := range []string{
		"chown root:root '/var/log/foo'", "chmod 0644 '/var/log/foo'",
		"chown root:adm '/var/log/bar'", "chmod 0640 '/var/log/bar'", // 640 padded to 0640
	} {
		if !ranContaining(tp, want) {
			t.Errorf("rollback missing %q; Runs=%v", want, tp.Runs)
		}
	}
}

// TestFindBased_NoMatches: a compliant host where find matches nothing — capture
// records an empty set, apply and rollback are no-ops, no error.
func TestFindBased_NoMatches(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results[findCaptureCmd] = &api.CommandResult{ExitCode: 0, Stdout: ""}
	h := filepermissions.New()
	params := api.Params{"find_paths": []interface{}{"/var/log"}, "find_type": "f", "find_args": "-perm /o+r", "mode": "o-r"}

	pre, err := h.Capture(context.Background(), tp, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if r, err := h.Apply(context.Background(), tp, params, pre); err != nil || !r.Success {
		t.Fatalf("Apply no-op: err=%v success=%v", err, r.Success)
	}
	if r, err := h.Rollback(context.Background(), tp, pre); err != nil || !r.Success {
		t.Fatalf("Rollback no-op: err=%v success=%v", err, r.Success)
	}
}

// TestFindBased_CapRefusal: more than maxFindFiles matches must refuse at
// capture (ErrCaptureIncomplete) rather than capture a partial, un-rollback-able
// pre-state.
func TestFindBased_CapRefusal(t *testing.T) {
	tp := engine.NewFakeTransport()
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&sb, "/var/log/f%d|0644|root|0|root|0\n", i)
	}
	tp.Results[findCaptureCmd] = &api.CommandResult{ExitCode: 0, Stdout: sb.String()}
	h := filepermissions.New()
	params := api.Params{"find_paths": []interface{}{"/var/log"}, "find_type": "f", "find_args": "-perm /o+r", "mode": "o-r"}

	_, err := h.Capture(context.Background(), tp, params)
	if !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Fatalf("expected ErrCaptureIncomplete above the file cap, got %v", err)
	}
}

// TestFindBased_InjectionGuard: find_args must reject command-injection vectors
// (action predicates, shell metacharacters, unescaped parens) and accept the
// real corpus forms (escaped grouping, quoted globs, simple tests).
func TestFindBased_InjectionGuard(t *testing.T) {
	h := filepermissions.New()
	reject := []string{
		"-exec rm -rf / {} +",       // find action predicate
		"-perm /o+r -delete",        // destructive action
		"! -user root; rm -rf /",    // command chaining
		"$(rm -rf /)",               // command substitution
		"`id`",                      // backtick substitution
		"! -user root | sh",         // pipe
		"-perm -0002 > /etc/passwd", // redirect
		"( id )",                    // bare-paren subshell
	}
	for _, fa := range reject {
		params := api.Params{"find_paths": []interface{}{"/x"}, "find_args": fa, "owner": "root"}
		if _, err := h.Capture(context.Background(), engine.NewFakeTransport(), params); err == nil {
			t.Errorf("find_args %q must be rejected", fa)
		}
	}
	accept := []string{
		"! -user root",
		"-perm /o+r",
		`\( -name '*.conf' -o -name '*.rules' \)`,
		"-xdev -perm -0002 ! -perm -1000",
		"-maxdepth 2 -name '.*' -perm /o+w",
	}
	for _, fa := range accept {
		params := api.Params{"find_paths": []interface{}{"/x"}, "find_args": fa, "owner": "root"}
		// Capture will try to run find (FakeTransport returns empty OK), so a
		// decode/validation rejection is the only way these error.
		if _, err := h.Capture(context.Background(), engine.NewFakeTransport(), params); err != nil {
			t.Errorf("find_args %q must be accepted, got %v", fa, err)
		}
	}
}

func ranContaining(tp *engine.FakeTransport, sub string) bool {
	for _, c := range tp.Runs {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}
