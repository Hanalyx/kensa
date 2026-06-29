package filepermissions_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/filepermissions"
)

// fakeStat is the canonical stat output for a 0644 root:root file
// with type-only SELinux context. Used as the FakeTransport's
// programmed response for the capture probe.
const fakeStatLine = "0644|root|0|root|0\nsystem_u:object_r:etc_t:s0"

// programCapture installs a FakeTransport response for the capture
// probe of path, returning a pre-state matching fakeStatLine.
func programCapture(t *testing.T, path string) *engine.FakeTransport {
	t.Helper()
	tp := engine.NewFakeTransport()
	// We don't know the exact command at programming time (it is
	// generated with shell quoting), so we install a wildcard match
	// by overriding the transport's Results map with the canonical
	// command shape that the handler will produce.
	cmd := "stat -c '%a|%U|%u|%G|%g' '" + path + "' && ls -Zd '" + path + "' 2>/dev/null | awk '{print $1}'"
	tp.Results[cmd] = &api.CommandResult{ExitCode: 0, Stdout: fakeStatLine}
	return tp
}

// @spec handler-file-permissions
// @ac AC-01
// TestApply_OwnerModeInjectionQuoted locks the fix for the command-injection
// found in the security review: owner/group/mode come from rule content, which
// is untrusted on the apply path. Before the fix they were spliced UNQUOTED, so
// owner "owadmin; touch /tmp/PWNED" ran the touch as root. They must now be
// shell-quoted so the malicious payload is an inert literal argument.
func TestApply_OwnerModeInjectionQuoted(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := filepermissions.New()
	if _, err := h.Apply(context.Background(), tp, api.Params{
		"path":  "/etc/foo",
		"owner": "root; touch /tmp/PWNED",
		"mode":  "0644; rm -rf /",
	}, nil); err != nil {
		t.Fatalf("Apply err: %v", err)
	}
	cmd := tp.Runs[0]
	// The whole malicious value must sit inside a single-quoted argument.
	for _, want := range []string{"chown 'root; touch /tmp/PWNED'", "chmod '0644; rm -rf /'"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("expected quoted (inert) argument %q; got: %s", want, cmd)
		}
	}
	// And there must be no bare command separator that escapes a quote.
	if strings.Contains(cmd, "; touch /tmp/PWNED '/etc/foo'") || strings.Contains(cmd, "; rm -rf / '/etc/foo'") {
		t.Errorf("injection escaped quoting: %s", cmd)
	}
}

func TestApply_AC01_SetsAllAttributes(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := filepermissions.New()

	res, err := h.Apply(context.Background(), tp, api.Params{
		"path":            "/etc/shadow",
		"owner":           "root",
		"group":           "root",
		"mode":            "0000",
		"selinux_context": "system_u:object_r:shadow_t:s0",
	}, nil)
	if err != nil {
		t.Fatalf("Apply err: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply Success=%v, want true (detail=%s)", res.Success, res.Detail)
	}
	// Verify the chained command included all three operations.
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	for _, want := range []string{"chown 'root:root'", "chmod '0000'", "chcon --no-dereference"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("apply pipeline missing %q\nfull cmd: %s", want, cmd)
		}
	}
}

// @spec handler-file-permissions
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-02")
	tp := engine.NewFakeTransport()
	h := filepermissions.New()
	params := api.Params{"path": "/etc/foo", "mode": "0644"}

	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, params, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d failed: err=%v success=%v", i+1, err, res.Success)
		}
	}
	// Each invocation should issue the same command. Idempotency at
	// the host level is guaranteed by chmod itself (chmod 0644 X is a
	// no-op when X already has mode 0644).
	if len(tp.Runs) != 3 {
		t.Errorf("got %d Run calls, want 3 (one per Apply)", len(tp.Runs))
	}
	for i, c := range tp.Runs {
		if !strings.Contains(c, "chmod '0644'") {
			t.Errorf("invocation %d cmd missing chmod: %s", i+1, c)
		}
	}
}

// @spec handler-file-permissions
// @ac AC-03
func TestCapture_AC03_RecordsAllFourAttributes(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-03")
	path := "/etc/shadow"
	tp := programCapture(t, path)
	h := filepermissions.New()

	pre, err := h.Capture(context.Background(), tp, api.Params{"path": path})
	if err != nil {
		t.Fatalf("Capture err: %v", err)
	}
	if pre == nil || pre.Data == nil {
		t.Fatal("expected non-nil pre-state with non-nil Data")
	}
	cases := map[string]string{
		"path":            path,
		"owner":           "root",
		"uid":             "0",
		"group":           "root",
		"gid":             "0",
		"mode":            "0644",
		"selinux_context": "system_u:object_r:etc_t:s0",
	}
	for k, want := range cases {
		got, _ := pre.Data[k].(string)
		if got != want {
			t.Errorf("Data[%q]=%q, want %q", k, got, want)
		}
	}
}

// @spec handler-file-permissions
// @ac AC-04
func TestCapture_AC04_NonExistentPathReturnsErrCaptureIncomplete(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-04")
	tp := engine.NewFakeTransport()
	// Program a stat failure (non-zero exit).
	cmd := "stat -c '%a|%U|%u|%G|%g' '/no/such/file' && ls -Zd '/no/such/file' 2>/dev/null | awk '{print $1}'"
	tp.Results[cmd] = &api.CommandResult{ExitCode: 1, Stderr: "stat: cannot statx '/no/such/file': No such file or directory"}

	h := filepermissions.New()
	_, err := h.Capture(context.Background(), tp, api.Params{"path": "/no/such/file"})
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
	if !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Errorf("got err=%v, want chain to ErrCaptureIncomplete", err)
	}
}

// @spec handler-file-permissions
// @ac AC-05
func TestRollback_AC05_RestoresAllAttributes(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-05")
	tp := engine.NewFakeTransport()
	h := filepermissions.New()

	pre := &api.PreState{
		Mechanism:  "file_permissions",
		Capturable: true,
		Data: map[string]interface{}{
			"path":            "/etc/shadow",
			"owner":           "root",
			"group":           "root",
			"mode":            "0640",
			"selinux_context": "system_u:object_r:shadow_t:s0",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback err: %v", err)
	}
	if !res.Success {
		t.Errorf("Rollback Success=%v, want true", res.Success)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	for _, want := range []string{"chown 'root:root'", "chmod '0640'", "chcon --no-dereference"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("rollback pipeline missing %q\nfull cmd: %s", want, cmd)
		}
	}
}

// @spec handler-file-permissions
// @ac AC-06
func TestRollback_AC06_IsIdempotent(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-06")
	tp := engine.NewFakeTransport()
	h := filepermissions.New()
	pre := &api.PreState{
		Capturable: true,
		Data: map[string]interface{}{
			"path": "/etc/foo",
			"mode": "0644",
		},
	}
	for i := 0; i < 3; i++ {
		res, err := h.Rollback(context.Background(), tp, pre)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
	if len(tp.Runs) != 3 {
		t.Errorf("got %d Run calls, want 3", len(tp.Runs))
	}
}

// @spec handler-file-permissions
// @ac AC-07
func TestApply_AC07_FailsCleanlyOnPermissionError(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-07")
	tp := engine.NewFakeTransport()
	// Override default to return permission-denied for any chmod cmd.
	// Our FakeTransport doesn't pattern-match; instead we set the
	// programmed result via the exact command we know will be issued.
	cmd := "chown 'root:root' '/etc/secret' && chmod '0600' '/etc/secret'"
	tp.Results[cmd] = &api.CommandResult{ExitCode: 1, Stderr: "chown: changing ownership of '/etc/secret': Operation not permitted"}

	h := filepermissions.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"path":  "/etc/secret",
		"owner": "root",
		"group": "root",
		"mode":  "0600",
	}, nil)
	if err != nil {
		t.Fatalf("Apply transport err: %v", err)
	}
	if res.Success {
		t.Error("expected Success=false on permission denied")
	}
	if !strings.Contains(res.Detail, "Operation not permitted") {
		t.Errorf("expected detail to include stderr; got %q", res.Detail)
	}
}

// @spec handler-file-permissions
// @ac AC-08
func TestRollback_AC08_UsesChconNotRestorecon(t *testing.T) {
	t.Log("// @spec handler-file-permissions")
	t.Log("// @ac AC-08")
	tp := engine.NewFakeTransport()
	h := filepermissions.New()
	pre := &api.PreState{
		Capturable: true,
		Data: map[string]interface{}{
			"path":            "/etc/foo",
			"selinux_context": "system_u:object_r:etc_t:s0",
		},
	}
	_, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback err: %v", err)
	}
	for _, c := range tp.Runs {
		if strings.Contains(c, "restorecon") {
			t.Errorf("rollback used restorecon (forbidden by spec C-04 / AC-08): %s", c)
		}
		if !strings.Contains(c, "chcon") {
			t.Errorf("rollback should use chcon: %s", c)
		}
	}
}

// Bonus: handler-interface AC-04 / AC-05 — file_permissions satisfies
// CombinedHandler at the type level.
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = filepermissions.New()
}
