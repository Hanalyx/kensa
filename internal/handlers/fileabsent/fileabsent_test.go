package fileabsent_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent/transport/local"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/fileabsent"
)

// captureCmd returns the exact shell command the handler produces for
// a given path, keyed for FakeTransport programming.
func captureCmd(path string) string {
	q := "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	return fmt.Sprintf(
		`if [ -e %[1]s ]; then printf 'EXISTS\n'; stat -c '%%a|%%U|%%G' %[1]s; ls -Zd %[1]s 2>/dev/null | awk '{print $1}'; cat %[1]s; else printf 'ABSENT\n'; fi`,
		q,
	)
}

// @spec handler-file-absent
// @ac AC-01
func TestApply_AC01_RemovesFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := fileabsent.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"path": "/etc/resolv.conf.bak"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "rm -f") {
		t.Errorf("expected rm -f; got %q", tp.Runs[0])
	}
}

// @spec handler-file-absent
// @ac AC-02
func TestApply_AC02_IsIdempotentForAbsentFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := fileabsent.New()
	// FakeTransport returns exit 0 by default; rm -f of absent file = 0.
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, api.Params{"path": "/etc/gone"}, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-file-absent
// @ac AC-03
func TestCapture_AC03_RecordsExistingFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/resolv.conf.bak"
	tp.Results[captureCmd(path)] = &api.CommandResult{
		Stdout: "EXISTS\n0600|root|root\nsystem_u:object_r:net_conf_t:s0\nnameserver 1.1.1.1\n",
	}
	h := fileabsent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"path": path})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != true {
		t.Errorf("file_existed=%v, want true", pre.Data["file_existed"])
	}
	if pre.Data["content"] != "nameserver 1.1.1.1\n" {
		t.Errorf("content=%q, want nameserver line", pre.Data["content"])
	}
	if pre.Data["mode"] != "0600" {
		t.Errorf("mode=%v, want 0600", pre.Data["mode"])
	}
}

// @spec handler-file-absent
// @ac AC-04
func TestCapture_AC04_AbsentFileReturnsFileExistedFalse(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/gone"
	tp.Results[captureCmd(path)] = &api.CommandResult{Stdout: "ABSENT\n"}
	h := fileabsent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"path": path})
	if err != nil {
		t.Fatalf("Capture returned unexpected error: %v", err)
	}
	if pre.Data["file_existed"] != false {
		t.Errorf("file_existed=%v, want false", pre.Data["file_existed"])
	}
}

// @spec handler-file-absent
// @ac AC-05
func TestRollback_AC05_RecreatesFileWithAttrs(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := fileabsent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/resolv.conf.bak",
			"file_existed": true,
			"content":      "nameserver 1.1.1.1\n",
			"mode":         "0644",
			"owner":        "root",
			"group":        "root",
			"selinux":      "system_u:object_r:net_conf_t:s0",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "printf") {
		t.Errorf("expected printf write; got %q", cmd)
	}
	if !strings.Contains(cmd, "chmod 0644") {
		t.Errorf("expected chmod; got %q", cmd)
	}
}

// @spec handler-file-absent
// @ac AC-06
func TestRollback_AC06_NoOpWhenFileWasAbsent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := fileabsent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/gone",
			"file_existed": false,
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 0 {
		t.Errorf("got %d Run calls, want 0 (no-op rollback)", len(tp.Runs))
	}
}

// @spec handler-file-absent
// @ac AC-07
func TestCapture_AC07_PermissionsErrorReturnsErrCaptureIncomplete(t *testing.T) {
	// The capture command exits non-zero on a permissions error (stat EACCES).
	// The handler must return ErrCaptureIncomplete rather than silently treating
	// the failure as "file absent".
	tp := engine.NewFakeTransport()
	path := "/root/secret"
	tp.Results[captureCmd(path)] = &api.CommandResult{
		ExitCode: 1,
		Stderr:   "stat: cannot statx '/root/secret': Permission denied",
	}
	h := fileabsent.New()
	_, err := h.Capture(context.Background(), tp, api.Params{"path": path})
	if err == nil {
		t.Fatal("expected error for permissions-denied stat; got nil")
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = fileabsent.New()
}

// ─── P-003 migration tests (agent-mode fsatomic.Transport path) ────────

// TestApply_AgentMode_AtomicRemove locks the P-003 migration:
// when transport satisfies fsatomic.Transport, Apply uses
// AtomicRemove instead of the rm -f shell pipeline. Verified
// via the LocalTransport (real-fs) wrapping fsatomic primitives.
func TestApply_AgentMode_AtomicRemove(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "to-be-removed")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	tr := local.New()
	h := fileabsent.New()
	res, err := h.Apply(context.Background(), tr, api.Params{"path": target}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should succeed; got: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "atomically removed") {
		t.Errorf("Detail should mention 'atomically removed' (proves agent-mode path fired); got: %q", res.Detail)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("file should be gone; stat err: %v", err)
	}
}

// TestApply_AgentMode_AlreadyAbsentIsIdempotent locks the
// ErrNotExist → success translation. FMA flagged this:
// AtomicRemove returns ErrNotExist where rm -f silently
// succeeds. The migration MUST translate.
func TestApply_AgentMode_AlreadyAbsentIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "never-existed")

	tr := local.New()
	h := fileabsent.New()
	res, err := h.Apply(context.Background(), tr, api.Params{"path": target}, nil)
	if err != nil {
		t.Fatalf("Apply on absent path: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply on already-absent path should succeed (idempotent); got: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "idempotent") {
		t.Errorf("Detail should mention idempotent path; got: %q", res.Detail)
	}
}

// TestRollback_AgentMode_AtomicWrite locks the rollback
// re-creation via AtomicWrite when transport is
// fsatomic.Transport.
func TestRollback_AgentMode_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "to-be-restored")

	pre := &api.PreState{
		Mechanism:  "file_absent",
		Capturable: true,
		Data: map[string]interface{}{
			"path":         target,
			"file_existed": true,
			"content":      "captured content\n",
			"mode":         "0644",
			"owner":        "",
			"group":        "",
			"selinux":      "",
		},
	}

	tr := local.New()
	h := fileabsent.New()
	res, err := h.Rollback(context.Background(), tr, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Rollback should succeed; got: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "atomically recreated") {
		t.Errorf("Detail should mention 'atomically recreated'; got: %q", res.Detail)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "captured content\n" {
		t.Errorf("content: got %q, want %q", got, "captured content\n")
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode: got %o, want 0644", info.Mode().Perm())
	}
}

// TestRollback_AgentMode_RefusesMissingCapturedMode locks the
// fix/phase-2-rework F-003 fail-loud behavior: if Capture
// somehow recorded an empty `mode` for a present-at-capture
// file, Rollback refuses to silently default to 0o644
// (which would widen perms on a tightened file). The
// operator gets an actionable error.
func TestRollback_AgentMode_RefusesMissingCapturedMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "to-be-restored")
	pre := &api.PreState{
		Mechanism:  "file_absent",
		Capturable: true,
		Data: map[string]interface{}{
			"path":         target,
			"file_existed": true,
			"content":      "captured\n",
			"mode":         "", // simulated capture bug
			"owner":        "",
			"group":        "",
			"selinux":      "",
		},
	}
	tr := local.New()
	h := fileabsent.New()
	res, err := h.Rollback(context.Background(), tr, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if res.Success {
		t.Errorf("Rollback with empty captured mode MUST fail; got success: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "captured mode missing") {
		t.Errorf("Detail should name 'captured mode missing'; got: %q", res.Detail)
	}
	// File must not have been created with a defaulted mode.
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Errorf("file should not be created when rollback refuses; stat: %v", statErr)
	}
}
