package configsetdropin_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent/transport/local"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/configsetdropin"
)

// @spec handler-config-set-dropin
// @ac AC-01
func TestApply_AC01_WritesDropinFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configsetdropin.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"path":  "/etc/systemd/system/sshd.service.d/kensa.conf",
		"key":   "LimitNOFILE",
		"value": "65536",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "mkdir -p") {
		t.Errorf("expected mkdir -p; got %q", cmd)
	}
	if !strings.Contains(cmd, "LimitNOFILE=65536") {
		t.Errorf("expected LimitNOFILE=65536 in content; got %q", cmd)
	}
	if !strings.Contains(cmd, "Managed by Kensa") {
		t.Errorf("expected Kensa header; got %q", cmd)
	}
}

// @spec handler-config-set-dropin
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configsetdropin.New()
	params := api.Params{
		"path": "/etc/systemd/system/sshd.service.d/kensa.conf",
		"key":  "LimitNOFILE", "value": "65536",
	}
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, params, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-config-set-dropin
// @ac AC-03
func TestCapture_AC03_RecordsExistingDropin(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/systemd/system/sshd.service.d/kensa.conf"
	qPath := "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	tp.Results["test -e "+qPath+" && cat "+qPath+" || printf '__KENSA_ABSENT__'"] =
		&api.CommandResult{Stdout: "# Managed by Kensa.\nLimitNOFILE=65536\n"}

	h := configsetdropin.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"path": path, "key": "LimitNOFILE", "value": "131072",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != true {
		t.Errorf("file_existed=%v, want true", pre.Data["file_existed"])
	}
	if !strings.Contains(pre.Data["prior_content"].(string), "LimitNOFILE=65536") {
		t.Errorf("prior_content missing expected line; got %q", pre.Data["prior_content"])
	}
}

// @spec handler-config-set-dropin
// @ac AC-04
func TestCapture_AC04_AbsentDropinRecordsFileExistedFalse(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/systemd/system/sshd.service.d/kensa.conf"
	qPath := "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	tp.Results["test -e "+qPath+" && cat "+qPath+" || printf '__KENSA_ABSENT__'"] =
		&api.CommandResult{Stdout: "__KENSA_ABSENT__"}

	h := configsetdropin.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"path": path, "key": "LimitNOFILE", "value": "65536",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != false {
		t.Errorf("file_existed=%v, want false", pre.Data["file_existed"])
	}
}

// @spec handler-config-set-dropin
// @ac AC-05
func TestRollback_AC05_RestoresPriorContent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configsetdropin.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":          "/etc/systemd/system/sshd.service.d/kensa.conf",
			"file_existed":  true,
			"prior_content": "# Managed by Kensa.\nLimitNOFILE=65536\n",
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
	if !strings.Contains(tp.Runs[0], "printf") {
		t.Errorf("expected printf restore; got %q", tp.Runs[0])
	}
}

// @spec handler-config-set-dropin
// @ac AC-06
func TestRollback_AC06_RemovesDropinWhenPriorWasAbsent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configsetdropin.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/systemd/system/sshd.service.d/kensa.conf",
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
	if !strings.Contains(tp.Runs[0], "rm -f") {
		t.Errorf("expected rm -f; got %q", tp.Runs[0])
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = configsetdropin.New()
}

// ─── P-005 migration tests (agent-mode AtomicTransport path) ────────────

// TestApply_AgentMode_AtomicWrite locks the new-file path
// of the P-005 migration: AtomicWrite creates the drop-in
// at a fresh path. MkdirAll handles missing parent dir.
func TestApply_AgentMode_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	// Drop-in under a subdir that doesn't exist yet — exercise
	// the MkdirAll path.
	target := filepath.Join(dir, "sysctl.d", "99-kensa.conf")

	tr := local.New()
	h := configsetdropin.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"path":  target,
		"key":   "kernel.dmesg_restrict",
		"value": "1",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should succeed; got: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "atomically wrote") {
		t.Errorf("Detail should mention 'atomically wrote' (agent-mode path); got: %q", res.Detail)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "kernel.dmesg_restrict") || !strings.Contains(string(got), "Managed by Kensa") {
		t.Errorf("drop-in content: %q", got)
	}
}

// TestApply_AgentMode_ReApplyOverwrites locks the FMA's
// "ErrAlreadyExists fallback to AtomicReplace" contract:
// re-applying against an existing drop-in MUST overwrite,
// not error.
func TestApply_AgentMode_ReApplyOverwrites(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "99-kensa.conf")

	tr := local.New()
	h := configsetdropin.New()

	// First Apply.
	if _, err := h.Apply(context.Background(), tr, api.Params{
		"path": target, "key": "k", "value": "1",
	}, nil); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// Re-Apply with different value — must overwrite,
	// not return ErrAlreadyExists.
	res, err := h.Apply(context.Background(), tr, api.Params{
		"path": target, "key": "k", "value": "2",
	}, nil)
	if err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("re-Apply should succeed (overwrite via AtomicReplace fallback); got: %s", res.Detail)
	}
	got, _ := os.ReadFile(target)
	if !strings.Contains(string(got), "k=2") {
		t.Errorf("re-Apply should have overwritten with new value; got: %q", got)
	}
}

// TestApply_AgentMode_ReApplyPreservesTightenedMode locks
// the fix/phase-2-rework F-003 fix: on re-Apply against an
// existing drop-in that an operator tightened to 0o600
// (e.g. a drop-in containing secrets), AtomicReplace
// preserves the current mode bits rather than silently
// widening to 0o644.
func TestApply_AgentMode_ReApplyPreservesTightenedMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "99-tightened.conf")
	// Seed an existing tightened drop-in.
	if err := os.WriteFile(target, []byte("# old\nk=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tr := local.New()
	h := configsetdropin.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"path": target, "key": "k", "value": "2",
	}, nil)
	if err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("re-Apply should succeed; got: %s", res.Detail)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("re-Apply silently widened mode: got %o, want 0600", info.Mode().Perm())
	}
}

// TestRollback_AgentMode_RemovesWhenFileWasAbsent locks
// the file_existed=false rollback path: AtomicRemove.
func TestRollback_AgentMode_RemovesWhenFileWasAbsent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "to-be-removed.conf")
	// Create the file as if Apply put it there.
	if err := os.WriteFile(target, []byte("from-apply"), 0o644); err != nil {
		t.Fatal(err)
	}

	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":          target,
			"file_existed":  false,
			"prior_content": "",
		},
	}

	tr := local.New()
	h := configsetdropin.New()
	res, err := h.Rollback(context.Background(), tr, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Rollback should succeed; got: %s", res.Detail)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("file should be gone; stat: %v", err)
	}
}

// TestRollback_AgentMode_RestoresPriorContent locks the
// file_existed=true rollback path: AtomicReplace with the
// captured priorContent.
func TestRollback_AgentMode_RestoresPriorContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existed.conf")
	if err := os.WriteFile(target, []byte("apply-modified"), 0o644); err != nil {
		t.Fatal(err)
	}

	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":          target,
			"file_existed":  true,
			"prior_content": "original-bytes",
		},
	}

	tr := local.New()
	h := configsetdropin.New()
	res, err := h.Rollback(context.Background(), tr, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Rollback should succeed; got: %s", res.Detail)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original-bytes" {
		t.Errorf("content after rollback: got %q, want %q", got, "original-bytes")
	}
}
