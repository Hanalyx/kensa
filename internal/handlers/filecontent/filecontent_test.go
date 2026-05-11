package filecontent_test

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
	"github.com/Hanalyx/kensa-go/internal/handlers/filecontent"
)

// captureOutput returns the fake capture stdout for an existing file.
func existingFileCapture(mode, owner, group, selinux, content string) string {
	return "EXISTS\n" + mode + "|" + owner + "|" + group + "\n" + selinux + "\n" + content
}

// @spec handler-file-content
// @ac AC-01
func TestApply_AC01_WritesContent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := filecontent.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"path":    "/etc/motd",
		"content": "Managed by Kensa.\n",
		"mode":    "0644",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// Apply chains write + chmod into a single &&-joined Run call.
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1 (write && chmod chain)", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "printf") {
		t.Errorf("expected printf write cmd; got %q", cmd)
	}
	if !strings.Contains(cmd, "chmod") {
		t.Errorf("expected chmod in chained cmd; got %q", cmd)
	}
}

// @spec handler-file-content
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := filecontent.New()
	params := api.Params{"path": "/etc/motd", "content": "hello\n"}
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, params, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-file-content
// @ac AC-03
func TestCapture_AC03_RecordsExistingFile(t *testing.T) {
	tp := engine.NewFakeTransport()
	// The capture command uses a shell one-liner; we match it via a
	// programmed result keyed to the exact quoting the handler produces.
	path := "/etc/motd"
	tp.Results[captureCmd(path)] = &api.CommandResult{
		Stdout: existingFileCapture("0644", "root", "root", "system_u:object_r:etc_t:s0", "hello\n"),
	}

	h := filecontent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"path": path, "content": "new"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != true {
		t.Errorf("file_existed=%v, want true", pre.Data["file_existed"])
	}
	if pre.Data["content"] != "hello\n" {
		t.Errorf("content=%q, want hello\\n", pre.Data["content"])
	}
	if pre.Data["mode"] != "0644" {
		t.Errorf("mode=%v, want 0644", pre.Data["mode"])
	}
}

// @spec handler-file-content
// @ac AC-04
func TestCapture_AC04_AbsentFileIsNotAnError(t *testing.T) {
	tp := engine.NewFakeTransport()
	path := "/etc/nonexistent"
	tp.Results[captureCmd(path)] = &api.CommandResult{
		Stdout: "ABSENT\n",
	}

	h := filecontent.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"path": path, "content": "x"})
	if err != nil {
		t.Fatalf("Capture returned unexpected error for absent file: %v", err)
	}
	if pre.Data["file_existed"] != false {
		t.Errorf("file_existed=%v, want false", pre.Data["file_existed"])
	}
}

// @spec handler-file-content
// @ac AC-05
func TestRollback_AC05_RestoresPriorContent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := filecontent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/motd",
			"file_existed": true,
			"content":      "original content\n",
			"mode":         "0644",
			"owner":        "root",
			"group":        "root",
			"selinux":      "system_u:object_r:etc_t:s0",
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
		t.Errorf("expected printf restore; got %q", cmd)
	}
	if !strings.Contains(cmd, "chmod 0644") {
		t.Errorf("expected chmod in restore pipeline; got %q", cmd)
	}
	if !strings.Contains(cmd, "chown root:root") {
		t.Errorf("expected chown in restore pipeline; got %q", cmd)
	}
	if !strings.Contains(cmd, "chcon") {
		t.Errorf("expected chcon in restore pipeline; got %q", cmd)
	}
}

// @spec handler-file-content
// @ac AC-06
func TestRollback_AC06_RemovesFileWhenPriorWasAbsent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := filecontent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/motd",
			"file_existed": false,
			"content":      "",
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
	if !strings.Contains(tp.Runs[0], "rm -f") {
		t.Errorf("expected rm -f; got %q", tp.Runs[0])
	}
}

// @spec handler-file-content
// @ac AC-07
func TestRollback_AC07_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := filecontent.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/motd",
			"file_existed": true,
			"content":      "hello\n",
			"mode":         "0644",
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

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = filecontent.New()
}

// ─── P-002 migration tests (agent-mode AtomicTransport path) ────────────

// TestApply_AgentMode_NewFile_AtomicWrite locks the new-file
// branch of Apply: AtomicWrite when the target doesn't exist.
func TestApply_AgentMode_NewFile_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fresh.conf")

	tr := local.New()
	h := filecontent.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"path":    target,
		"content": "hello\n",
		"mode":    "0640",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should succeed; got: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "atomically wrote") {
		t.Errorf("Detail should mention 'atomically wrote' (agent-mode); got: %q", res.Detail)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "hello\n" {
		t.Errorf("content: got %q, want %q", got, "hello\n")
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode: got %o, want 0640", info.Mode().Perm())
	}
}

// TestApply_AgentMode_ExistingFile_AtomicReplace locks the
// replace branch: AtomicReplace preserves the inode (well,
// via Renameat2 actually replaces the entry, but readers see
// the file continuously).
func TestApply_AgentMode_ExistingFile_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing.conf")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	tr := local.New()
	h := filecontent.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"path":    target,
		"content": "new content",
		"mode":    "0644",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should succeed; got: %s", res.Detail)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new content" {
		t.Errorf("content: got %q, want %q", got, "new content")
	}
}

// TestApply_AgentMode_EmptyModePreservesExisting locks the
// fix/phase-2-rework F-003 fix: when a rule omits `mode` and
// the target file already exists, Apply preserves the file's
// current mode bits rather than silently widening to 0o644.
// This was P0-A in the post-merge correctness review.
func TestApply_AgentMode_EmptyModePreservesExisting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tightened.conf")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	tr := local.New()
	h := filecontent.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"path":    target,
		"content": "new secret",
		// mode intentionally omitted
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should succeed; got: %s", res.Detail)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode silently widened: got %o, want 0600 (preserved)", info.Mode().Perm())
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new secret" {
		t.Errorf("content: got %q, want %q", got, "new secret")
	}
}

// TestApply_AgentMode_RejectsBadMode locks the FMA Q1.a
// concern: mode strings the Go parser can't handle surface
// as a clear error rather than corrupting bytes.
func TestApply_AgentMode_RejectsBadMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "bad-mode.conf")

	tr := local.New()
	h := filecontent.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"path":    target,
		"content": "x",
		"mode":    "u=rw,g=r,o=r", // symbolic notation; Go parser rejects
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Success {
		t.Error("Apply with invalid mode string should NOT succeed")
	}
	if !strings.Contains(res.Detail, "parse mode") {
		t.Errorf("Detail should mention parse mode failure; got: %q", res.Detail)
	}
	// File MUST NOT have been written.
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("file should not exist; stat: %v", err)
	}
}

// TestRollback_AgentMode_RemovesWhenWasAbsent locks the
// file_existed=false rollback branch.
func TestRollback_AgentMode_RemovesWhenWasAbsent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "to-remove.conf")
	if err := os.WriteFile(target, []byte("from-apply"), 0o644); err != nil {
		t.Fatal(err)
	}

	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         target,
			"file_existed": false,
		},
	}
	tr := local.New()
	h := filecontent.New()
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

// TestRollback_AgentMode_RestoresContent locks the
// file_existed=true rollback branch.
func TestRollback_AgentMode_RestoresContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "restored.conf")
	if err := os.WriteFile(target, []byte("apply-modified"), 0o644); err != nil {
		t.Fatal(err)
	}

	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":         target,
			"file_existed": true,
			"content":      "original-bytes\n",
			"mode":         "0640",
		},
	}
	tr := local.New()
	h := filecontent.New()
	res, err := h.Rollback(context.Background(), tr, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Rollback should succeed; got: %s", res.Detail)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original-bytes\n" {
		t.Errorf("content: got %q, want %q", got, "original-bytes\n")
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode after rollback: got %o, want 0640", info.Mode().Perm())
	}
}

// captureCmd returns the exact shell command the handler produces for
// a given path, so tests can program FakeTransport responses.
func captureCmd(path string) string {
	q := "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
	return fmt.Sprintf(
		`if [ -e %[1]s ]; then printf 'EXISTS\n'; stat -c '%%a|%%U|%%G' %[1]s; ls -Zd %[1]s 2>/dev/null | awk '{print $1}'; cat %[1]s; else printf 'ABSENT\n'; fi`,
		q,
	)
}
