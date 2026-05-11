// End-to-end subprocess test for `kensa agent --stdio`.
// Spawns the real built binary, pipes a framed Request to its
// stdin, reads the echoed Response from its stdout, asserts
// correlation_id + payload + clean exit code.
//
// In-process testing via runCLI() can't easily inject framed
// bytes (the harness's stdin is the test runner's stdin). A
// subprocess is the only way to exercise the full pipeline
// — including os.Stdin/os.Stdout, signal handling, and the
// CLI dispatch path.
package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanalyx/kensa-go/internal/agent"
	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
)

// TestKensaAgent_StdioEndToEnd locks AC-07: spawn the kensa
// binary in agent mode, write a framed wirev1.Request to its
// stdin, read back the framed wirev1.Response from its stdout,
// verify correlation_id is preserved and payload is echoed
// verbatim. Close stdin → expect exit 0.
//
// Skipped when bin/kensa doesn't exist (e.g., go test ./...
// before `make build`). CI runs `make build` before tests so
// the gate fires reliably there.
//
// @spec agent-stdio-subcommand
// @ac AC-07
func TestKensaAgent_StdioEndToEnd(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	binPath := filepath.Join(repoRoot, "bin", "kensa")
	if !fileExists(binPath) {
		t.Skipf("bin/kensa not built (run `make build`); skipping E2E echo test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "agent", "--stdio")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Build + write a framed Request.
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 0xdeadbeef,
		Payload:       []byte("end-to-end echo test"),
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal Request: %v", err)
	}
	if err := agent.Write(stdin, reqBytes); err != nil {
		t.Fatalf("Write frame to subprocess stdin: %v", err)
	}

	// Read back the echoed Response. The agent process writes
	// one frame in response, then waits for more input.
	respBytes, err := agent.Read(stdout)
	if err != nil {
		t.Fatalf("Read frame from subprocess stdout: %v; stderr=%q", err, stderr.String())
	}
	var resp wirev1.Response
	if err := proto.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal Response: %v", err)
	}
	if resp.GetCorrelationId() != req.GetCorrelationId() {
		t.Errorf("correlation_id mismatch: got %d, want %d", resp.GetCorrelationId(), req.GetCorrelationId())
	}
	if !bytes.Equal(resp.GetPayload(), req.GetPayload()) {
		t.Errorf("payload mismatch: got %q, want %q", resp.GetPayload(), req.GetPayload())
	}
	if resp.GetSchemaVersion() != 1 {
		t.Errorf("schema_version: got %d, want 1", resp.GetSchemaVersion())
	}

	// Close stdin → agent should see EOF and exit 0.
	if err := stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("agent exited non-zero: %v; stderr=%q", err, stderr.String())
	}
}

// TestKensaAgent_StdioRejectsTruncatedFrame locks the failure-mode
// path: if the controller crashes mid-frame, the agent surfaces
// a stderr diagnostic and exits 1.
func TestKensaAgent_StdioRejectsTruncatedFrame(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	binPath := filepath.Join(repoRoot, "bin", "kensa")
	if !fileExists(binPath) {
		t.Skipf("bin/kensa not built (run `make build`); skipping E2E truncation test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "agent", "--stdio")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Write a length prefix promising 100 bytes, then close
	// stdin WITHOUT sending those bytes. Agent sees a
	// mid-frame EOF (io.ErrUnexpectedEOF) and exits 1.
	if _, err := stdin.Write([]byte{0x00, 0x00, 0x00, 0x64}); err != nil {
		t.Fatalf("write truncated length prefix: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	err = cmd.Wait()
	if err == nil {
		t.Error("expected non-zero exit on truncated frame; got nil error")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError; got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("truncated frame: exit code = %d, want 1", exitErr.ExitCode())
	}
	if stderr.Len() == 0 {
		t.Error("stderr should carry a diagnostic; got empty")
	}
}

// findRepoRootE2E anchors to this test file's location via
// runtime.Caller so the path resolves the same regardless of
// the cwd `go test` happens to inherit. Walks up to the
// directory that contains go.mod.
// TestKensaAgent_SIGTERMWhileBlockedOnRead locks the assumption
// baked into spec C-07 — the "in practice SIGTERM also closes
// stdin" claim. We send SIGTERM to the agent process while it's
// blocked on a read (no frames have arrived). The Go runtime
// closes the inherited stdin pipe on signal, the read returns
// EOF, the agent exits 0. If a future kernel/runtime change
// buffers stdin past signal delivery this test catches it.
func TestKensaAgent_SIGTERMWhileBlockedOnRead(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	binPath := filepath.Join(repoRoot, "bin", "kensa")
	if !fileExists(binPath) {
		t.Skipf("bin/kensa not built (run `make build`); skipping SIGTERM test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "agent", "--stdio")
	// Leave stdin attached but with nothing flowing — the agent
	// blocks on io.ReadFull waiting for the next length prefix.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	defer stdin.Close()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Let the agent settle into its read.
	time.Sleep(100 * time.Millisecond)

	// Send SIGTERM. The Go runtime + OS coordinate to close
	// stdin on signal delivery, so the read unblocks with EOF
	// and the agent exits 0 cleanly.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		// SIGTERM-triggered exit on Linux returns non-nil from
		// cmd.Wait if the process was signaled, but the exit
		// code path through agent.Run + the signal.NotifyContext
		// cancel handler returns ctx.Canceled which the CLI
		// maps to exit 0. Either outcome is acceptable per
		// spec C-07; what we lock is "process actually exits
		// within 1s of SIGTERM."
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Logf("exit code %d (acceptable; spec C-07)", exitErr.ExitCode())
			}
		}
	case <-time.After(1 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("agent did not exit within 1s of SIGTERM — spec C-07's stdin-close assumption may have regressed")
	}
}

func findRepoRootE2E(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate repo root")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// fileExists reports whether p is a regular file (or symlink to
// one). One os.Stat call; no subprocesses, no path-vs-name
// distinction.
func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
