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
	"fmt"
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

	// Build + write a framed ApplyRequest (post-L-009 typed
	// payload; the L-008 bytes payload is gone).
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 0xdeadbeef,
		Payload: &wirev1.Request_Apply{
			Apply: &wirev1.ApplyRequest{Mechanism: "file_content"},
		},
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal Request: %v", err)
	}
	if err := agent.Write(stdin, agent.FramePayload, reqBytes, nil); err != nil {
		t.Fatalf("Write frame to subprocess stdin: %v", err)
	}

	// Read back the typed Response. ApplyRequest produces
	// ApplyResponse (L-009 C-02 dispatch contract).
	_, respBytes, err := agent.Read(stdout, nil)
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
	if _, ok := resp.GetPayload().(*wirev1.Response_ApplyResp); !ok {
		t.Errorf("expected ApplyResp variant; got %T", resp.GetPayload())
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

// TestKensaAgent_TypedRequestsEcho locks L-009 AC-06: spawn the
// real binary, pipe ALL four typed Request variants
// (Apply/Capture/Rollback/Heartbeat) in order, verify each
// produces the matching Response variant. End-to-end coverage
// of the typed-payload dispatch contract.
//
// @spec agent-wire-handler-schema
// @ac AC-06
func TestKensaAgent_TypedRequestsEcho(t *testing.T) {
	repoRoot := findRepoRootE2E(t)
	binPath := filepath.Join(repoRoot, "bin", "kensa")
	if !fileExists(binPath) {
		t.Skipf("bin/kensa not built (run `make build`); skipping typed-E2E test")
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

	requests := []*wirev1.Request{
		{SchemaVersion: 1, CorrelationId: 100, Payload: &wirev1.Request_Apply{Apply: &wirev1.ApplyRequest{Mechanism: "file_permissions"}}},
		{SchemaVersion: 1, CorrelationId: 101, Payload: &wirev1.Request_Capture{Capture: &wirev1.CaptureRequest{Mechanism: "file_permissions"}}},
		{SchemaVersion: 1, CorrelationId: 102, Payload: &wirev1.Request_Rollback{Rollback: &wirev1.RollbackRequest{PreState: &wirev1.WirePreState{Mechanism: "file_permissions"}}}},
		{SchemaVersion: 1, CorrelationId: 103, Payload: &wirev1.Request_Heartbeat{Heartbeat: &wirev1.HeartbeatRequest{Token: 0xcafe}}},
	}
	for _, req := range requests {
		reqBytes, err := proto.Marshal(req)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := agent.Write(stdin, agent.FramePayload, reqBytes, nil); err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}

	wantVariants := []string{"*wirev1.Response_ApplyResp", "*wirev1.Response_CaptureResp", "*wirev1.Response_RollbackResp", "*wirev1.Response_HeartbeatAck"}
	for i, req := range requests {
		_, respBytes, err := agent.Read(stdout, nil)
		if err != nil {
			t.Fatalf("read response %d: %v; stderr=%q", i, err, stderr.String())
		}
		var resp wirev1.Response
		if err := proto.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("unmarshal response %d: %v", i, err)
		}
		if resp.GetCorrelationId() != req.GetCorrelationId() {
			t.Errorf("response %d correlation_id: got %d, want %d", i, resp.GetCorrelationId(), req.GetCorrelationId())
		}
		gotVariant := fmt.Sprintf("%T", resp.GetPayload())
		if gotVariant != wantVariants[i] {
			t.Errorf("response %d variant: got %s, want %s", i, gotVariant, wantVariants[i])
		}
	}

	// Heartbeat token must round-trip exactly (AC-07).
	// Re-read the last Response from above is a bit awkward;
	// just send another Heartbeat with a distinct token and
	// verify the ack.
	hbReq := &wirev1.Request{
		SchemaVersion: 1, CorrelationId: 999,
		Payload: &wirev1.Request_Heartbeat{Heartbeat: &wirev1.HeartbeatRequest{Token: 0xbaadf00d}},
	}
	hbBytes, _ := proto.Marshal(hbReq)
	_ = agent.Write(stdin, agent.FramePayload, hbBytes, nil)
	_, respBytes, err := agent.Read(stdout, nil)
	if err != nil {
		t.Fatalf("read hb response: %v", err)
	}
	var hbResp wirev1.Response
	_ = proto.Unmarshal(respBytes, &hbResp)
	ack, ok := hbResp.GetPayload().(*wirev1.Response_HeartbeatAck)
	if !ok {
		t.Fatalf("expected HeartbeatAck; got %T", hbResp.GetPayload())
	}
	if ack.HeartbeatAck.GetToken() != 0xbaadf00d {
		t.Errorf("heartbeat token round-trip: got %#x, want 0xbaadf00d", ack.HeartbeatAck.GetToken())
	}

	if err := stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("agent exited non-zero: %v; stderr=%q", err, stderr.String())
	}
}

// TestKensaAgent_SIGTERMWhileBlockedOnRead locks the assumption
// baked into spec C-07: when SIGTERM arrives while the agent is
// blocked in io.ReadFull, the 500ms grace-period os.Exit
// fallback in cmd/kensa/agent.go ensures the process exits
// within bounded time. Without that fallback, the loop would
// hang until the controller closed the SSH channel — Go's
// runtime poller does not reliably wake a blocked pipe Read
// when another goroutine calls Close. If a future kernel/
// runtime/Go-version change regresses the grace-period exit,
// this test catches it.
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

// findRepoRootE2E anchors to this test file's location via
// runtime.Caller so the path resolves the same regardless of
// the cwd `go test` happens to inherit. Walks up to the
// directory that contains go.mod.
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
