package pidfd

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPidfd_ProbeSupport: AC-01. On any test host the loop
// runs on (modern Linux), ProbeSupport returns nil. The
// ENOSYS branch is unreachable here; that path is verified
// via inspection of the probe code rather than a mock.
func TestPidfd_ProbeSupport(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		if errors.Is(err, ErrKernelTooOld) {
			t.Skip("kernel < 5.3 — pidfd_open unsupported, skipping rest of suite")
		}
		t.Fatalf("ProbeSupport: %v", err)
	}
}

// TestPidfd_FiresOnProcessExit: AC-02.
func TestPidfd_FiresOnProcessExit(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		t.Skip("ProbeSupport failed:", err)
	}
	// Fork a child that sleeps; we'll signal it to exit.
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	p, err := Open(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Kill the child in a goroutine after a brief delay.
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = cmd.Process.Kill()
	}()

	start := time.Now()
	if err := p.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait returned too late: %v (expected ~100-200ms)", elapsed)
	}
}

// TestPidfd_DoesNotFireOnUnrelatedExit: AC-03.
func TestPidfd_DoesNotFireOnUnrelatedExit(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		t.Skip("ProbeSupport failed:", err)
	}
	// Fork two sleep children; pidfd targets A; we'll kill B.
	cmdA := exec.Command("/bin/sleep", "10")
	if err := cmdA.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmdA.Process.Kill()
		_ = cmdA.Wait()
	}()
	cmdB := exec.Command("/bin/sleep", "10")
	if err := cmdB.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmdB.Process.Kill()
		_ = cmdB.Wait()
	}()

	p, err := Open(cmdA.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Kill child B.
	if err := cmdB.Process.Kill(); err != nil {
		t.Fatal(err)
	}

	// Assert pidfd-on-A does NOT fire within 1s. Reviewer
	// flagged 300ms as too thin under loaded CI.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err = p.Wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("pidfd fired for unrelated process exit; got: %v", err)
	}
}

// TestPidfd_ContextCancel: AC-04.
func TestPidfd_ContextCancel(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		t.Skip("ProbeSupport failed:", err)
	}
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	p, err := Open(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = p.Wait(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded; got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait took too long after ctx cancel: %v", elapsed)
	}
}

// TestPidfd_CloseIdempotent: AC-05.
func TestPidfd_CloseIdempotent(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		t.Skip("ProbeSupport failed:", err)
	}
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	p, err := Open(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := p.Wait(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Wait after Close: expected ErrClosed; got: %v", err)
	}
	if fd := p.FD(); fd != -1 {
		t.Errorf("FD after Close: got %d, want -1", fd)
	}
}

// TestPidfd_PIDAccessor: PID() returns what we passed in.
func TestPidfd_PIDAccessor(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		t.Skip("ProbeSupport failed:", err)
	}
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	p, err := Open(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if got := p.PID(); got != cmd.Process.Pid {
		t.Errorf("PID(): got %d, want %d", got, cmd.Process.Pid)
	}
}

// TestPidfd_OpenParent: smoke test — the test process has a
// parent (Go test runner), so OpenParent should succeed.
func TestPidfd_OpenParent(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		t.Skip("ProbeSupport failed:", err)
	}
	p, err := OpenParent()
	if err != nil {
		t.Fatalf("OpenParent: %v", err)
	}
	defer p.Close()
	if p.PID() <= 1 {
		t.Errorf("OpenParent PID: got %d, want >1", p.PID())
	}
}

// TestPidfd_OpenNonExistentPID: a PID that doesn't exist
// returns a wrapped ESRCH.
func TestPidfd_OpenNonExistentPID(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		t.Skip("ProbeSupport failed:", err)
	}
	// PID 0 is the kernel-task placeholder; pidfd_open(0)
	// would refer to the current process per the man page;
	// use a large unlikely-to-exist PID instead.
	_, err := Open(0x7fffffff)
	if !errors.Is(err, unix.ESRCH) {
		t.Fatalf("expected wrapped ESRCH; got: %v", err)
	}
}

// TestPidfd_OpenParent_GoneSentinel: when called from a
// process whose parent has already exited (or which IS init
// in a container with ppid=0), OpenParent returns
// ErrParentGone. Hard to test directly without a forked
// daemonized child; instead verify the sentinel is returned
// for the manually-constructed ppid≤1 path by setting up
// a child that calls OpenParent after its parent exited.
// For now, the simpler smoke test: just call OpenParent
// from this normal test process and assert no
// ErrParentGone (test runner is a real parent).
func TestPidfd_OpenParent_NotGoneInNormalRun(t *testing.T) {
	if err := ProbeSupport(); err != nil {
		t.Skip("ProbeSupport failed:", err)
	}
	p, err := OpenParent()
	if err != nil {
		t.Fatalf("OpenParent in normal test run: %v (expected nil — test runner is alive)", err)
	}
	defer p.Close()
	if p.PID() <= 1 {
		t.Errorf("OpenParent PID: got %d, expected >1", p.PID())
	}
}
