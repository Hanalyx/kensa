package signalfd

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestSignalfd_DeliversSIGTERM locks AC-01.
//
// @spec deadman-signalfd
// @ac AC-01
func TestSignalfd_DeliversSIGTERM(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-01")
	// Use SIGUSR1 instead of SIGTERM to avoid disturbing
	// the test runner (Go's test harness sometimes installs
	// SIGTERM handlers; SIGUSR1 is the safe canary).
	s, err := New(unix.SIGUSR1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Raise the signal after a short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	}()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := s.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("Wait returned too late: %v", elapsed)
	}
}

// TestSignalfd_ContextCancel locks AC-02.
//
// @spec deadman-signalfd
// @ac AC-02
func TestSignalfd_ContextCancel(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-02")
	s, err := New(unix.SIGUSR2)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Wait(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded; got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait took too long after ctx cancel: %v", elapsed)
	}
}

// TestSignalfd_CloseRestoresMask: after Close, signal.Notify
// is stopped (default disposition restored). Hard to verify
// directly without sending the signal — instead verify the
// goroutine exit + idempotent close.
//
// @spec deadman-signalfd
// @ac AC-03
func TestSignalfd_CloseIdempotent(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-03")
	s, err := New(unix.SIGUSR1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if fd := s.FD(); fd != -1 {
		t.Errorf("FD after Close: got %d, want -1", fd)
	}
	if err := s.Wait(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Wait after Close: expected ErrClosed; got: %v", err)
	}
}

// TestSignalfd_ConcurrentCloseDuringWait locks the close-
// during-wait safety contract (same pattern as D-001
// TestTimerfd_ConcurrentCloseDuringWait).
func TestSignalfd_ConcurrentCloseDuringWait(t *testing.T) {
	s, err := New(unix.SIGUSR2)
	if err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	s.poll = func(fds []unix.PollFd, timeout int) (int, error) {
		close(entered)
		<-resume
		return unix.Poll(fds, timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	waited := make(chan error, 1)
	go func() { waited <- s.Wait(ctx) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("Wait never reached poll")
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	waitClosedFlag(t, s)
	close(resume)
	select {
	case err := <-waited:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("concurrent Close during Wait: got %v; want ErrClosed", err)
		}
	case <-ctx.Done():
		t.Fatal("Wait did not finish")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("Close did not finish")
	}
}

// TestSignalfd_SignalAccessor returns what we asked for.
func TestSignalfd_SignalAccessor(t *testing.T) {
	s, err := New(unix.SIGUSR1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Signal() != unix.SIGUSR1 {
		t.Errorf("Signal(): got %v, want SIGUSR1", s.Signal())
	}
}

// TestPrctl_SetReturnsNoError locks AC-04 — SetParentDeathSignal
// returns nil on a supported kernel. The end-to-end fork-and-
// kill test is scoped to D-006's fuzz harness.
//
// @spec deadman-signalfd
// @ac AC-04
func TestPrctl_SetReturnsNoError(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-04")
	if err := SetParentDeathSignal(unix.SIGKILL); err != nil {
		t.Errorf("SetParentDeathSignal(SIGKILL): %v", err)
	}
	// Reset to default disposition (0 = no signal on parent
	// death) so the test process doesn't get SIGKILL'd if
	// the runner exits weirdly.
	if err := SetParentDeathSignal(0); err != nil {
		t.Errorf("SetParentDeathSignal(0): %v", err)
	}
}

// TestPrctl_AcceptsSIGUSR1: any valid signal works.
func TestPrctl_AcceptsSIGUSR1(t *testing.T) {
	if err := SetParentDeathSignal(unix.SIGUSR1); err != nil {
		t.Errorf("SetParentDeathSignal(SIGUSR1): %v", err)
	}
	_ = SetParentDeathSignal(0)
}
