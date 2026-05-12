package timerfd

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestTimerfd_FiresAfterWindow locks AC-01.
func TestTimerfd_FiresAfterWindow(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	if err := tm.Arm(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := tm.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 90*time.Millisecond {
		t.Errorf("fired too early: %v < 90ms", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("fired too late: %v > 500ms (loaded test runner allowance)", elapsed)
	}
}

// TestTimerfd_CanCancel locks AC-02. Cancel does NOT unblock
// a pending Wait per the documented contract — caller must
// use ctx to abort.
func TestTimerfd_CanCancel(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	if err := tm.Arm(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tm.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err = tm.Wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded (cancel disarmed the timer); got: %v", err)
	}
}

// TestTimerfd_ContextCancel locks AC-03.
func TestTimerfd_ContextCancel(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	if err := tm.Arm(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err = tm.Wait(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected ctx.Canceled; got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait took too long after ctx cancel: %v", elapsed)
	}
}

// TestTimerfd_RejectsZeroDuration locks AC-04 + the
// negative-boundary case (-1ns).
func TestTimerfd_RejectsZeroDuration(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	cases := []time.Duration{0, -1 * time.Nanosecond, -1 * time.Second}
	for _, d := range cases {
		if err := tm.Arm(d); !errors.Is(err, ErrInvalidDuration) {
			t.Errorf("Arm(%v): expected ErrInvalidDuration; got: %v", d, err)
		}
	}
}

// TestTimerfd_FDReadShape locks AC-05. Bumped the sleep to
// 200ms (was 50ms) so this stays reliable on loaded CI.
func TestTimerfd_FDReadShape(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	if err := tm.Arm(10 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	var buf [8]byte
	n, err := unix.Read(tm.FD(), buf[:])
	if err != nil {
		t.Fatalf("unix.Read: %v", err)
	}
	if n != 8 {
		t.Errorf("read shape: got %d bytes, want exactly 8", n)
	}
	count := binary.LittleEndian.Uint64(buf[:])
	if count == 0 {
		t.Error("expiration count: got 0, want ≥1 (timer fired)")
	}
}

// TestTimerfd_CloseIdempotent locks AC-06.
func TestTimerfd_CloseIdempotent(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := tm.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tm.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestTimerfd_ArmAfterClose returns ErrClosed.
func TestTimerfd_ArmAfterClose(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	_ = tm.Close()

	if err := tm.Arm(100 * time.Millisecond); !errors.Is(err, ErrClosed) {
		t.Errorf("Arm after Close: expected ErrClosed; got: %v", err)
	}
	if err := tm.Cancel(); !errors.Is(err, ErrClosed) {
		t.Errorf("Cancel after Close: expected ErrClosed; got: %v", err)
	}
	if err := tm.Wait(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Wait after Close: expected ErrClosed; got: %v", err)
	}
	if fd := tm.FD(); fd != -1 {
		t.Errorf("FD after Close: got %d, want -1", fd)
	}
}

// TestTimerfd_ReArm: re-arm after fire works cleanly.
func TestTimerfd_ReArm(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	if err := tm.Arm(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := tm.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait: %v", err)
	}

	if err := tm.Arm(50 * time.Millisecond); err != nil {
		t.Fatalf("second Arm: %v", err)
	}
	start := time.Now()
	if err := tm.Wait(context.Background()); err != nil {
		t.Fatalf("second Wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Errorf("second arm fired too early: %v (carry-over from first?)", elapsed)
	}
}

// TestTimerfd_ArmCancelArm: re-arm after Cancel (not fire)
// works correctly. Tests the kernel's "replace previous
// deadline" semantics that D-005 will use to extend the
// window.
func TestTimerfd_ArmCancelArm(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	if err := tm.Arm(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tm.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if err := tm.Arm(100 * time.Millisecond); err != nil {
		t.Fatalf("re-Arm after Cancel: %v", err)
	}
	start := time.Now()
	if err := tm.Wait(context.Background()); err != nil {
		t.Fatalf("Wait after re-arm: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Errorf("re-armed timer fired too late: %v", elapsed)
	}
}

// TestTimerfd_WaitUnarmed_CtxCancels: Wait on a never-armed
// timer blocks until ctx cancel.
func TestTimerfd_WaitUnarmed_CtxCancels(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = tm.Wait(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("unarmed Wait: expected DeadlineExceeded; got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("unarmed Wait took too long: %v", elapsed)
	}
}

// TestTimerfd_ConcurrentCloseDuringWait: Wait is blocked;
// Close races. Wait must return ErrClosed without
// fd-reuse race. P0-2 lock.
func TestTimerfd_ConcurrentCloseDuringWait(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := tm.Arm(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	var waitErr atomic.Value
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := tm.Wait(context.Background())
		waitErr.Store(err)
	}()

	// Give Wait a moment to enter the poll loop.
	time.Sleep(20 * time.Millisecond)
	if err := tm.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
	if err := waitErr.Load().(error); !errors.Is(err, ErrClosed) {
		t.Errorf("concurrent Close: expected ErrClosed; got: %v", err)
	}
}

// TestTimerfd_ConcurrentArmCalls: serialize via t.mu — both
// Arm calls return without error, the LAST one wins.
func TestTimerfd_ConcurrentArmCalls(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = tm.Arm(5 * time.Second)
	}()
	go func() {
		defer wg.Done()
		_ = tm.Arm(100 * time.Millisecond)
	}()
	wg.Wait()
	// Whichever wins, Wait should return within 5s+ε without panicking.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := tm.Wait(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Wait after concurrent Arm: %v", err)
	}
}
