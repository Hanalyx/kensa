package eventloop_test

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Hanalyx/kensa-go/internal/agent/deadman/eventloop"
	"github.com/Hanalyx/kensa-go/internal/agent/deadman/pidfd"
	"github.com/Hanalyx/kensa-go/internal/agent/deadman/signalfd"
	"github.com/Hanalyx/kensa-go/internal/agent/deadman/timerfd"
)

// TestEventLoop_TimerFiresFirst locks AC-01: a 100ms timer
// fires before a long-running pidfd → Loop.Run returns
// EventTimer.
//
// @spec deadman-eventloop
// @ac AC-01
func TestEventLoop_TimerFiresFirst(t *testing.T) {
	t.Log("// @spec deadman-eventloop")
	t.Log("// @ac AC-01")
	if err := pidfd.ProbeSupport(); err != nil {
		t.Skip("pidfd unsupported:", err)
	}
	// Long-running child for pidfd target.
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	tm, err := timerfd.New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()

	pf, err := pidfd.Open(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	loop, err := eventloop.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	if err := loop.Register(tm.FD(), eventloop.EventTimer); err != nil {
		t.Fatal(err)
	}
	if err := loop.Register(pf.FD(), eventloop.EventParentDeath); err != nil {
		t.Fatal(err)
	}
	if err := tm.Arm(100 * time.Millisecond); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	ev, err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ev.Kind != eventloop.EventTimer {
		t.Errorf("Run: got Kind=%v, want EventTimer", ev.Kind)
	}
	if ev.FD != tm.FD() {
		t.Errorf("Run: got FD=%d, want timer FD=%d", ev.FD, tm.FD())
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Run returned too late: %v", elapsed)
	}
}

// TestEventLoop_ParentDeathWins locks AC-02.
//
// @spec deadman-eventloop
// @ac AC-02
func TestEventLoop_ParentDeathWins(t *testing.T) {
	t.Log("// @spec deadman-eventloop")
	t.Log("// @ac AC-02")
	if err := pidfd.ProbeSupport(); err != nil {
		t.Skip("pidfd unsupported:", err)
	}
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	tm, err := timerfd.New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	pf, err := pidfd.Open(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	loop, err := eventloop.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	_ = loop.Register(tm.FD(), eventloop.EventTimer)
	_ = loop.Register(pf.FD(), eventloop.EventParentDeath)
	if err := tm.Arm(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	// Kill the child after a brief delay so the pidfd
	// fires before the 5s timer.
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = cmd.Process.Kill()
	}()

	start := time.Now()
	ev, err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ev.Kind != eventloop.EventParentDeath {
		t.Errorf("Run: got Kind=%v, want EventParentDeath", ev.Kind)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Run returned too late: %v", elapsed)
	}
}

// TestEventLoop_SignalWins locks AC-03.
//
// @spec deadman-eventloop
// @ac AC-03
func TestEventLoop_SignalWins(t *testing.T) {
	t.Log("// @spec deadman-eventloop")
	t.Log("// @ac AC-03")
	tm, err := timerfd.New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	sf, err := signalfd.New(unix.SIGUSR1)
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()

	loop, err := eventloop.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	_ = loop.Register(tm.FD(), eventloop.EventTimer)
	_ = loop.Register(sf.FD(), eventloop.EventSignal)
	if err := tm.Arm(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
	}()

	start := time.Now()
	ev, err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ev.Kind != eventloop.EventSignal {
		t.Errorf("Run: got Kind=%v, want EventSignal", ev.Kind)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Run returned too late: %v", elapsed)
	}
}

// TestEventLoop_CtxCancel locks AC-04.
//
// @spec deadman-eventloop
// @ac AC-04
func TestEventLoop_CtxCancel(t *testing.T) {
	t.Log("// @spec deadman-eventloop")
	t.Log("// @ac AC-04")
	tm, err := timerfd.New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	loop, err := eventloop.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	_ = loop.Register(tm.FD(), eventloop.EventTimer)
	_ = tm.Arm(5 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = loop.Run(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run: expected DeadlineExceeded; got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Run took too long after ctx cancel: %v", elapsed)
	}
}

// TestEventLoop_ConcurrentClose locks AC-05.
//
// @spec deadman-eventloop
// @ac AC-05
func TestEventLoop_ConcurrentClose(t *testing.T) {
	t.Log("// @spec deadman-eventloop")
	t.Log("// @ac AC-05")
	tm, err := timerfd.New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	loop, err := eventloop.New()
	if err != nil {
		t.Fatal(err)
	}
	_ = loop.Register(tm.FD(), eventloop.EventTimer)
	_ = tm.Arm(5 * time.Second)

	var runErr atomic.Value
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := loop.Run(context.Background())
		runErr.Store(err)
	}()
	time.Sleep(20 * time.Millisecond)
	if err := loop.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
	if err := runErr.Load().(error); !errors.Is(err, eventloop.ErrClosed) {
		t.Errorf("concurrent Close: expected ErrClosed; got: %v", err)
	}
}

// TestEventLoop_CloseIdempotent.
func TestEventLoop_CloseIdempotent(t *testing.T) {
	loop, err := eventloop.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := loop.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := loop.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestEventLoop_RejectsUnknownKind.
func TestEventLoop_RejectsUnknownKind(t *testing.T) {
	loop, err := eventloop.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	if err := loop.Register(0, eventloop.EventUnknown); err == nil {
		t.Error("Register(EventUnknown): expected error")
	}
}

// TestEventKind_String: every EventKind has a non-"unknown"
// string except EventUnknown itself.
func TestEventKind_String(t *testing.T) {
	cases := []struct {
		k    eventloop.EventKind
		want string
	}{
		{eventloop.EventTimer, "timer"},
		{eventloop.EventParentDeath, "parent-death"},
		{eventloop.EventSignal, "signal"},
		{eventloop.EventControlChannel, "control-channel"},
		{eventloop.EventUnknown, "unknown"},
	}
	for _, c := range cases {
		if got := c.k.String(); got != c.want {
			t.Errorf("EventKind(%d).String(): got %q, want %q", c.k, got, c.want)
		}
	}
}
