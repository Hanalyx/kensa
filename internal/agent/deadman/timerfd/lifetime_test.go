package timerfd

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func awaitTimerClosure(t *testing.T, tm *Timer) {
	t.Helper()
	limit := time.Now().Add(3 * time.Second)
	for !tm.closed.Load() {
		if time.Now().After(limit) {
			t.Fatal("Close did not publish closure")
		}
		runtime.Gosched()
	}
}
func receiveTimerError(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not finish")
		return nil
	}
}

func TestTimerLifetime_PollAndDrain(t *testing.T) {
	for _, phase := range []string{"poll", "ready", "drain"} {
		t.Run(phase, func(t *testing.T) {
			tm, err := New()
			if err != nil {
				t.Fatal(err)
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			defer func() { release(); _ = tm.Close() }()
			switch phase {
			case "poll":
				tm.poll = func(fds []unix.PollFd, timeout int) (int, error) {
					close(entered)
					<-resume
					return unix.Poll(fds, timeout)
				}
			case "ready":
				tm.poll = func(fds []unix.PollFd, timeout int) (int, error) {
					n, err := unix.Poll(fds, timeout)
					if n > 0 {
						close(entered)
						<-resume
					}
					return n, err
				}
			case "drain":
				tm.read = func(fd int, b []byte) (int, error) { close(entered); <-resume; return unix.Read(fd, b) }
			}
			if phase != "poll" {
				if err := tm.Arm(time.Nanosecond); err != nil {
					t.Fatal(err)
				}
			}
			fd := tm.FD()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			waited := make(chan error, 1)
			go func() { waited <- tm.Wait(ctx) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("syscall rendezvous not reached")
			}
			if tm.mu.TryLock() {
				tm.mu.Unlock()
				t.Error("poll/drain lost descriptor ownership")
			}
			closed := make(chan error, 1)
			go func() { closed <- tm.Close() }()
			awaitTimerClosure(t, tm)
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
				t.Errorf("descriptor closed during paused operation: %v", err)
			}
			release()
			if err := receiveTimerError(t, waited); !errors.Is(err, ErrClosed) {
				t.Errorf("Wait=%v; want ErrClosed", err)
			}
			if err := receiveTimerError(t, closed); err != nil {
				t.Fatal(err)
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Errorf("descriptor not released: %v", err)
			}
		})
	}
}

func TestTimerLifetime_CancelAndRearmDuringDrain(t *testing.T) {
	for _, operation := range []string{"cancel", "rearm"} {
		t.Run(operation, func(t *testing.T) {
			tm, err := New()
			if err != nil {
				t.Fatal(err)
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			defer func() { release(); _ = tm.Close() }()
			readResult := make(chan error, 1)
			tm.read = func(fd int, b []byte) (int, error) {
				close(entered)
				<-resume
				n, err := unix.Read(fd, b)
				readResult <- err
				return n, err
			}
			if err := tm.Arm(time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waited := make(chan error, 1)
			go func() { waited <- tm.Wait(ctx) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("drain not reached")
			}
			if operation == "cancel" {
				err = tm.Cancel()
			} else {
				err = tm.Arm(time.Hour)
			}
			if err != nil {
				t.Fatal(err)
			}
			// Removing readiness must make the real read return EAGAIN rather than block.
			cancel()
			release()
			if err := receiveTimerError(t, readResult); !errors.Is(err, unix.EAGAIN) {
				t.Errorf("read after %s=%v; want EAGAIN", operation, err)
			}
			if err := receiveTimerError(t, waited); !errors.Is(err, context.Canceled) {
				t.Errorf("Wait=%v; want context.Canceled", err)
			}
		})
	}
}

func TestTimerLifetime_StateChangesHoldDescriptor(t *testing.T) {
	for _, operation := range []string{"arm", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			tm, err := New()
			if err != nil {
				t.Fatal(err)
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			defer func() { release(); _ = tm.Close() }()
			tm.settime = func(fd, flags int, value, old *unix.ItimerSpec) error {
				close(entered)
				<-resume
				return unix.TimerfdSettime(fd, flags, value, old)
			}
			fd := tm.FD()
			changed := make(chan error, 1)
			go func() {
				if operation == "arm" {
					changed <- tm.Arm(time.Second)
				} else {
					changed <- tm.Cancel()
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("settime not reached")
			}
			if tm.mu.TryLock() {
				tm.mu.Unlock()
				t.Error("state change lost descriptor ownership")
			}
			closed := make(chan error, 1)
			go func() { closed <- tm.Close() }()
			awaitTimerClosure(t, tm)
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
				t.Errorf("closed during settime: %v", err)
			}
			release()
			if err := receiveTimerError(t, changed); err != nil {
				t.Errorf("in-flight change failed: %v", err)
			}
			if err := receiveTimerError(t, closed); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTimerLifetime_Flags(t *testing.T) {
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer tm.Close()
	fd := tm.FD()
	if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("CLOEXEC: flags=%d err=%v", flags, err)
	}
	if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("drain can block: flags=%d err=%v", flags, err)
	}
	var b [8]byte
	if _, err := unix.Read(fd, b[:]); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("unarmed raw read=%v; want EAGAIN", err)
	}
}

// @spec deadman-timerfd
// @ac AC-06
func TestTimerLifetime_ConcurrentCloseAndReuse(t *testing.T) {
	t.Log("// @spec deadman-timerfd")
	t.Log("// @ac AC-06")
	tm, err := New()
	if err != nil {
		t.Fatal(err)
	}
	fd := tm.FD()
	start := make(chan struct{})
	done := make(chan error, 16)
	for range 16 {
		go func() { <-start; done <- tm.Close() }()
	}
	close(start)
	for range 16 {
		if err := receiveTimerError(t, done); err != nil {
			t.Fatal(err)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatal("Close returned before release")
		}
	}
	pipe := make([]int, 2)
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipe[1])
	if pipe[0] != fd {
		if err := unix.Dup3(pipe[0], fd, unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		unix.Close(pipe[0])
	}
	defer unix.Close(fd)
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if _, err := unix.Write(pipe[1], data); err != nil {
		t.Fatal(err)
	}
	if err := tm.Close(); err != nil {
		t.Fatal(err)
	}
	if tm.FD() != -1 {
		t.Error("FD after close")
	}
	if err := tm.Wait(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Wait=%v", err)
	}
	if err := tm.Arm(time.Second); !errors.Is(err, ErrClosed) {
		t.Errorf("Arm=%v", err)
	}
	if err := tm.Cancel(); !errors.Is(err, ErrClosed) {
		t.Errorf("Cancel=%v", err)
	}
	var got [8]byte
	if n, err := unix.Read(fd, got[:]); err != nil || n != 8 || got != [8]byte{1, 2, 3, 4, 5, 6, 7, 8} {
		t.Fatalf("foreign bytes changed: n=%d data=%v err=%v", n, got, err)
	}
}
