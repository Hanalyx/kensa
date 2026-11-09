package signalfd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func waitClosedFlag(t *testing.T, s *SignalFD) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !s.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("Close did not publish closure")
		}
		runtime.Gosched()
	}
}

// @spec deadman-signalfd
// @ac AC-05
func TestSignalFD_LifetimeLease(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-05")
	for _, phase := range []string{"poll", "drain"} {
		t.Run(phase, func(t *testing.T) {
			s, err := New(unix.SIGUSR1)
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			// Always release a paused syscall before cleanup, including assertion failures.
			defer func() { unblock(); _ = s.Close() }()
			if phase == "poll" {
				s.poll = func(fds []unix.PollFd, timeout int) (int, error) {
					close(entered)
					<-release
					return unix.Poll(fds, timeout)
				}
			} else {
				s.read = func(fd int, b []byte) (int, error) { close(entered); <-release; return unix.Read(fd, b) }
				s.forwardSignal()
			}
			fd := s.FD()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			waited := make(chan error, 1)
			go func() { waited <- s.Wait(ctx) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("syscall rendezvous not reached")
			}
			if s.mu.TryLock() {
				s.mu.Unlock()
				t.Error("descriptor operation did not retain its lifetime lease")
			}
			closed := make(chan error, 1)
			go func() { closed <- s.Close() }()
			waitClosedFlag(t, s)
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
				t.Errorf("descriptor closed while operation is paused: %v", err)
			}
			unblock()
			select {
			case err := <-waited:
				if !errors.Is(err, ErrClosed) {
					t.Errorf("Wait=%v; want ErrClosed", err)
				}
			case <-ctx.Done():
				t.Fatal("Wait stuck")
			}
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("Close stuck")
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Errorf("descriptor not released: %v", err)
			}
		})
	}
}

// @spec deadman-signalfd
// @ac AC-08
func TestSignalFD_ClosedWaitDoesNotReadReusedDescriptor(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-08")
	s, err := New(unix.SIGUSR1)
	if err != nil {
		t.Fatal(err)
	}
	fd := s.FD()
	if err := s.Close(); err != nil {
		t.Fatal(err)
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
	if _, err := unix.Write(pipe[1], []byte{42}); err != nil {
		t.Fatal(err)
	}
	if err := s.Wait(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Wait=%v", err)
	}
	var got [1]byte
	if n, err := unix.Read(fd, got[:]); err != nil || n != 1 || got[0] != 42 {
		t.Fatalf("unrelated descriptor consumed: n=%d data=%v err=%v", n, got, err)
	}
	if s.FD() != -1 {
		t.Fatal("closed FD accessor returned a descriptor")
	}
}

// @spec deadman-signalfd
// @ac AC-03
func TestSignalFD_ConcurrentCloseCompletesTeardown(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-03")
	s, err := New(unix.SIGUSR1)
	if err != nil {
		t.Fatal(err)
	}
	fd := s.FD()
	start := make(chan struct{})
	results := make(chan error, 16)
	for range 16 {
		go func() { <-start; results <- s.Close() }()
	}
	close(start)
	for range 16 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent Close stuck")
		}
		if s.FD() != -1 {
			t.Fatal("Close returned before closure")
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("Close returned before descriptor release: %v", err)
		}
	}
}

// @spec deadman-signalfd
// @ac AC-06
func TestSignalFD_FullPipeDoesNotBlockPumpOrClose(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-06")
	s, err := New(unix.SIGUSR1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	flags, err := unix.FcntlInt(uintptr(s.writeNum), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatal("write end can block")
	}
	if flags, err := unix.FcntlInt(uintptr(s.readNum), unix.F_GETFL, 0); err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("read end can block: flags=%d err=%v", flags, err)
	}
	for _, fd := range []int{s.readNum, s.writeNum} {
		if f, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e != nil || f&unix.FD_CLOEXEC == 0 {
			t.Fatalf("descriptor %d lacks CLOEXEC: %d %v", fd, f, e)
		}
	}
	for {
		_, err := unix.Write(s.writeNum, make([]byte, 4096))
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// A queued real notification cannot leave the pump parked in a full pipe.
	s.sigCh <- syscall.SIGUSR1
	done := make(chan error, 1)
	go func() { s.forwardSignal(); done <- s.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("full pipe blocked teardown")
	}
}

// @spec deadman-signalfd
// @ac AC-07
func TestSignalFD_SignalLifecycle(t *testing.T) {
	t.Log("// @spec deadman-signalfd")
	t.Log("// @ac AC-07")
	for _, mode := range []string{"other-subscriber", "default-disposition"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSignalFDSignalHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "KENSA_SIGNAL_LIFECYCLE="+mode)
			output, err := cmd.CombinedOutput()
			if mode == "other-subscriber" {
				if err != nil || !strings.Contains(string(output), "other subscriber received signal") {
					t.Fatalf("helper: %v %s", err, output)
				}
				return
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("want signal exit: err=%v output=%s", err, output)
			}
			status, ok := ee.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
				t.Fatalf("want SIGTERM exit: %v %s", err, output)
			}
		})
	}
}

func TestSignalFDSignalHelper(t *testing.T) {
	mode := os.Getenv("KENSA_SIGNAL_LIFECYCLE")
	if mode == "" {
		return
	}
	sig := unix.SIGUSR1
	if mode == "default-disposition" {
		sig = unix.SIGTERM
		signal.Reset(syscall.SIGTERM)
	}
	other := make(chan os.Signal, 1)
	if mode == "other-subscriber" {
		signal.Notify(other, syscall.SIGUSR1)
		defer signal.Stop(other)
	}
	s, err := New(sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.Signal(sig)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if mode == "other-subscriber" {
		select {
		case <-other:
		case <-ctx.Done():
			t.Fatal("other subscriber lost initial signal")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.Signal(sig)); err != nil {
		t.Fatal(err)
	}
	if mode == "other-subscriber" {
		select {
		case <-other:
			t.Log("other subscriber received signal")
		case <-ctx.Done():
			t.Fatal("Close removed another subscriber")
		}
		return
	}
	select {} // Parent timeout fails if default termination was not restored.
}
