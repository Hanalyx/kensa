package pidfd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ownPidfd(t *testing.T) *Pidfd {
	t.Helper()
	p, err := Open(os.Getpid())
	if errors.Is(err, ErrKernelTooOld) {
		t.Skip("pidfd_open requires Linux 5.3+")
	}
	if err != nil {
		t.Fatal(err)
	}
	if flags, err := unix.FcntlInt(uintptr(p.FD()), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("CLOEXEC: flags=%d err=%v", flags, err)
	}
	return p
}
func awaitPidfdClosure(t *testing.T, p *Pidfd) {
	t.Helper()
	limit := time.Now().Add(3 * time.Second)
	for !p.closed.Load() {
		if time.Now().After(limit) {
			t.Fatal("Close did not publish closure")
		}
		runtime.Gosched()
	}
}
func receivePidfdError(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not finish")
		return nil
	}
}

func TestPidfdLifetime_Poll(t *testing.T) {
	p := ownPidfd(t)
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer func() { release(); _ = p.Close() }()
	p.poll = func(fds []unix.PollFd, timeout int) (int, error) {
		close(entered)
		<-resume
		return unix.Poll(fds, timeout)
	}
	fd := p.FD()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	waited := make(chan error, 1)
	go func() { waited <- p.Wait(ctx) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("poll not reached")
	}
	if p.mu.TryLock() {
		p.mu.Unlock()
		t.Error("poll lost descriptor ownership")
	}
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	awaitPidfdClosure(t, p)
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Errorf("closed during poll: %v", err)
	}
	release()
	if err := receivePidfdError(t, waited); !errors.Is(err, ErrClosed) {
		t.Errorf("Wait=%v; want ErrClosed", err)
	}
	if err := receivePidfdError(t, closed); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Errorf("descriptor not released: %v", err)
	}
}

// Use an actual exiting child so a ready pidfd is tested during Close.
func TestPidfdLifetime_ReadyDuringClose(t *testing.T) {
	if err := ProbeSupport(); errors.Is(err, ErrKernelTooOld) {
		t.Skip("pidfd_open requires Linux 5.3+")
	} else if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("/bin/true")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Wait() }()
	p, err := Open(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer func() { release(); _ = p.Close() }()
	p.poll = func(fds []unix.PollFd, timeout int) (int, error) {
		n, err := unix.Poll(fds, timeout)
		if n > 0 {
			close(entered)
			<-resume
		}
		return n, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	waited := make(chan error, 1)
	go func() { waited <- p.Wait(ctx) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("ready pidfd not observed")
	}
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	awaitPidfdClosure(t, p)
	release()
	if err := receivePidfdError(t, waited); !errors.Is(err, ErrClosed) {
		t.Errorf("ready Wait=%v; want ErrClosed", err)
	}
	if err := receivePidfdError(t, closed); err != nil {
		t.Fatal(err)
	}
}

// @spec deadman-pidfd
// @ac AC-05
func TestPidfdLifetime_ConcurrentCloseAndReuse(t *testing.T) {
	t.Log("// @spec deadman-pidfd")
	t.Log("// @ac AC-05")
	p := ownPidfd(t)
	fd := p.FD()
	start := make(chan struct{})
	done := make(chan error, 16)
	for range 16 {
		go func() { <-start; done <- p.Close() }()
	}
	close(start)
	for range 16 {
		if err := receivePidfdError(t, done); err != nil {
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
	if _, err := unix.Write(pipe[1], []byte{42}); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if p.FD() != -1 {
		t.Error("FD after close")
	}
	if err := p.Wait(context.Background()); !errors.Is(err, ErrClosed) {
		t.Errorf("Wait=%v", err)
	}
	var b [1]byte
	if n, err := unix.Read(fd, b[:]); err != nil || n != 1 || b[0] != 42 {
		t.Fatalf("foreign bytes changed: n=%d data=%v err=%v", n, b, err)
	}
}
