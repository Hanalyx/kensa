package eventloop

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type loopResult struct {
	event Event
	err   error
}

func awaitLoop(t *testing.T, condition func() bool, message string) {
	t.Helper()
	limit := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(limit) {
			t.Fatal(message)
		}
		runtime.Gosched()
	}
}
func receiveLoop[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("operation did not finish")
		var zero T
		return zero
	}
}
func newLifetimeLoop(t *testing.T) *Loop {
	t.Helper()
	l, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	if flags, err := unix.FcntlInt(uintptr(l.epfd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("epoll CLOEXEC: flags=%d err=%v", flags, err)
	}
	return l
}
func loopPipe(t *testing.T) []int {
	t.Helper()
	fds := make([]int, 2)
	if err := unix.Pipe2(fds, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	return fds
}
func foreignLoop(t *testing.T, fd int) {
	t.Helper()
	other, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if other != fd {
		if err := unix.Dup3(other, fd, unix.O_CLOEXEC); err != nil {
			unix.Close(other)
			t.Fatal(err)
		}
		unix.Close(other)
	}
	t.Cleanup(func() { unix.Close(fd) })
}
func readableLoopPipe(t *testing.T, fds []int) {
	t.Helper()
	if _, err := unix.Write(fds[1], []byte{1}); err != nil {
		t.Fatal(err)
	}
}

// The before-wait and after-ready pauses are the two retained Run/Close schedules.
// Close must join the paused operation before the epoll integer can be reused.
// @spec deadman-eventloop
// @ac AC-05
func TestLoopLifetime_RunClose(t *testing.T) {
	t.Log("// @spec deadman-eventloop")
	t.Log("// @ac AC-05")
	for _, phase := range []string{"before-wait", "after-ready"} {
		t.Run(phase, func(t *testing.T) {
			l := newLifetimeLoop(t)
			source := loopPipe(t)
			if err := l.Register(source[0], EventTimer); err != nil {
				t.Fatal(err)
			}
			if phase == "after-ready" {
				readableLoopPipe(t, source)
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			defer release()
			l.wait = func(fd int, events []unix.EpollEvent, timeout int) (int, error) {
				if phase == "before-wait" {
					close(entered)
					<-resume
				}
				n, err := unix.EpollWait(fd, events, timeout)
				if phase == "after-ready" && n > 0 {
					close(entered)
					<-resume
				}
				return n, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ran := make(chan loopResult, 1)
			go func() { e, err := l.Run(ctx); ran <- loopResult{e, err} }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("wait rendezvous not reached")
			}
			if l.life.TryLock() {
				l.life.Unlock()
				t.Error("Run lost descriptor ownership")
			}
			closed := make(chan error, 1)
			go func() { closed <- l.Close() }()
			awaitLoop(t, l.closed.Load, "Close did not publish closure")
			if _, err := unix.FcntlInt(uintptr(l.epfd), unix.F_GETFD, 0); err != nil {
				t.Errorf("epoll closed during paused wait: %v", err)
			}
			release()
			if r := receiveLoop(t, ran); !errors.Is(r.err, ErrClosed) || r.event != (Event{}) {
				t.Errorf("Run=%+v; want empty event and ErrClosed", r)
			}
			if err := receiveLoop(t, closed); err != nil {
				t.Fatal(err)
			}
			if _, err := unix.FcntlInt(uintptr(l.epfd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("Close did not release epoll: %v", err)
			}
			foreignLoop(t, l.epfd)
			ev := &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(source[0])}
			if err := unix.EpollCtl(l.epfd, unix.EPOLL_CTL_ADD, source[0], ev); err != nil {
				t.Fatal(err)
			}
			if phase == "before-wait" {
				readableLoopPipe(t, source)
			}
			if e, err := l.Run(context.Background()); !errors.Is(err, ErrClosed) || e != (Event{}) {
				t.Errorf("closed Run used foreign epoll: event=%+v err=%v", e, err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			events := make([]unix.EpollEvent, 1)
			if n, err := unix.EpollWait(l.epfd, events, 0); err != nil || n != 1 || int(events[0].Fd) != source[0] {
				t.Fatalf("foreign epoll changed: n=%d events=%v err=%v", n, events, err)
			}
			var b [1]byte
			if n, err := unix.Read(source[0], b[:]); err != nil || n != 1 || b[0] != 1 {
				t.Fatalf("foreign source was drained: n=%d b=%v err=%v", n, b, err)
			}
		})
	}
}

func TestLoopLifetime_RegisterClose(t *testing.T) {
	l := newLifetimeLoop(t)
	source := loopPipe(t)
	entered := make(chan struct{})
	l.beforeRegister = func() { close(entered) }
	l.mu.Lock()
	var unlock sync.Once
	release := func() { unlock.Do(l.mu.Unlock) }
	defer release()
	registered := make(chan error, 1)
	go func() { registered <- l.Register(source[0], EventControlChannel) }()
	// The rendezvous is after the initial closed check and before the map lock.
	// Register holds a lifetime lease but must recheck closure under the map lock.
	receiveLoop(t, entered)
	if l.life.TryLock() {
		l.life.Unlock()
		t.Error("Register lost descriptor ownership")
	}
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	awaitLoop(t, l.closed.Load, "Close did not publish closure")
	if _, err := unix.FcntlInt(uintptr(l.epfd), unix.F_GETFD, 0); err != nil {
		t.Errorf("epoll closed while Register was active: %v", err)
	}
	release()
	if err := receiveLoop(t, registered); !errors.Is(err, ErrClosed) {
		t.Errorf("delayed Register=%v; want ErrClosed", err)
	}
	if err := receiveLoop(t, closed); err != nil {
		t.Fatal(err)
	}
	foreignLoop(t, l.epfd)
	if err := l.Register(source[0], EventControlChannel); !errors.Is(err, ErrClosed) {
		t.Errorf("closed Register=%v; want ErrClosed", err)
	}
	readableLoopPipe(t, source)
	events := make([]unix.EpollEvent, 1)
	if n, err := unix.EpollWait(l.epfd, events, 0); err != nil || n != 0 {
		t.Fatalf("closed Register changed foreign epoll: n=%d events=%v err=%v", n, events, err)
	}
}

func TestLoopLifetime_RegisterDuringRun(t *testing.T) {
	l := newLifetimeLoop(t)
	source := loopPipe(t)
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	l.wait = func(fd int, events []unix.EpollEvent, timeout int) (int, error) {
		close(entered)
		<-resume
		return unix.EpollWait(fd, events, timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ran := make(chan loopResult, 1)
	go func() { e, err := l.Run(ctx); ran <- loopResult{e, err} }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("Run did not enter wait")
	}
	registered := make(chan error, 1)
	go func() { registered <- l.Register(source[0], EventControlChannel) }()
	if err := receiveLoop(t, registered); err != nil {
		t.Fatal(err)
	}
	readableLoopPipe(t, source)
	release()
	if r := receiveLoop(t, ran); r.err != nil || r.event.Kind != EventControlChannel || r.event.FD != source[0] {
		t.Fatalf("Run after concurrent registration=%+v", r)
	}
}

// @spec deadman-eventloop
// @ac AC-05
func TestLoopLifetime_ConcurrentClose(t *testing.T) {
	t.Log("// @spec deadman-eventloop")
	t.Log("// @ac AC-05")
	l := newLifetimeLoop(t)
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	l.wait = func(fd int, events []unix.EpollEvent, timeout int) (int, error) {
		close(entered)
		<-resume
		return unix.EpollWait(fd, events, timeout)
	}
	ran := make(chan loopResult, 1)
	go func() { e, err := l.Run(context.Background()); ran <- loopResult{e, err} }()
	receiveLoop(t, entered)
	started, closed := make(chan struct{}, 16), make(chan error, 16)
	for range 16 {
		go func() {
			started <- struct{}{}
			err := l.Close()
			if _, fdErr := unix.FcntlInt(uintptr(l.epfd), unix.F_GETFD, 0); !errors.Is(fdErr, unix.EBADF) {
				err = fmt.Errorf("Close returned before release: %v", fdErr)
			}
			closed <- err
		}()
	}
	for range 16 {
		receiveLoop(t, started)
	}
	awaitLoop(t, l.closed.Load, "Close did not publish closure")
	release()
	for range 16 {
		if err := receiveLoop(t, closed); err != nil {
			t.Error(err)
		}
	}
	if r := receiveLoop(t, ran); !errors.Is(r.err, ErrClosed) {
		t.Errorf("Run=%+v", r)
	}
	foreignLoop(t, l.epfd)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(l.epfd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("repeated Close closed foreign epoll: %v", err)
	}
}

func TestLoopLifetime_CancelDuringWait(t *testing.T) {
	l := newLifetimeLoop(t)
	source := loopPipe(t)
	if err := l.Register(source[0], EventTimer); err != nil {
		t.Fatal(err)
	}
	readableLoopPipe(t, source)
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	l.wait = func(fd int, events []unix.EpollEvent, timeout int) (int, error) {
		n, err := unix.EpollWait(fd, events, timeout)
		close(entered)
		<-resume
		return n, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan loopResult, 1)
	go func() { e, err := l.Run(ctx); ran <- loopResult{e, err} }()
	receiveLoop(t, entered)
	cancel()
	release()
	if r := receiveLoop(t, ran); !errors.Is(r.err, context.Canceled) || r.event != (Event{}) {
		t.Fatalf("Run after cancel=%+v", r)
	}
}
