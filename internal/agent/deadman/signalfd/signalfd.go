// Package signalfd provides a poll-readable file descriptor
// that becomes readable when SIGTERM is delivered to the
// agent process. Used by the rebuilt deadman event loop
// (D-004) to integrate signal delivery alongside timerfd
// (D-001) and pidfd (D-002).
//
// **Why self-pipe + signal.Notify, not signalfd(2).** Linux's
// signalfd(2) requires blocking the watched signal via
// sigprocmask in EVERY thread. Go's runtime owns the signal
// mask and creates threads on demand for goroutine
// scheduling; manually managing the mask races with the
// runtime. The cleanest Go-friendly pattern: register
// SIGTERM with `signal.Notify` (Go's runtime catches it),
// then have a goroutine forward channel sends to a pipe's
// write end. The pipe's read end is poll-readable just like
// signalfd would be, but the mask handling is delegated to
// Go's runtime which already does it correctly.
//
// Cost: one extra goroutine + one pipe per SignalFD. The
// goroutine is ~100B of overhead; the pipe is one fd pair.
// Acceptable for the deadman use case (one SignalFD per
// agent process).
//
// **PR_SET_PDEATHSIG** is the kernel-side fallback for
// parent-death detection when pidfd_open is unavailable
// (kernel <5.3 or seccomp-blocked). SetParentDeathSignal
// wraps it as a one-liner; D-005's startup path calls it
// when pidfd.ProbeSupport returns a fallback sentinel.
//
// Spec: specs/deadman/signalfd.spec.yaml (D-003).
package signalfd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// ErrClosed is returned by methods on a SignalFD that has
// already been Close()d.
var ErrClosed = errors.New("signalfd: signalfd is closed")

// pollInterval matches timerfd/pidfd — 50ms.
const pollInterval = 50

// SignalFD watches a single signal (SIGTERM in v1) and
// exposes a poll-readable file descriptor for epoll
// integration.
//
// Concurrency: Close is safe to call from any goroutine.
// Wait should be called from one goroutine at a time.
type SignalFD struct {
	signal unix.Signal

	readFD  *os.File
	writeFD *os.File
	sigCh   chan os.Signal
	pumpWG  sync.WaitGroup
	pumpCtx context.Context
	pumpCxl context.CancelFunc

	closed    atomic.Bool
	mu        sync.RWMutex
	closeOnce sync.Once
	closeErr  error
	readNum   int
	writeNum  int

	// Per-instance syscall functions keep lifetime interleavings testable
	// with real descriptors, without changing process-wide syscall behavior.
	poll func([]unix.PollFd, int) (int, error)
	read func(int, []byte) (int, error)
}

// New creates a SignalFD watching `sig`. A goroutine is
// spawned to forward Go's signal.Notify deliveries to the
// pipe's write end; the pipe's read end is exposed via FD().
//
// Returns an error if pipe allocation or nonblocking configuration fails.
func New(sig unix.Signal) (*SignalFD, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("signalfd: pipe: %w", err)
	}
	readNum, writeNum := int(r.Fd()), int(w.Fd())
	// Raw reads and writes must never block while holding a lifetime lease.
	// A full pipe already signals readiness, so another notification may coalesce.
	if err := unix.SetNonblock(readNum, true); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, fmt.Errorf("signalfd: nonblocking read end: %w", err)
	}
	if err := unix.SetNonblock(writeNum, true); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, fmt.Errorf("signalfd: nonblocking write end: %w", err)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, sig)

	ctx, cancel := context.WithCancel(context.Background())
	s := &SignalFD{
		signal:   sig,
		readFD:   r,
		writeFD:  w,
		sigCh:    sigCh,
		pumpCtx:  ctx,
		pumpCxl:  cancel,
		readNum:  readNum,
		writeNum: writeNum,
		poll:     unix.Poll,
		read:     unix.Read,
	}
	s.pumpWG.Add(1)
	go s.pump()
	return s, nil
}

// pump forwards channel sends from signal.Notify to the
// pipe's write end. Notifications may coalesce while the pipe is full;
// readers drain the pipe to consume an event.
func (s *SignalFD) pump() {
	defer s.pumpWG.Done()
	for {
		select {
		case <-s.pumpCtx.Done():
			return
		case <-s.sigCh:
			s.forwardSignal()
		}
	}
}

// forwardSignal writes without blocking when the pipe is full. The lifetime
// lock prevents either descriptor from closing during this syscall.
func (s *SignalFD) forwardSignal() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return
	}
	for {
		_, err := unix.Write(s.writeNum, []byte{1})
		if !errors.Is(err, unix.EINTR) {
			return
		}
	}
}

// FD returns a snapshot of the read descriptor, or -1 after closure begins.
// Calling FD is concurrency-safe; the returned number is not a lifetime lease.
// The external poll owner must stop using it before calling Close.
func (s *SignalFD) FD() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return -1
	}
	return s.readNum
}

// Signal returns the signal this SignalFD watches.
func (s *SignalFD) Signal() unix.Signal {
	return s.signal
}

// Wait blocks until the watched signal is delivered OR ctx
// is canceled OR Close is called.
//
// Same poll-based pattern as timerfd/pidfd to avoid the
// Go-on-Linux fd-reuse footgun.
func (s *SignalFD) Wait(ctx context.Context) error {
	for {
		if s.closed.Load() {
			return ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := s.waitOnce()
		if ready || err != nil {
			return err
		}
	}
}

// waitOnce holds a lifetime lease across both poll and drain. Close publishes
// closure before waiting for leases, so it cannot close or recycle a borrowed fd.
func (s *SignalFD) waitOnce() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return false, ErrClosed
	}
	fds := []unix.PollFd{{Fd: int32(s.readNum), Events: unix.POLLIN}}
	n, err := s.poll(fds, pollInterval)
	if s.closed.Load() {
		return false, ErrClosed
	}
	if errors.Is(err, unix.EINTR) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("signalfd: poll: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	if fds[0].Revents&unix.POLLNVAL != 0 {
		return false, ErrClosed
	}
	if fds[0].Revents&unix.POLLIN == 0 {
		return false, nil
	}
	var buf [1]byte
	_, err = s.read(s.readNum, buf[:])
	if s.closed.Load() {
		return false, ErrClosed
	}
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("signalfd: read: %w", err)
	}
	return true, nil
}

// Close unregisters this instance's notifications, joins the pump and active
// descriptor operations, then releases the pipe. Other signal subscribers remain
// registered. Concurrent Close calls wait for the same completed teardown.
func (s *SignalFD) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		signal.Stop(s.sigCh)
		s.pumpCxl()
		s.pumpWG.Wait()

		s.mu.Lock()
		defer s.mu.Unlock()
		_ = s.writeFD.Close()
		if err := s.readFD.Close(); err != nil {
			s.closeErr = fmt.Errorf("signalfd: close read end: %w", err)
		}
	})
	return s.closeErr
}

// SetParentDeathSignal asks the kernel to deliver `sig` to
// the current process when its parent terminates. This is
// the fallback for parent-death detection when pidfd_open
// is unavailable (kernel <5.3 or seccomp-blocked, per Q2.b
// ratification).
//
// Common callers pass unix.SIGKILL — uncatchable, lossless.
// The deadman won't get to run rollback under this path
// (Q3.a accepted risk), but the agent doesn't linger on an
// orphaned target.
//
// **Note on semantics.** PR_SET_PDEATHSIG is per-thread and
// is reset on execve. The agent should call this once at
// startup, before goroutine scheduling spawns additional
// threads.
func SetParentDeathSignal(sig unix.Signal) error {
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(sig), 0, 0, 0); err != nil {
		return fmt.Errorf("signalfd: prctl(PR_SET_PDEATHSIG, %d): %w", sig, err)
	}
	return nil
}
