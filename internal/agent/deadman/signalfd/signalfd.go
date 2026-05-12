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
	"time"

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

	closed atomic.Bool
	mu     sync.Mutex
}

// New creates a SignalFD watching `sig`. A goroutine is
// spawned to forward Go's signal.Notify deliveries to the
// pipe's write end; the pipe's read end is exposed via FD().
//
// Returns an error only if the pipe creation fails (rare —
// EMFILE / ENFILE).
func New(sig unix.Signal) (*SignalFD, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("signalfd: pipe: %w", err)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, sig)

	ctx, cancel := context.WithCancel(context.Background())
	s := &SignalFD{
		signal:  sig,
		readFD:  r,
		writeFD: w,
		sigCh:   sigCh,
		pumpCtx: ctx,
		pumpCxl: cancel,
	}
	s.pumpWG.Add(1)
	go s.pump()
	return s, nil
}

// pump forwards channel sends from signal.Notify to the
// pipe's write end. One byte per signal delivery — readers
// drain the pipe to consume the event.
func (s *SignalFD) pump() {
	defer s.pumpWG.Done()
	for {
		select {
		case <-s.pumpCtx.Done():
			return
		case <-s.sigCh:
			// Write one byte. Best-effort — if the read end
			// is closed (Close raced), drop the signal.
			_, _ = s.writeFD.Write([]byte{1})
		}
	}
}

// FD returns the underlying file descriptor (the pipe's
// read end) for epoll registration (D-004). Returns -1 if
// Close was called.
func (s *SignalFD) FD() int {
	if s.closed.Load() {
		return -1
	}
	return int(s.readFD.Fd())
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
	if s.closed.Load() {
		return ErrClosed
	}
	for {
		if s.closed.Load() {
			return ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		pollFds := []unix.PollFd{{Fd: int32(s.readFD.Fd()), Events: unix.POLLIN}}
		n, err := unix.Poll(pollFds, pollInterval)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if s.closed.Load() {
				return ErrClosed
			}
			return fmt.Errorf("signalfd: poll: %w", err)
		}
		if n == 0 {
			continue
		}
		if pollFds[0].Revents&unix.POLLNVAL != 0 {
			return ErrClosed
		}
		if pollFds[0].Revents&unix.POLLIN != 0 {
			// Drain one byte from the pipe so the fd
			// doesn't stay readable on subsequent epoll
			// wakeups.
			var buf [1]byte
			_, err := unix.Read(int(s.readFD.Fd()), buf[:])
			if err != nil {
				if s.closed.Load() {
					return ErrClosed
				}
				if errors.Is(err, unix.EAGAIN) {
					continue
				}
				return fmt.Errorf("signalfd: read: %w", err)
			}
			return nil
		}
	}
}

// Close stops the signal.Notify forwarding, releases the
// pipe fds, and restores the default signal disposition.
// Idempotent.
func (s *SignalFD) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Drain so concurrent Wait observes closed=true and exits
	// its poll loop before we close the fds.
	time.Sleep(2 * pollInterval * time.Millisecond)

	// Stop forwarding signals (restores default disposition).
	signal.Stop(s.sigCh)
	// Cancel the pump goroutine; it may be blocked on sigCh
	// reads, so we also close sigCh (signal.Stop allows it).
	s.pumpCxl()
	s.pumpWG.Wait()

	// Close write end first so any future signal-pump
	// drop-on-write is silent (no broken-pipe race).
	_ = s.writeFD.Close()
	if err := s.readFD.Close(); err != nil {
		return fmt.Errorf("signalfd: close read end: %w", err)
	}
	return nil
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
