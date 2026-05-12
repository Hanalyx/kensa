// Package timerfd wraps Linux's timerfd_create(CLOCK_BOOTTIME)
// for use as the rollback timer in the rebuilt agent-side
// deadman subsystem.
//
// **Why CLOCK_BOOTTIME.** This is the load-bearing reason
// timerfd exists in kensa-go: it's the ONLY Linux clock that
// counts elapsed time DURING system suspend. Go's stdlib
// time.Timer uses CLOCK_MONOTONIC which stops during sleep,
// so a laptop or VM suspended mid-remediation would resume
// with a deadman that thinks zero seconds passed — the
// rollback would not fire even though wall-clock minutes
// elapsed.
//
// CLOCK_BOOTTIME also ignores wall-clock jumps (NTP, manual
// `date -s`, leap seconds). The deadman promise is "fire
// after N seconds of elapsed real time regardless of
// operator interference"; BOOTTIME is the clock that
// satisfies it.
//
// **What this package is NOT.** This package ships ONLY the
// timer wrapper. The deadman event loop (D-004) integrates
// this with pidfd (D-002) and signalfd (D-003) via epoll.
// The current shell-based internal/deadman/ is untouched by
// this deliverable.
//
// **Concurrency contract.**
//   - Arm / Cancel / FD / Close: safe to call concurrently
//     from multiple goroutines.
//   - Wait: safe to call from one goroutine at a time. While
//     a Wait is in flight, another goroutine MAY call
//     Cancel (Wait will continue blocking until ctx cancel
//     or a new Arm fires it — Cancel does NOT unblock Wait)
//     or Close (Wait will return ErrClosed cleanly via the
//     poll-loop's closed-flag check, no fd-reuse race).
//
// Spec: specs/deadman/timerfd.spec.yaml (D-001).
package timerfd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ErrInvalidDuration is returned by Arm when the supplied
// duration is zero or negative. Spec C-03.
var ErrInvalidDuration = errors.New("timerfd: duration must be positive")

// ErrClosed is returned by methods on a Timer that has
// already been Close()d.
var ErrClosed = errors.New("timerfd: timer is closed")

// pollInterval is how often Wait's poll loop wakes to check
// ctx/closed status. 50ms is short enough that ctx cancel
// and Close return reasonably quickly; long enough that the
// idle CPU cost is negligible. D-005's epoll integration
// won't use Wait, so this overhead is unit-test-only.
const pollInterval = 50

// Timer wraps a Linux timerfd_create(CLOCK_BOOTTIME) fd.
// Construct with New(); call Close() to release the fd when
// done.
//
// A Timer can be Arm()'d, Cancel()'d, and Arm()'d again. Each
// Arm replaces the previous deadline; the kernel handles the
// transition atomically.
type Timer struct {
	fd     int
	closed atomic.Bool

	// mu serializes Arm/Cancel/Close. The fd itself is
	// thread-safe for read but not for the timerfd_settime
	// call sequence we want to keep linear.
	mu sync.Mutex
}

// New creates a new Timer using CLOCK_BOOTTIME with TFD_CLOEXEC.
// The Timer is unarmed; call Arm to schedule a fire.
//
// Spec C-01 (CLOCK_BOOTTIME), C-02 (TFD_CLOEXEC).
func New() (*Timer, error) {
	fd, err := unix.TimerfdCreate(unix.CLOCK_BOOTTIME, unix.TFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("timerfd: create: %w", err)
	}
	return &Timer{fd: fd}, nil
}

// Arm schedules the timer to fire after d. Replaces any
// previously-armed deadline.
//
// Returns ErrInvalidDuration if d <= 0 (spec C-03).
// Returns ErrClosed if Close() has been called.
//
// DO NOT add a periodic-interval parameter without updating
// Wait's single-fire-then-return assumption — periodic
// timerfds queue an expiration count that the current code
// reads-and-discards once per Wait call.
func (t *Timer) Arm(d time.Duration) error {
	if d <= 0 {
		return ErrInvalidDuration
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed.Load() {
		return ErrClosed
	}
	// itimerspec: it_value is the initial expiration; it_interval
	// is 0 (one-shot, no periodic refire).
	spec := unix.ItimerSpec{
		Interval: unix.Timespec{Sec: 0, Nsec: 0},
		Value: unix.Timespec{
			Sec:  int64(d / time.Second),
			Nsec: int64(d % time.Second),
		},
	}
	if err := unix.TimerfdSettime(t.fd, 0, &spec, nil); err != nil {
		return fmt.Errorf("timerfd: settime arm: %w", err)
	}
	return nil
}

// Cancel disarms the timer. Safe to call multiple times and
// on a never-armed timer (spec C-05).
//
// **Cancel does NOT unblock a concurrent Wait.** A goroutine
// currently in Wait will continue polling until ctx cancel
// or Close. This is intentional: D-005's epoll integration
// will not use Wait; Cancel is for the post-success "tear
// down the timer cleanly" path where no Wait is in flight.
//
// Returns ErrClosed if Close() has been called.
func (t *Timer) Cancel() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed.Load() {
		return ErrClosed
	}
	// Zero itimerspec disarms.
	spec := unix.ItimerSpec{}
	if err := unix.TimerfdSettime(t.fd, 0, &spec, nil); err != nil {
		return fmt.Errorf("timerfd: settime cancel: %w", err)
	}
	return nil
}

// FD returns the underlying file descriptor for epoll
// registration (D-004 event loop will use this).
//
// Returns -1 if Close() has been called. Safe to call
// concurrently with all other methods.
func (t *Timer) FD() int {
	if t.closed.Load() {
		return -1
	}
	return t.fd
}

// Wait blocks until the timer fires OR ctx is canceled OR
// Close is called. Returns nil on fire; ctx.Err() on context
// cancellation; ErrClosed if Close happens during the wait.
//
// Implementation: a poll() loop wakes every pollInterval to
// check the closed flag and ctx state, then polls the fd for
// POLLIN. This pattern avoids the Go-on-Linux footgun where
// a goroutine parked in blocking Read on a closed-and-recycled
// fd reads from a stranger's fd (issue #7970).
//
// Cost: ~50ms response latency to ctx cancel / Close. D-005's
// epoll integration won't use Wait — it'll register the fd
// directly — so this overhead is unit-test-path only.
func (t *Timer) Wait(ctx context.Context) error {
	if t.closed.Load() {
		return ErrClosed
	}
	for {
		if t.closed.Load() {
			return ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		pollFds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pollFds, pollInterval)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if t.closed.Load() {
				return ErrClosed
			}
			return fmt.Errorf("timerfd: poll: %w", err)
		}
		if n == 0 {
			// Timeout — loop and recheck ctx/closed.
			continue
		}
		if pollFds[0].Revents&unix.POLLNVAL != 0 {
			// fd was closed under us — Close() ran.
			return ErrClosed
		}
		if pollFds[0].Revents&unix.POLLIN != 0 {
			var buf [8]byte
			n, err := unix.Read(t.fd, buf[:])
			if err != nil {
				if t.closed.Load() {
					return ErrClosed
				}
				return fmt.Errorf("timerfd: read: %w", err)
			}
			if n != 8 {
				return fmt.Errorf("timerfd: read returned %d bytes, expected 8", n)
			}
			_ = binary.LittleEndian.Uint64(buf[:]) // expiration count; unused
			return nil
		}
	}
}

// Close releases the timerfd. Idempotent (spec C-06).
//
// Safe to call concurrently with a pending Wait — the poll
// loop will observe the closed flag within pollInterval and
// return ErrClosed before this method's unix.Close runs,
// avoiding the fd-reuse race.
func (t *Timer) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// Wait briefly so a concurrent Wait observes the closed
	// flag and exits its poll loop before we unix.Close.
	// 2 * pollInterval gives the poll-loop one full iteration
	// to see closed=true after returning from poll. Worst case
	// this adds 100ms to Close; acceptable for a primitive
	// used in test scaffolding + an event loop that doesn't
	// call Wait.
	time.Sleep(2 * pollInterval * time.Millisecond)
	if err := unix.Close(t.fd); err != nil && !errors.Is(err, unix.EBADF) {
		return fmt.Errorf("timerfd: close: %w", err)
	}
	return nil
}
