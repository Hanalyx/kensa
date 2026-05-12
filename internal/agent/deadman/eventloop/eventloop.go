// Package eventloop wraps epoll_create1 + EPOLL_CTL_ADD +
// epoll_wait into a single-thread wakeup integrator for the
// rebuilt agent-side deadman subsystem.
//
// **Why epoll.** D-001/D-002/D-003 each ship a poll-based
// Wait for unit-test ergonomics, but the production deadman
// waits on the UNION of three (or more) fds simultaneously:
// timer expires OR parent dies OR SIGTERM arrives. Three
// goroutines select-ing channels would work but adds
// cross-goroutine coordination. epoll lets one goroutine
// wait on the union and report which fd fired.
//
// **Single-event-per-Run.** Each Run call returns ONE event.
// D-005's use case is "wait for any wakeup; on wakeup,
// execute rollback and exit" — no persistent dispatch
// needed.
//
// **Drain belongs to the caller.** When epoll_wait says
// timerfd is readable, the loop reports "timer fired"; the
// caller (with reference to the timerfd.Timer) reads it.
// Cleaner than baking per-source drain into the loop.
//
// Spec: specs/deadman/eventloop.spec.yaml (D-004).
package eventloop

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ErrClosed is returned by methods on a Loop that has
// already been Close()d.
var ErrClosed = errors.New("eventloop: loop is closed")

// pollInterval matches the primitive packages — 50ms wakeup
// for ctx/closed checks during epoll_wait.
const pollInterval = 50

// EventKind tags the source of an event returned by Run.
type EventKind int

const (
	// EventUnknown is the zero value; never returned by Run.
	EventUnknown EventKind = iota

	// EventTimer indicates a registered timerfd fired
	// (CLOCK_BOOTTIME deadline elapsed).
	EventTimer

	// EventParentDeath indicates a registered pidfd became
	// readable (the watched process exited).
	EventParentDeath

	// EventSignal indicates a registered signalfd became
	// readable (SIGTERM or other watched signal arrived).
	EventSignal

	// EventControlChannel indicates a registered control-
	// channel fd (e.g., D-005's transport socket) saw
	// activity. Used for "the controller sent a cancel"
	// detection.
	EventControlChannel
)

// String returns the EventKind name for logging.
func (e EventKind) String() string {
	switch e {
	case EventTimer:
		return "timer"
	case EventParentDeath:
		return "parent-death"
	case EventSignal:
		return "signal"
	case EventControlChannel:
		return "control-channel"
	}
	return "unknown"
}

// Event is what Run returns: the kind of source that woke us
// up and the underlying file descriptor.
type Event struct {
	Kind EventKind
	FD   int
}

// Loop wraps an epoll_create1 fd. Construct with New(); call
// Close() to release the epoll fd.
//
// Concurrency: Register/Close are safe to call from any
// goroutine. Run should be called from one goroutine at a
// time (single-event-per-Run semantics).
type Loop struct {
	epfd int

	mu      sync.Mutex
	sources map[int]EventKind // fd → kind

	closed atomic.Bool
}

// New creates a Loop with an epoll fd (EPOLL_CLOEXEC set).
func New() (*Loop, error) {
	fd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("eventloop: epoll_create1: %w", err)
	}
	return &Loop{
		epfd:    fd,
		sources: make(map[int]EventKind),
	}, nil
}

// Register adds `fd` to the epoll set with the given
// EventKind tag. The fd is registered with EPOLLIN (level-
// trigger — no EPOLLET, no EPOLLONESHOT) so it stays
// readable until the caller drains it.
//
// Safe to call before or during Run.
//
// Returns ErrClosed if Close has been called.
func (l *Loop) Register(fd int, kind EventKind) error {
	if l.closed.Load() {
		return ErrClosed
	}
	if kind == EventUnknown {
		return errors.New("eventloop: cannot register EventUnknown")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ev := &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
	}
	if err := unix.EpollCtl(l.epfd, unix.EPOLL_CTL_ADD, fd, ev); err != nil {
		return fmt.Errorf("eventloop: epoll_ctl ADD fd=%d: %w", fd, err)
	}
	l.sources[fd] = kind
	return nil
}

// Run blocks until any registered fd becomes readable OR
// ctx is canceled OR Close is called. Returns the Event
// describing which source fired, or ctx.Err()/ErrClosed.
//
// Single-event-per-Run: the first event wins. D-005's use
// case (fire rollback and exit) doesn't need persistent
// dispatch.
func (l *Loop) Run(ctx context.Context) (Event, error) {
	if l.closed.Load() {
		return Event{}, ErrClosed
	}
	events := make([]unix.EpollEvent, 8)
	for {
		if l.closed.Load() {
			return Event{}, ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return Event{}, err
		}
		n, err := unix.EpollWait(l.epfd, events, pollInterval)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if l.closed.Load() {
				return Event{}, ErrClosed
			}
			return Event{}, fmt.Errorf("eventloop: epoll_wait: %w", err)
		}
		if n == 0 {
			continue
		}
		// First-event-wins. If multiple fds fired in the
		// same epoll batch, we return the first; the rest
		// stay readable for a hypothetical re-Run call.
		// The "first" is determined by kernel registration
		// order, which is acceptable for D-005's deadman
		// (any wakeup triggers rollback; which one fires
		// first doesn't matter for fail-safe semantics).
		//
		// We don't inspect events[i].Events for POLLERR /
		// POLLHUP — if a registered fd transitions to an
		// error state, we still report the wakeup. The
		// deadman's failure model is fail-safe: trip on
		// suspicion, don't gate on "the fd looks healthy."
		l.mu.Lock()
		var found Event
		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)
			kind, ok := l.sources[fd]
			if !ok {
				continue
			}
			found = Event{Kind: kind, FD: fd}
			break
		}
		l.mu.Unlock()
		if found.Kind == EventUnknown {
			// epoll returned an fd we don't know about
			// (raced with concurrent Register/unregister?).
			// Loop and re-poll.
			continue
		}
		return found, nil
	}
}

// Close releases the epoll fd. Idempotent.
//
// Safe to call concurrently with a pending Run — the run
// loop observes the closed flag within pollInterval and
// exits via ErrClosed before this method's unix.Close runs.
func (l *Loop) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Drain so a concurrent Run observes closed=true and
	// exits before we close the epoll fd. Avoids the
	// Go-on-Linux fd-reuse footgun.
	time.Sleep(2 * pollInterval * time.Millisecond)
	if err := unix.Close(l.epfd); err != nil && !errors.Is(err, unix.EBADF) {
		return fmt.Errorf("eventloop: close: %w", err)
	}
	return nil
}
