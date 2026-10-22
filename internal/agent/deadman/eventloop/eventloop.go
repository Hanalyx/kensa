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

	// life leases epfd across kernel operations; mu protects source registration.
	// Register and Run share lifetime leases, so registration can wake a pending Run.
	life    sync.RWMutex
	mu      sync.Mutex
	sources map[int]EventKind // fd → kind

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error

	// Per-instance seam for deterministic tests around real kernel waits.
	wait           func(int, []unix.EpollEvent, int) (int, error)
	beforeRegister func()
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
		wait:    unix.EpollWait,
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
	l.life.RLock()
	defer l.life.RUnlock()
	if l.closed.Load() {
		return ErrClosed
	}
	if kind == EventUnknown {
		return errors.New("eventloop: cannot register EventUnknown")
	}
	if l.beforeRegister != nil {
		l.beforeRegister()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return ErrClosed
	}
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
	events := make([]unix.EpollEvent, 8)
	for {
		event, err := l.waitOnce(ctx, events)
		if err != nil || event.Kind != EventUnknown {
			return event, err
		}
	}
}

// waitOnce retains epfd through the kernel wait and interpretation of readiness.
// Its shared lease allows concurrent Register calls; Close waits for its release.
func (l *Loop) waitOnce(ctx context.Context, events []unix.EpollEvent) (Event, error) {
	l.life.RLock()
	defer l.life.RUnlock()
	if l.closed.Load() {
		return Event{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
	n, err := l.wait(l.epfd, events, pollInterval)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed.Load() {
		return Event{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
	if errors.Is(err, unix.EINTR) {
		return Event{}, nil
	}
	if err != nil {
		return Event{}, fmt.Errorf("eventloop: epoll_wait: %w", err)
	}
	if n == 0 {
		return Event{}, nil
	}
	// First-event-wins, retaining the existing kernel batch order and source tags.
	// Level-triggered sources remain readable until their owner drains them.
	// Error/hangup readiness still counts as a wakeup, preserving fail-safe policy.
	for i := 0; i < n; i++ {
		fd := int(events[i].Fd)
		if kind, ok := l.sources[fd]; ok {
			return Event{Kind: kind, FD: fd}, nil
		}
	}
	// Ignore unregistered sources and retry, as before.
	return Event{}, nil
}

// Close publishes closure, joins active kernel operations and releases epfd once.
// Concurrent Close calls wait for the same completed teardown. Source descriptor
// ownership remains with callers, who must keep sources open while registered.
func (l *Loop) Close() error {
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		l.life.Lock()
		defer l.life.Unlock()
		if err := unix.Close(l.epfd); err != nil && !errors.Is(err, unix.EBADF) {
			l.closeErr = fmt.Errorf("eventloop: close: %w", err)
		}
	})
	return l.closeErr
}
