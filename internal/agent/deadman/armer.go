// Agent-side deadman Armer. D-005 deliverable.
//
// This package's primitives (timerfd, pidfd, signalfd) and
// the eventloop integrator come from sibling subpackages.
// The Armer here is the orchestrator: it receives
// ArmDeadmanRequest from the engine, spawns a goroutine
// running the eventloop over the union of (timer ∪ pidfd ∪
// signalfd), and on the first wakeup executes the supplied
// rollback commands via the agent's LocalTransport.
//
// **Scope.**
//   - ArmDeadman: dry-run-generated rollback_commands +
//     window → spawn goroutine.
//   - CancelDeadman: cancel goroutine's context; goroutine
//     exits without firing.
//   - On wakeup (timer / parent death / SIGTERM): execute
//     rollback_commands in order via sh -c.
//
// **Per-process Armer singleton.** The agent spawns one
// Armer per agent process; activeArms is keyed by txn UUID.
// Multiple concurrent transactions to the same host are
// allowed (engine generates a unique UUID per transaction)
// but rare in production — each Arm holds its own goroutine.
//
// **SIGTERM fan-out is intentional fail-safe-closed
// behavior.** Each ArmDeadman constructs its own
// signalfd.SignalFD watching SIGTERM. Go's signal.Notify
// fans out a single process-level SIGTERM to every
// registered channel — so N concurrent arms all wake on
// one SIGTERM, and ALL N rollback scripts execute. This
// includes transactions whose Apply succeeded but whose
// Cancel hasn't yet arrived from the engine. The rationale:
// SIGTERM means "the agent is being asked to die." If the
// agent dies, the engine loses its only reliable signal
// for any in-flight transaction. Fail-safe-closed: fire
// rollback for everything in flight; operators see
// "rollback fired by deadman on signal" in evidence and
// can re-apply if a transaction was actually successful
// but raced the SIGTERM. The alternative (silent exit, no
// rollback) leaves the host in an indeterminate state with
// no recovery path.

package deadman

import (
	"context"
	"errors"
	"fmt"
	"os"

	"sync"
	"time"

	"github.com/Hanalyx/kensa/internal/agent/deadman/eventloop"
	"github.com/Hanalyx/kensa/internal/agent/deadman/pidfd"
	"github.com/Hanalyx/kensa/internal/agent/deadman/signalfd"
	"github.com/Hanalyx/kensa/internal/agent/deadman/timerfd"
	"github.com/Hanalyx/kensa/internal/agent/ownedexec"

	"golang.org/x/sys/unix"
)

// ErrAlreadyArmed is returned by Armer.ArmDeadman when a
// deadman is already in flight for the supplied txn_id.
var ErrAlreadyArmed = errors.New("deadman: txn_id already armed")

// ErrNotArmed is returned by Armer.CancelDeadman when no
// arm is in flight for the supplied txn_id.
var ErrNotArmed = errors.New("deadman: txn_id not armed")

// armedJob tracks one in-flight deadman.
type armedJob struct {
	cancel   context.CancelFunc // cancels the watcher goroutine
	done     chan struct{}      // closed only after joined teardown
	wake     context.CancelFunc
	fired    bool
	started  bool
	canceled bool
}

// Armer is the agent-side deadman orchestrator. Construct
// with New(); call ArmDeadman / CancelDeadman from the wire-
// dispatcher (server.go).
type Armer struct {
	mu             sync.Mutex
	active         map[string]*armedJob // txn_id → job
	closed         bool
	recovering     int
	mutations      map[*mutation]struct{}
	captures       map[*capture]struct{}
	changed        chan struct{}
	failures       []error
	beforeAllocate func() // deterministic instance-local test seam
	commandTimeout time.Duration
	commandQueued  func()       // instance-local queue-observation seam
	afterTeardown  func() error // instance-local error propagation seam
}

// defaultArmer is the package-level singleton used by
// HandleArmDeadman / HandleCancelDeadman. The wire-dispatch
// in server.go routes through these free functions; the
// singleton holds the activeArms state per agent process.
var defaultArmer = New()

// New constructs a fresh Armer. Most callers should use the
// package-level defaultArmer via HandleArmDeadman /
// HandleCancelDeadman.
func New() *Armer {
	return &Armer{
		active:    make(map[string]*armedJob),
		mutations: make(map[*mutation]struct{}), captures: make(map[*capture]struct{}), changed: make(chan struct{}), commandTimeout: 60 * time.Second,
	}
}

// ArmDeadman spawns a watcher goroutine for the given
// txn_id. The goroutine runs an event loop over timerfd +
// parent pidfd + SIGTERM signalfd; on any wakeup (timer
// expires, parent dies, signal received) the goroutine
// executes rollbackCommands in order via sh -c.
//
// Returns the fires-at Unix-seconds timestamp (agent's local
// clock; informational only — the engine's clock is
// authoritative).
//
// Failure modes:
//   - txn_id already armed → ErrAlreadyArmed
//   - timerfd_create / signalfd / pidfd_open syscall failure
//     → wrapped error
//   - window <= 0 → wrapped ErrInvalidDuration from timerfd
//
// Command ownership first requires pidfd support for this agent. If that
// prerequisite is unavailable, admission fails before mutation. Parent lookup
// retains its existing best-effort behavior below.
//
// ErrParentGone from pidfd.OpenParent does NOT fail the Arm
// either — the watcher proceeds with just timerfd + signalfd;
// the engine should NOT have called ArmDeadman with no
// parent visible, but if it did, we degrade gracefully.
func (a *Armer) ArmDeadman(txnID string, window time.Duration, rollbackCommands []string) (int64, error) {
	if window <= 0 {
		return 0, fmt.Errorf("deadman: window must be positive: %v", window)
	}

	// P0-2 fix: reserve the txn_id slot atomically BEFORE
	// any fd allocation. Two concurrent Arm calls with the
	// same txn_id can otherwise race past the duplicate
	// check and both end up allocating fds + storing
	// (with the second overwriting the first → first's
	// goroutine + fds leak, both rollback on fire).
	//
	// We insert a placeholder job under the lock; if any
	// subsequent allocation fails, we delete the placeholder
	// before returning.
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return 0, ErrShuttingDown
	}
	if _, exists := a.active[txnID]; exists {
		a.mu.Unlock()
		return 0, ErrAlreadyArmed
	}
	jobCtx, jobCancel := context.WithCancel(context.Background())
	waitCtx, wake := context.WithCancel(jobCtx)
	job := &armedJob{cancel: jobCancel, done: make(chan struct{}), wake: wake}
	a.active[txnID] = job
	a.notifyLocked()
	a.mu.Unlock()
	if a.beforeAllocate != nil {
		a.beforeAllocate()
	}

	// On any allocation failure below, clear the reservation.
	cleanupOnFailure := func(cause error) {
		jobCancel()
		wake()
		a.finishJob(txnID, job, cause)
	}

	if err := ownedexec.Prepare(); err != nil {
		cleanupOnFailure(err)
		return 0, err
	}
	timer, err := timerfd.New()
	if err != nil {
		cleanupOnFailure(err)
		return 0, fmt.Errorf("deadman: timerfd: %w", err)
	}
	if err := timer.Arm(window); err != nil {
		closeErr := timer.Close()
		cleanupOnFailure(errors.Join(err, closeErr))
		return 0, fmt.Errorf("deadman: arm timer: %w", err)
	}

	sig, err := signalfd.New(unix.SIGTERM)
	if err != nil {
		closeErr := timer.Close()
		cleanupOnFailure(errors.Join(err, closeErr))
		return 0, fmt.Errorf("deadman: signalfd: %w", err)
	}

	// pidfd is best-effort. Both probe-failure AND
	// ErrParentGone paths (P1-2 fix) fall back to prctl so
	// the agent at least dies cleanly when the parent dies,
	// even if we can't fire rollback under SIGKILL.
	var parent *pidfd.Pidfd
	if probeErr := pidfd.ProbeSupport(); probeErr == nil {
		p, err := pidfd.OpenParent()
		if err == nil {
			parent = p
		} else {
			// ErrKernelTooOld / ErrPidfdBlocked / ErrParentGone
			// all fall back to prctl. ErrParentGone is unusual
			// — engine shouldn't arm if parent is already
			// dead — but if it does, the prctl call is a
			// defensive backstop.
			_ = signalfd.SetParentDeathSignal(unix.SIGKILL)
		}
	} else {
		_ = signalfd.SetParentDeathSignal(unix.SIGKILL)
	}

	loop, err := eventloop.New()
	if err != nil {
		closeErr := teardown(nil, timer, sig, parent)
		cleanupOnFailure(errors.Join(err, closeErr))
		return 0, fmt.Errorf("deadman: eventloop: %w", err)
	}
	if err := loop.Register(timer.FD(), eventloop.EventTimer); err != nil {
		closeErr := teardown(loop, timer, sig, parent)
		cleanupOnFailure(errors.Join(err, closeErr))
		return 0, fmt.Errorf("deadman: register timer: %w", err)
	}
	if err := loop.Register(sig.FD(), eventloop.EventSignal); err != nil {
		closeErr := teardown(loop, timer, sig, parent)
		cleanupOnFailure(errors.Join(err, closeErr))
		return 0, fmt.Errorf("deadman: register signal: %w", err)
	}
	if parent != nil {
		if err := loop.Register(parent.FD(), eventloop.EventParentDeath); err != nil {
			closeErr := teardown(loop, timer, sig, parent)
			cleanupOnFailure(errors.Join(err, closeErr))
			return 0, fmt.Errorf("deadman: register pidfd: %w", err)
		}
	}

	firesAt := time.Now().Add(window).Unix()

	go a.watcherLoop(jobCtx, waitCtx, txnID, job, loop, timer, sig, parent, rollbackCommands)

	return firesAt, nil
}

// watcherLoop is the goroutine spawned by ArmDeadman. Blocks
// on loop.Run; on event, executes rollbackCommands; in either
// the event-fire or ctx-cancel paths, tears down the fds and
// removes the txn from activeArms.
func (a *Armer) watcherLoop(
	ctx context.Context,
	waitCtx context.Context,
	txnID string,
	job *armedJob,
	loop *eventloop.Loop,
	timer *timerfd.Timer,
	sig *signalfd.SignalFD,
	parent *pidfd.Pidfd,
	rollbackCommands []string,
) {
	var outcome error
	defer func() {
		closeErr := teardown(loop, timer, sig, parent)
		if a.afterTeardown != nil {
			closeErr = errors.Join(closeErr, a.afterTeardown())
		}
		job.cancel()
		job.wake()
		a.finishJob(txnID, job, errors.Join(outcome, closeErr))
	}()
	_, waitErr := loop.Run(waitCtx)
	a.mu.Lock()
	if job.canceled {
		a.mu.Unlock()
		return
	}
	// A shutdown wake is deliberately distinct from explicit cancellation.
	job.fired = true
	a.recovering++
	for operation := range a.mutations {
		operation.cancel()
	}
	a.notifyLocked()
	a.mu.Unlock()
	if waitErr != nil && !errors.Is(waitErr, context.Canceled) {
		outcome = errors.Join(outcome, waitErr)
	}
	// Every trigger waits for native Capture waits as well as mutating work.
	reportedCapture := false
	for {
		a.mu.Lock()
		if len(a.mutations) == 0 && len(a.captures) == 0 {
			a.mu.Unlock()
			break
		}
		changed := a.changed
		pendingCapture := len(a.captures) > 0
		a.mu.Unlock()
		if pendingCapture && !reportedCapture {
			fmt.Fprintln(os.Stderr, "kensa agent: recovery waiting for natural Capture completion; UNRESOLVED until joined")
			reportedCapture = true
		}
		<-changed
	}
	for index, command := range rollbackCommands {
		a.mu.Lock()
		if job.canceled {
			if job.started {
				outcome = errors.Join(outcome, errors.New("deadman: recovery aborted after execution began"))
			}
			a.mu.Unlock()
			return
		}
		a.mu.Unlock()
		_, _, err := ownedexec.RunRecovery(ctx, a.commandTimeout, func() {
			a.mu.Lock()
			job.started = true
			a.notifyLocked()
			a.mu.Unlock()
		}, a.commandQueued, "/bin/sh", "-c", command)
		if ctx.Err() != nil {
			a.mu.Lock()
			started := job.started
			a.mu.Unlock()
			if started {
				outcome = errors.Join(outcome, err, errors.New("deadman: recovery aborted after execution began"))
			} else if err != nil && err != context.Canceled {
				// Only pure queued cancellation is clean. A simultaneous
				// launch/accounting error must not disappear with cancellation.
				outcome = errors.Join(outcome, fmt.Errorf("deadman: rollback command %d: %w", index, err))
			}
			// A canceled waiter that never launched is a clean pending cancel.
			// Prior ordinary errors, if any, remain in outcome.
			return
		}
		if err != nil {
			outcome = errors.Join(outcome, fmt.Errorf("deadman: rollback command %d: %w", index, err))
		}
		// Ordinary failures continue only after ownedexec joins the failed work.
	}

}

// CancelDeadman tears down the watcher goroutine for txn_id
// without firing rollback. Returns wasActive=true if an arm
// was in flight; false if no matching arm (which is not an
// error — the engine may double-cancel during teardown).
func (a *Armer) CancelDeadman(txnID string) (wasActive bool) {
	active, _ := a.Cancel(txnID)
	return active
}

// finishJob publishes completion only after actual watcher/descriptor teardown.
func (a *Armer) finishJob(txnID string, job *armedJob, outcome error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if outcome != nil {
		a.failures = append(a.failures, outcome)
	}
	if job.fired {
		a.recovering--
	}
	delete(a.active, txnID)
	close(job.done)
	a.notifyLocked()
}

// teardown closes all the primitive fds. Helper to keep the
// armer paths short.
func teardown(loop *eventloop.Loop, timer *timerfd.Timer, sig *signalfd.SignalFD, parent *pidfd.Pidfd) error {
	var result error
	if loop != nil {
		result = errors.Join(result, loop.Close())
	}
	if timer != nil {
		result = errors.Join(result, timer.Close())
	}
	if sig != nil {
		result = errors.Join(result, sig.Close())
	}
	if parent != nil {
		result = errors.Join(result, parent.Close())
	}
	return result
}

// HandleArmDeadman / HandleCancelDeadman are the free-
// function entry points the wire dispatcher (server.go)
// calls. They route through the package-level defaultArmer
// singleton.

// HandleArmDeadman dispatches an ArmDeadman wire request to
// the package-level Armer.
func HandleArmDeadman(txnID string, windowSeconds int64, rollbackCommands []string) (firesAt int64, err error) {
	return defaultArmer.ArmDeadman(txnID, time.Duration(windowSeconds)*time.Second, rollbackCommands)
}

// HandleCancelDeadman dispatches a CancelDeadman wire request.
func HandleCancelDeadman(txnID string) (wasActive bool) {
	return defaultArmer.CancelDeadman(txnID)
}

// ActiveCount returns the number of in-flight arms. Used by
// the integration tests and the agent's diagnostic surface.
func (a *Armer) ActiveCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active)
}
