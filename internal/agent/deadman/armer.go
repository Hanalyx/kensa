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
	"os/exec"
	"sync"
	"time"

	"github.com/Hanalyx/kensa-go/internal/agent/deadman/eventloop"
	"github.com/Hanalyx/kensa-go/internal/agent/deadman/pidfd"
	"github.com/Hanalyx/kensa-go/internal/agent/deadman/signalfd"
	"github.com/Hanalyx/kensa-go/internal/agent/deadman/timerfd"

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
	cancel context.CancelFunc // cancels the watcher goroutine
	done   chan struct{}      // closed when goroutine exits
}

// Armer is the agent-side deadman orchestrator. Construct
// with New(); call ArmDeadman / CancelDeadman from the wire-
// dispatcher (server.go).
type Armer struct {
	mu     sync.Mutex
	active map[string]*armedJob // txn_id → job
}

// defaultArmer is the package-level singleton used by
// HandleArmDeadman / HandleCancelDeadman. server.go's
// wire-dispatch routes through these free functions; the
// singleton holds the activeArms state per agent process.
var defaultArmer = New()

// New constructs a fresh Armer. Most callers should use the
// package-level defaultArmer via HandleArmDeadman /
// HandleCancelDeadman.
func New() *Armer {
	return &Armer{
		active: make(map[string]*armedJob),
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
// Pidfd unavailability (kernel <5.3 or seccomp-blocked) does
// NOT fail the Arm — the watcher uses prctl(PR_SET_PDEATHSIG)
// fallback instead. The deadman won't get to run rollback
// under parent SIGKILL (Q3.a accepted risk).
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
	jobCtx, jobCancel := context.WithCancel(context.Background())
	job := &armedJob{
		cancel: jobCancel,
		done:   make(chan struct{}),
	}
	a.mu.Lock()
	if _, exists := a.active[txnID]; exists {
		a.mu.Unlock()
		jobCancel() // drain the un-used ctx
		return 0, ErrAlreadyArmed
	}
	a.active[txnID] = job
	a.mu.Unlock()

	// On any allocation failure below, clear the reservation.
	cleanupOnFailure := func() {
		a.removeArm(txnID)
		jobCancel()
	}

	timer, err := timerfd.New()
	if err != nil {
		cleanupOnFailure()
		return 0, fmt.Errorf("deadman: timerfd: %w", err)
	}
	if err := timer.Arm(window); err != nil {
		_ = timer.Close()
		cleanupOnFailure()
		return 0, fmt.Errorf("deadman: arm timer: %w", err)
	}

	sig, err := signalfd.New(unix.SIGTERM)
	if err != nil {
		_ = timer.Close()
		cleanupOnFailure()
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
		_ = timer.Close()
		_ = sig.Close()
		if parent != nil {
			_ = parent.Close()
		}
		cleanupOnFailure()
		return 0, fmt.Errorf("deadman: eventloop: %w", err)
	}
	if err := loop.Register(timer.FD(), eventloop.EventTimer); err != nil {
		teardown(loop, timer, sig, parent)
		cleanupOnFailure()
		return 0, fmt.Errorf("deadman: register timer: %w", err)
	}
	if err := loop.Register(sig.FD(), eventloop.EventSignal); err != nil {
		teardown(loop, timer, sig, parent)
		cleanupOnFailure()
		return 0, fmt.Errorf("deadman: register signal: %w", err)
	}
	if parent != nil {
		if err := loop.Register(parent.FD(), eventloop.EventParentDeath); err != nil {
			teardown(loop, timer, sig, parent)
			cleanupOnFailure()
			return 0, fmt.Errorf("deadman: register pidfd: %w", err)
		}
	}

	firesAt := time.Now().Add(window).Unix()

	go a.watcherLoop(jobCtx, txnID, job, loop, timer, sig, parent, rollbackCommands)

	return firesAt, nil
}

// watcherLoop is the goroutine spawned by ArmDeadman. Blocks
// on loop.Run; on event, executes rollbackCommands; in either
// the event-fire or ctx-cancel paths, tears down the fds and
// removes the txn from activeArms.
func (a *Armer) watcherLoop(
	ctx context.Context,
	txnID string,
	job *armedJob,
	loop *eventloop.Loop,
	timer *timerfd.Timer,
	sig *signalfd.SignalFD,
	parent *pidfd.Pidfd,
	rollbackCommands []string,
) {
	defer close(job.done)
	defer teardown(loop, timer, sig, parent)
	defer a.removeArm(txnID)

	event, err := loop.Run(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// CancelDeadman path — clean exit, no rollback.
			return
		}
		// P1-1 fix: any non-cancel error from the event loop
		// (epoll error, ErrClosed during teardown race,
		// internal) MUST be treated as a wakeup — the
		// deadman's fail-safe-closed posture says "if
		// uncertain, fire rollback." Silent-drop would leave
		// the host in an indeterminate state with no recovery
		// path. We fall through to the rollback-execute
		// branch below; event.Kind stays zero, which is
		// surfaced to operators via the kind logging stub
		// once a logger is wired.
		_ = err
	}

	// Wake-up: fire rollback commands. P1-3 fix: thread the
	// watcher's ctx into exec.CommandContext so CancelDeadman
	// can interrupt a mid-rollback exec. Per-command timeout
	// kept liberal (60s) — federal-host rollback steps run
	// apt / systemctl / chmod / etc.; 60s covers the slow-
	// host case without leaving us indefinitely stuck on a
	// single bad command.
	_ = event // event.Kind diagnostics once a logger is wired
	for _, cmd := range rollbackCommands {
		execCtx, execCancel := context.WithTimeout(ctx, 60*time.Second)
		c := exec.CommandContext(execCtx, "/bin/sh", "-c", cmd)
		_ = c.Run()
		execCancel()
		// On ctx-cancel mid-rollback, stop processing the
		// remaining commands; the operator decided to abort.
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
	}
}

// CancelDeadman tears down the watcher goroutine for txn_id
// without firing rollback. Returns wasActive=true if an arm
// was in flight; false if no matching arm (which is not an
// error — the engine may double-cancel during teardown).
func (a *Armer) CancelDeadman(txnID string) (wasActive bool) {
	a.mu.Lock()
	job, exists := a.active[txnID]
	a.mu.Unlock()
	if !exists {
		return false
	}
	job.cancel()
	// Wait for the goroutine to exit so the caller can
	// reliably observe state (e.g., that fds are released)
	// before returning.
	<-job.done
	return true
}

// removeArm clears txn from activeArms. Called from
// watcherLoop's deferred cleanup, regardless of whether the
// loop exited via fire-rollback or cancel.
func (a *Armer) removeArm(txnID string) {
	a.mu.Lock()
	delete(a.active, txnID)
	a.mu.Unlock()
}

// teardown closes all the primitive fds. Helper to keep the
// armer paths short.
func teardown(loop *eventloop.Loop, timer *timerfd.Timer, sig *signalfd.SignalFD, parent *pidfd.Pidfd) {
	if loop != nil {
		_ = loop.Close()
	}
	if timer != nil {
		_ = timer.Close()
	}
	if sig != nil {
		_ = sig.Close()
	}
	if parent != nil {
		_ = parent.Close()
	}
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
