package api

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrNotYetImplemented signals that an [api] method's engine-side
// implementation has not yet landed for the current milestone. Method
// signatures are stable from commit 1; bodies fill in progressively per
// docs/KENSA_GO_DAY1_PLAN.md §11. Consumers should treat this error as
// transient and retry once the relevant milestone ships.
var ErrNotYetImplemented = errors.New("kensa: not yet implemented")

// ErrHostBusy signals that a non-blocking operation found the target
// host's per-host mutex held by an in-flight transaction. Returned only
// when the caller passed [WithNonBlocking]; otherwise the engine waits
// for the mutex.
var ErrHostBusy = errors.New("kensa: host has an in-flight transaction")

// ErrRecoverActive signals that a live mutation could not proceed because a
// `kensa recover` holds the exclusive recover lock on the same store. Like
// [ErrHostBusy] it is TRANSIENT — retry once the recovery finishes. Returned by
// the engine only when it was constructed with the recover-lock fence (the
// Default* constructors wire it); a bare engine has no store path to fence on.
// The fence stops a recover from compensating a transaction the engine is
// mid-flight on (docs/test_docs/security.md #14).
var ErrRecoverActive = errors.New("kensa: store is being recovered by another process")

// ErrSchedulerUnavailable signals that the engine refused to execute a
// control-channel-sensitive transaction because the target host has
// neither at(1) nor systemd-run(1) available to arm a deadman timer.
// Atomicity cannot be honored without one of them, so the engine
// fails closed.
var ErrSchedulerUnavailable = errors.New("kensa: no scheduler available for deadman timer")

// ErrCaptureIncomplete signals that a capture handler could not record
// sufficient pre-state to guarantee a clean rollback. The engine aborts
// the transaction before any apply step runs.
var ErrCaptureIncomplete = errors.New("kensa: capture handler could not record complete pre-state")

// ErrNoActiveDeadman signals that [DeadmanControl.CancelDeadman] was
// invoked for a transaction with no armed timer.
var ErrNoActiveDeadman = errors.New("kensa: no active deadman timer for transaction")

// PlanStaleError is returned by [Executor.Execute] when the host's state
// has diverged from the plan's captured pre-state since planning. The
// step-level fields let UIs report which mechanism's pre-state changed
// and why a re-plan is required, rather than a generic staleness signal.
type PlanStaleError struct {
	// PlanID is the [Plan.ID] of the stale plan.
	PlanID uuid.UUID
	// StaleStepIndex is the [StepPreview.Index] whose pre-state diverged.
	StaleStepIndex int
	// Mechanism is the [Handler.Name] of the diverged step.
	Mechanism string
	// Field names the specific pre-state field that diverged
	// (for example, "content", "mode", "value").
	Field string
	// Expected is the value the plan captured at planning time.
	Expected interface{}
	// Actual is the value present on the host at execution time.
	Actual interface{}
	// Message is an optional human-readable summary; if empty,
	// [PlanStaleError.Error] composes one from the structured fields.
	Message string
}

// Error reports the staleness condition. If [PlanStaleError.Message] is
// set it is returned verbatim; otherwise a short summary is composed
// from the structured fields.
func (e *PlanStaleError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("kensa: plan stale at step %d (%s.%s): expected %v, got %v",
		e.StaleStepIndex, e.Mechanism, e.Field, e.Expected, e.Actual)
}
