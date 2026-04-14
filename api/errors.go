package api

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrNotYetImplemented is returned by api methods whose implementation has
// not yet landed per the KENSA_GO_DAY1_PLAN.md milestone sequence.
// Signatures are stable from commit 1; bodies fill in progressively.
var ErrNotYetImplemented = errors.New("kensa: not yet implemented")

// ErrHostBusy is returned by non-blocking operations against a host that
// has an in-flight transaction. Callers using WithNonBlocking() receive
// this immediately instead of waiting for the per-host mutex.
var ErrHostBusy = errors.New("kensa: host has an in-flight transaction")

// ErrSchedulerUnavailable is returned when a control-channel-sensitive
// transaction cannot arm its deadman timer because neither `at` nor
// `systemd-run` is available on the target host. The engine refuses to
// execute such a transaction because atomicity cannot be honored.
var ErrSchedulerUnavailable = errors.New("kensa: no scheduler available for deadman timer")

// ErrCaptureIncomplete is returned when a capture handler cannot record
// sufficient pre-state to guarantee a clean rollback. The engine aborts
// the transaction before any apply step runs.
var ErrCaptureIncomplete = errors.New("kensa: capture handler could not record complete pre-state")

// ErrNoActiveDeadman is returned by DeadmanControl.CancelDeadman when no
// timer is armed for the specified transaction.
var ErrNoActiveDeadman = errors.New("kensa: no active deadman timer for transaction")

// PlanStaleError is returned by Executor.Execute when the host's state has
// diverged from the plan's captured pre-state since the plan was produced.
// Step-level detail lets UIs say "re-plan because X changed," not just
// "re-plan."
type PlanStaleError struct {
	PlanID         uuid.UUID
	StaleStepIndex int
	Mechanism      string      // The mechanism whose pre-state diverged
	Field          string      // Specific field, e.g. "content", "mode", "value"
	Expected       interface{} // What the plan captured
	Actual         interface{} // What the host has now
	Message        string      // Human-readable summary
}

// Error implements the error interface.
func (e *PlanStaleError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("kensa: plan stale at step %d (%s.%s): expected %v, got %v",
		e.StaleStepIndex, e.Mechanism, e.Field, e.Expected, e.Actual)
}
