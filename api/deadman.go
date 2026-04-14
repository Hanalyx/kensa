package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// DeadmanControl exposes cancel and status operations for armed deadman
// timers. When the engine arms a timer, operators need the ability to
// cancel it cleanly (run in-band rollback, remove the scheduled script)
// from OpenWatch's UI — without waiting for the timer window to fire.
//
// Implemented by internal/deadman. Satisfies the deadman-timer spec
// (specs/deadman/timer.spec.yaml) AC-09 and the interface requirement
// from KENSA_OPENWATCH_RESPONSE_2026-04-14.md §4.2.
type DeadmanControl interface {
	// CancelDeadman executes an immediate clean rollback of the
	// transaction's applied steps and cancels the scheduled deadman
	// script. Safer than waiting for the timer to fire because it
	// runs in-band over the existing control channel.
	//
	// Returns ErrNoActiveDeadman if no timer is armed for txnID.
	CancelDeadman(ctx context.Context, transport Transport, txnID uuid.UUID) (*RollbackResult, error)

	// DeadmanStatus returns the current armed-timer state for a
	// transaction. OpenWatch's UI polls or subscribes via the event
	// stream; the status is also accessible on demand here.
	DeadmanStatus(ctx context.Context, transport Transport, txnID uuid.UUID) (*DeadmanState, error)
}

// DeadmanState is the armed-timer state for one transaction.
type DeadmanState struct {
	TxnID        uuid.UUID
	Armed        bool
	ArmedAt      time.Time
	FiresAt      time.Time // Absolute time the scheduled script will fire
	ScriptPath   string    // Where the rollback script lives on the host
	RollbackPlan []RollbackStepPreview
}
