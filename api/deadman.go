package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// DeadmanControl exposes cancel and status operations for armed
// deadman timers. When the engine arms a timer for a
// control-channel-affecting transaction, operators need the ability
// to cancel cleanly — running an in-band rollback and removing the
// scheduled script — without waiting for the timer window to fire.
//
// Spec: deadman-timer (specs/deadman/timer.spec.yaml) AC-09.
type DeadmanControl interface {
	// CancelDeadman performs an in-band rollback of the transaction's
	// applied steps and cancels the scheduled deadman script.
	// Preferred over waiting for the timer to fire because it runs
	// synchronously over the existing control channel.
	//
	// Returns [ErrNoActiveDeadman] if no timer is armed for txnID.
	CancelDeadman(ctx context.Context, transport Transport, txnID uuid.UUID) (*RollbackResult, error)

	// DeadmanStatus returns the current armed-timer state for
	// txnID, or [ErrNoActiveDeadman] if no timer is armed.
	DeadmanStatus(ctx context.Context, transport Transport, txnID uuid.UUID) (*DeadmanState, error)
}

// DeadmanState is the armed-timer state for one transaction.
type DeadmanState struct {
	// TxnID is the source [Transaction.ID].
	TxnID uuid.UUID
	// Armed is true while the scheduled script remains pending.
	Armed bool
	// ArmedAt is when the engine scheduled the script.
	ArmedAt time.Time
	// FiresAt is the absolute time the scheduled script will fire on
	// the host if not canceled first.
	FiresAt time.Time
	// ScriptPath is the location of the rollback script on the host
	// (typically /tmp/kensa-rollback-<txn-id>.sh).
	ScriptPath string
	// RollbackPlan describes what the script would do, in execution
	// order.
	RollbackPlan []RollbackStepPreview
}
