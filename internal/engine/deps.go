package engine

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// Store persists transactions and their pre-state bundles to durable
// storage. The engine writes through the Store before any apply step
// runs (engine-transaction spec C-02), so a crash between write and
// apply leaves pre-state recoverable.
//
// The production implementation is internal/store/sqlite. The engine
// holds only this interface so tests can substitute an in-memory fake.
type Store interface {
	// PersistPreStates writes the pre-state bundle for a transaction.
	// Must complete (write + fsync) before the engine enters the apply
	// phase.
	PersistPreStates(ctx context.Context, txnID uuid.UUID, preStates []api.PreState) error

	// PersistResult writes the terminal [api.TransactionResult] to the
	// log. Called once per transaction at the commit-or-rollback
	// terminus.
	PersistResult(ctx context.Context, result *api.TransactionResult) error

	// LoadPreStates returns the previously persisted pre-state bundle
	// for a transaction. Used by `kensa rollback --start N` for
	// out-of-band rollback after a crash.
	LoadPreStates(ctx context.Context, txnID uuid.UUID) ([]api.PreState, error)
}

// Signer produces and verifies Ed25519 signatures over canonicalized
// evidence envelopes (evidence-envelope spec). The engine calls Sign at
// commit time; consumers call Verify via [api.Kensa.VerifyEnvelope].
type Signer interface {
	// Sign returns the Ed25519 signature over the canonicalized
	// envelope bytes. The signing key ID is recorded in
	// [api.EvidenceEnvelope.SigningKeyID].
	Sign(envelope *api.EvidenceEnvelope) (signature []byte, keyID string, err error)

	// Verify checks signature against the deployment's registered
	// public keys and rotation history.
	Verify(envelope *api.EvidenceEnvelope) (*api.VerifyResult, error)
}

// DeadmanArmer arms an out-of-band rollback path before applying a
// control-channel-affecting change (deadman-timer spec). The engine
// invokes this only when the transaction's selected implementation
// touches SSH, networking, PAM, or firewall state.
type DeadmanArmer interface {
	// Arm schedules a rollback script on the host that will run after
	// the timer window if the engine does not call Cancel first.
	// Returns the path to the script on the host and the absolute fire
	// time, both surfaced via [api.DeadmanState].
	Arm(ctx context.Context, transport api.Transport, txnID uuid.UUID, plan []api.RollbackStepPreview) (scriptPath string, firesAt int64, err error)

	// Cancel removes the scheduled rollback script and verifies it no
	// longer appears in the host's job list. Failure to verify is
	// recorded as a transaction anomaly per deadman-timer spec C-04.
	Cancel(ctx context.Context, transport api.Transport, txnID uuid.UUID) error
}

// EventBus is the engine's connection to the event stream that
// [api.EventSubscriber] consumers subscribe to. The engine emits
// transaction-lifecycle events at phase boundaries; the bus fans them
// out to subscribers with the back-pressure semantics described on
// [api.EventSubscriber].
type EventBus interface {
	api.EventPublisher
	api.EventSubscriber
}
