package engine

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
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

// JournalStore is the OPTIONAL crash-recovery capability a [Store] may
// implement (asserted by type, mirroring the fsatomic.Transport pattern).
// When the engine's store implements it, the engine writes the intent
// journal in the PREPARE phase — atomically with the pre-state, before any
// host mutation — and clears it at terminal. A store that does not implement
// it falls back to plain [Store.PersistPreStates] with no crash-recovery
// journaling, so existing stores keep working unchanged.
type JournalStore interface {
	// PrepareTransaction writes the journal entry and the pre-states in ONE
	// atomic, synchronous commit (the write-ahead barrier).
	PrepareTransaction(ctx context.Context, entry api.JournalEntry, preStates []api.PreState) error
	// AdvanceJournalCursor durably records, write-ahead, the step about to
	// mutate.
	AdvanceJournalCursor(ctx context.Context, txnID uuid.UUID, cursor int) error
	// LoadOpenJournalEntries returns entries whose transaction never reached
	// a terminal status — the recovery targets.
	LoadOpenJournalEntries(ctx context.Context) ([]api.JournalEntry, error)
	// ClearJournalEntry removes an entry once its transaction is terminal.
	ClearJournalEntry(ctx context.Context, txnID uuid.UUID) error
}

// RollbackStore is the OPTIONAL capability a [Store] may implement to
// record the outcome of a deliberate rollback (`kensa rollback --start`)
// back to durable storage — asserted by type, mirroring [JournalStore].
// When the engine's store implements it, a successful RollbackTransaction
// marks the transaction rolled-back (status + rolled_back_at), records the
// per-step rollback events, and refreshes the owning session's counters so
// it stops showing as rollback-able. A store that does not implement it
// reverts the host but records nothing (the pre-fix behavior), so existing
// stores keep working unchanged.
type RollbackStore interface {
	// PersistRollback records that txnID was rolled back at rolledBackAt,
	// with one rollback event per step result. It must not be called for a
	// partial rollback (a step that failed); the engine only calls it after
	// every step succeeded.
	PersistRollback(ctx context.Context, txnID uuid.UUID, results []api.RollbackResult, rolledBackAt time.Time) error
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
	// Arm uploads a POSIX shell rollback script to the host and
	// schedules it via at(1) or systemd-run. The script is generated
	// by dry-running each capturable step's RollbackHandler against
	// the captured preStates. Returns the remote script path and the
	// absolute fire epoch (Unix seconds). Returns
	// [api.ErrSchedulerUnavailable] when neither at(1) nor systemd-run
	// is available on the host.
	Arm(ctx context.Context, transport api.Transport, txnID uuid.UUID, preStates []api.PreState) (scriptPath string, firesAt int64, err error)

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
