// Package engine implements the four-phase transaction coordinator
// (capture → apply → validate → commit-or-rollback) defined by the
// engine-transaction spec at specs/engine/transaction.spec.yaml.
//
// The engine is Tier 1: its correctness IS the atomicity commitment in
// docs/TRANSACTION_CONTRACT_V1.md. Every change to this package
// requires a human-authored failure-mode analysis in the PR per
// CONTRIBUTING.md, and the rollback path requires two-human review.
//
// # Architecture
//
// The Run loop is split across files for review-locality:
//
//   - preflight.go — validate steps, check transactional consistency,
//     scan for control-channel sensitivity.
//   - capture.go   — invoke each capturable step's CaptureHandler,
//     persist the bundle.
//   - apply.go     — invoke each step's Handler.Apply in order.
//   - validate.go  — run the rule's check plus declared validators.
//   - commit.go    — sign envelope, write log.
//   - rollback.go  — invoke each applied step's RollbackHandler in
//     reverse order.
//
// External consumers go through [api.Kensa]; this package backs that
// type via [Engine.AsKensa].
package engine

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

// Engine is the transaction coordinator. Construct one with [New], then
// call [Engine.Run] for each transaction.
type Engine struct {
	registry *handler.Registry
	store    Store
	signer   Signer
	deadman  DeadmanArmer
	events   EventBus
	locks    *hostLocks
}

// Option configures [Engine] at construction. The default zero-config
// engine uses an in-memory store, a no-op signer, a no-op deadman
// armer, and a no-op event bus — sufficient for unit tests but not for
// production.
type Option func(*Engine)

// WithRegistry overrides the handler registry. Default is
// [handler.Default].
func WithRegistry(r *handler.Registry) Option {
	return func(e *Engine) { e.registry = r }
}

// WithStore overrides the persistence backend.
func WithStore(s Store) Option { return func(e *Engine) { e.store = s } }

// WithSigner overrides the evidence signer.
func WithSigner(s Signer) Option { return func(e *Engine) { e.signer = s } }

// WithDeadman overrides the deadman-timer subsystem.
func WithDeadman(d DeadmanArmer) Option { return func(e *Engine) { e.deadman = d } }

// WithEvents overrides the event bus.
func WithEvents(b EventBus) Option { return func(e *Engine) { e.events = b } }

// New constructs an Engine with the given options. Defaults applied for
// unset dependencies (in-memory store, no-op signer, no-op deadman, no-op
// event bus).
func New(opts ...Option) *Engine {
	e := &Engine{
		registry: handler.Default(),
		store:    newInMemoryStore(),
		signer:   noopSigner{},
		deadman:  noopDeadman{},
		events:   noopEventBus{},
		locks:    newHostLocks(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Run executes a transaction against the host reachable via transport
// and returns the resulting [api.TransactionResult]. The result's
// Status is always one of the four [api.TransactionStatus] values:
// Committed, RolledBack, PartiallyApplied, or Errored
// (engine-transaction spec C-01).
//
// The nonBlocking flag controls per-host mutex acquisition. When true,
// Run returns [api.ErrHostBusy] if another transaction is in flight
// against the same host (engine-transaction spec AC-08).
func (e *Engine) Run(ctx context.Context, transport api.Transport, txn *api.Transaction, nonBlocking bool) (*api.TransactionResult, error) {
	if txn == nil {
		return nil, errors.New("engine: nil transaction")
	}
	if txn.ID == uuid.Nil {
		txn.ID = uuid.New()
	}
	startedAt := time.Now().UTC()
	if txn.StartedAt.IsZero() {
		txn.StartedAt = startedAt
	}

	// Per-host serialization (engine-transaction spec AC-07, C-05).
	release, err := e.locks.acquire(txn.HostID, nonBlocking)
	if err != nil {
		return nil, err
	}
	defer release()

	e.publishStarted(ctx, txn)

	// Phase 1: PRE-FLIGHT.
	if err := e.preflight(txn); err != nil {
		return e.errored(ctx, txn, startedAt, api.PhaseCapture, err), nil
	}

	// Phase 2: CAPTURE. Persist the bundle BEFORE any apply step runs
	// (engine-transaction spec AC-04, C-02).
	preStates, capErr := e.capture(ctx, transport, txn)
	if capErr != nil {
		return e.errored(ctx, txn, startedAt, api.PhaseCapture, capErr), nil
	}
	if err := e.store.PersistPreStates(ctx, txn.ID, preStates); err != nil {
		return e.errored(ctx, txn, startedAt, api.PhaseCapture, err), nil
	}
	e.publishPhaseCompleted(ctx, txn, api.PhaseCapture, true, time.Since(startedAt))

	// Arm deadman timer for control-channel-sensitive transactions
	// (engine-transaction spec AC-06, C-04).
	armed := false
	if shouldArmDeadman(txn, e.registry) {
		if _, _, err := e.deadman.Arm(ctx, transport, txn.ID, rollbackPlanFromPreStates(preStates)); err != nil {
			return e.errored(ctx, txn, startedAt, api.PhaseCapture, err), nil
		}
		armed = true
	}

	// Phase 3: APPLY.
	applyResults, applyOK := e.apply(ctx, transport, txn, preStates)
	e.publishPhaseCompleted(ctx, txn, api.PhaseApply, applyOK, time.Since(startedAt))

	// Phase 4: VALIDATE (only if APPLY succeeded).
	var validators []api.ValidatorResult
	validateOK := applyOK
	if applyOK {
		validators, validateOK = e.validate(ctx, transport, txn)
		e.publishPhaseCompleted(ctx, txn, api.PhaseValidate, validateOK, time.Since(startedAt))
	}

	// Phase 5: COMMIT or ROLLBACK.
	if applyOK && validateOK {
		if armed {
			if err := e.deadman.Cancel(ctx, transport, txn.ID); err != nil {
				// Cancel failed — record but proceed; the deadman
				// will fire and rollback the change. We mark the
				// outcome RolledBack with deadman as the source.
				rb := e.rollback(ctx, transport, applyResults, preStates, "deadman")
				return e.finalize(ctx, txn, startedAt, api.StatusRolledBack, applyResults, preStates, validators, rb), nil
			}
		}
		return e.finalize(ctx, txn, startedAt, api.StatusCommitted, applyResults, preStates, validators, nil), nil
	}

	// Failure path: invoke rollback.
	rb := e.rollback(ctx, transport, applyResults, preStates, "inline")
	if armed {
		// Cancel the deadman regardless; in-band rollback already ran.
		_ = e.deadman.Cancel(ctx, transport, txn.ID)
	}

	status := api.StatusRolledBack
	if !txn.Transactional && hasStrandedNonCapturable(applyResults) {
		status = api.StatusPartiallyApplied
	}
	return e.finalize(ctx, txn, startedAt, status, applyResults, preStates, validators, rb), nil
}

// hasStrandedNonCapturable reports whether any successful apply step
// is non-capturable. Used to distinguish StatusRolledBack from
// StatusPartiallyApplied for transactional:false rules
// (engine-transaction spec AC-05).
func hasStrandedNonCapturable(steps []api.StepResult) bool {
	for _, s := range steps {
		if s.Success && !s.Capturable {
			return true
		}
	}
	return false
}
