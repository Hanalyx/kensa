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
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
	"github.com/Hanalyx/kensa/internal/handler"
)

// Engine is the transaction coordinator. Construct one with [New], then
// call [Engine.Run] for each transaction.
type Engine struct {
	registry          *handler.Registry
	store             Store
	signer            Signer
	deadman           DeadmanArmer
	events            EventBus
	locks             *hostLocks
	validators        []Validator
	forceValidateFail bool

	// emitter writes a transaction-phase record into the host's auditd
	// at each phase boundary (the AUDIT_NETLINK observability surface). It is
	// strictly best-effort and non-blocking — an audit-log failure can
	// NEVER fail or delay a transaction. Defaults to a no-op; the
	// production path wires auditnl.NewEmitter via WithAuditEmitter.
	emitter PhaseEmitter

	// agentClient is set via WithAgentClient. When non-nil,
	// every handler lookup returns a RemoteHandler wrapping
	// this client (the original handler's Capturable() value
	// is preserved). The local handler code does not run on
	// the controller — the agent process does. L-014
	// deliverable.
	agentClient AgentClient
}

// AgentClient is the controller-side wire-protocol client.
// Engine takes the interface (rather than importing
// internal/agent/client directly) to keep engine free of
// cycles with the agent stack. The implementation in
// internal/agent/client.*Client satisfies this interface.
type AgentClient interface {
	Apply(ctx context.Context, mechanism string, params api.Params, preState *api.PreState) (*api.StepResult, error)
	Capture(ctx context.Context, mechanism string, params api.Params) (*api.PreState, error)
	Rollback(ctx context.Context, preState api.PreState) (*api.RollbackResult, error)
	ArmDeadman(ctx context.Context, txnID string, windowSeconds int64, rollbackCommands []string) (int64, error)
	CancelDeadman(ctx context.Context, txnID string) (wasActive bool, err error)
}

// DeadmanAgentClient is the narrow subset of AgentClient the
// deadman armer needs for agent-mode dispatch. Defined here
// (rather than as a deadman-local interface) so the named
// type is identical on both sides of the
// AgentAwareDeadmanArmer.UseAgentClient signature — Go's
// interface satisfaction is by named-type identity, not
// structural compatibility. Without this shared type, an
// armer defining its own local interface would NOT satisfy
// AgentAwareDeadmanArmer and engine.New's type assertion
// would silently fail.
type DeadmanAgentClient interface {
	ArmDeadman(ctx context.Context, txnID string, windowSeconds int64, rollbackCommands []string) (int64, error)
	CancelDeadman(ctx context.Context, txnID string) (wasActive bool, err error)
}

// AgentAwareDeadmanArmer is the optional capability
// interface a DeadmanArmer can satisfy to receive the
// engine's AgentClient. D-005 deliverable: when WithAgentClient
// is set and the configured DeadmanArmer implements this
// interface, engine.New calls UseAgentClient to wire the
// armer for the agent-mode dispatch path.
//
// The pattern mirrors fsatomic.Transport: optional capability
// surfaced via type assertion, no hard interface dependency.
//
// **CRITICAL.** The parameter type MUST be DeadmanAgentClient
// (defined above), not the wider AgentClient. The deadman
// package's Armer.UseAgentClient implementation references
// this same DeadmanAgentClient type so Go's interface
// satisfaction holds at the type assertion in engine.New.
type AgentAwareDeadmanArmer interface {
	DeadmanArmer
	UseAgentClient(c DeadmanAgentClient)
}

// PhaseEmitter receives a transaction-phase record at each phase
// boundary. Implementations MUST be non-blocking and MUST NOT error —
// the engine ignores any failure, and audit emission can never affect a
// transaction's outcome. The interface lives here (not in auditnl) so the
// engine core does not import the netlink stack; auditnl.Emitter
// satisfies it structurally and is injected via WithAuditEmitter.
type PhaseEmitter interface {
	// EmitPhase records that transaction txnID reached phase with the
	// given success state.
	EmitPhase(txnID, phase string, ok bool)
}

// noopPhaseEmitter is the default — emission is off unless a real emitter
// is wired in.
type noopPhaseEmitter struct{}

func (noopPhaseEmitter) EmitPhase(_, _ string, _ bool) {}

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

// WithAuditEmitter wires a transaction-phase auditd emitter.
// The production path passes auditnl.NewEmitter(); tests pass a recorder.
// Emission is best-effort and never affects a transaction.
func WithAuditEmitter(em PhaseEmitter) Option {
	return func(e *Engine) {
		if em != nil {
			e.emitter = em
		}
	}
}

// WithForceValidateFail forces the validate phase to return false for
// every transaction. Used by kensa-fuzz to test the
// apply→validate-fail→rollback path without requiring a real rule check
// implementation to be wired.
func WithForceValidateFail() Option {
	return func(e *Engine) { e.forceValidateFail = true }
}

// WithAgentClient enables agent-mode dispatch. When set,
// every handler invocation routes through a RemoteHandler
// wrapping this client; the local handler code does NOT run
// on the controller. L-014 deliverable.
//
// The client's lifecycle is the caller's responsibility:
// cmd/kensa/remediate.go typically constructs the client
// from a bootstrap+ssh+stdio pipeline, calls
// client.Handshake, then passes via this option.
func WithAgentClient(c AgentClient) Option {
	return func(e *Engine) { e.agentClient = c }
}

// New constructs an Engine with the given options. Defaults applied
// for unset dependencies:
//   - in-memory store
//   - REAL Ed25519 signer (ephemeral per-call keypair via
//     evidence.Generate(); no-op signer was deleted in C-060)
//   - no-op deadman
//   - no-op event bus
//
// The real-signer default means every engine.New() call produces
// envelopes with valid signatures, even in tests. Tests that need
// to verify against a specific keypair pass engine.WithSigner.
//
// An evidence.Generate() failure (extremely unlikely — only fires
// on crypto/rand exhaustion) panics: a kensa engine with no
// working signer cannot produce trustworthy envelopes, and the
// failure is loud rather than silent.
func New(opts ...Option) *Engine {
	signer, err := evidence.Generate()
	if err != nil {
		panic(fmt.Sprintf("engine: ed25519 keygen failed (crypto/rand exhausted?): %v", err))
	}
	e := &Engine{
		registry: handler.Default(),
		store:    newInMemoryStore(),
		signer:   signer,
		deadman:  noopDeadman{},
		events:   noopEventBus{},
		locks:    newHostLocks(),
		emitter:  noopPhaseEmitter{},
	}
	for _, opt := range opts {
		opt(e)
	}
	// D-005 capability wiring: if the configured deadman
	// armer accepts an AgentClient AND we have one, hand it
	// over so the armer can dispatch via RPC instead of the
	// shell-based path.
	if e.agentClient != nil {
		if ada, ok := e.deadman.(AgentAwareDeadmanArmer); ok {
			ada.UseAgentClient(e.agentClient)
		}
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
	e.emitter.EmitPhase(txn.ID.String(), "started", true)

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
	e.emitter.EmitPhase(txn.ID.String(), "capture", true)

	// Arm deadman timer for control-channel-sensitive transactions
	// (engine-transaction spec AC-06, C-04).
	armed := false
	if shouldArmDeadman(txn, e.registry) {
		if _, _, err := e.deadman.Arm(ctx, transport, txn.ID, preStates); err != nil {
			return e.errored(ctx, txn, startedAt, api.PhaseCapture, err), nil
		}
		armed = true
	}

	// Phase 3: APPLY.
	applyResults, applyOK := e.apply(ctx, transport, txn, preStates)
	e.publishPhaseCompleted(ctx, txn, api.PhaseApply, applyOK, time.Since(startedAt))
	e.emitter.EmitPhase(txn.ID.String(), "apply", applyOK)

	// Phase 4: VALIDATE (only if APPLY succeeded).
	var validators []api.ValidatorResult
	validateOK := applyOK
	if applyOK {
		validators, validateOK = e.validate(ctx, transport, txn)
		e.publishPhaseCompleted(ctx, txn, api.PhaseValidate, validateOK, time.Since(startedAt))
		e.emitter.EmitPhase(txn.ID.String(), "validate", validateOK)
	}

	// Phase 5: COMMIT or ROLLBACK.
	if applyOK && validateOK {
		if armed {
			if err := e.deadman.Cancel(ctx, transport, txn.ID); err != nil {
				// Cancel failed — record but proceed; the deadman
				// will fire and rollback the change. We mark the
				// outcome RolledBack with deadman as the source.
				rb := e.rollback(ctx, transport, applyResults, preStates, "deadman")
				return e.finalize(ctx, txn, startedAt, rollbackStatus(rb, txn, applyResults), applyResults, preStates, validators, rb), nil
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

	status := rollbackStatus(rb, txn, applyResults)
	return e.finalize(ctx, txn, startedAt, status, applyResults, preStates, validators, rb), nil
}

// rollbackStatus computes the terminal status after a rollback ran, as a
// verdict over the per-step RollbackResults rather than a constant. The
// rollback is clean only when every reversed step restored without error
// and without a partial restore; otherwise the host is in an unconfirmed
// state and the status is RollbackFailed (engine-transaction C-11). A clean
// rollback that left stranded non-capturable steps (transactional:false) is
// PartiallyApplied; an otherwise-clean rollback is RolledBack.
func rollbackStatus(rb []api.RollbackResult, txn *api.Transaction, applyResults []api.StepResult) api.TransactionStatus {
	if !rollbackClean(rb) {
		return api.StatusRollbackFailed
	}
	if !txn.Transactional && hasStrandedNonCapturable(applyResults) {
		return api.StatusPartiallyApplied
	}
	return api.StatusRolledBack
}

// rollbackClean reports whether every reversed step restored cleanly —
// succeeded and reported no partial restore. An empty set is clean: there
// was nothing to reverse (e.g. the first step failed to apply).
func rollbackClean(results []api.RollbackResult) bool {
	for _, r := range results {
		if !r.Success || r.PartialRestore {
			return false
		}
	}
	return true
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

// lookupHandler is the engine-internal indirection that
// intercepts handler lookups when agent-mode is active
// (WithAgentClient was passed). When agentClient is nil,
// delegates to registry.Get. When non-nil, returns an
// agentBackedHandler wrapping the client + the local
// handler's Capturable() value.
//
// The local handler is consulted ONLY for its Capturable()
// metadata — its Apply/Capture/Rollback code never runs on
// the controller in agent mode. If the mechanism is not
// registered locally, agent-mode dispatch falls back to a
// "true" Capturable assumption, since the agent might have
// the handler even if the controller's registry doesn't.
func (e *Engine) lookupHandler(mechanism string) (api.Handler, bool) {
	if e.agentClient == nil {
		return e.registry.Get(mechanism)
	}
	// Try the controller's registry for the Capturable bit;
	// missing-locally means the agent registers something
	// we don't, so assume capturable=true as the safer
	// default (engine treats it as a transactional step,
	// agent's dispatcher will surface a "not_capturable"
	// envelope Error if that's wrong).
	capturable := true
	if local, ok := e.registry.Get(mechanism); ok {
		capturable = local.Capturable()
	}
	return &agentBackedHandler{
		client:     e.agentClient,
		mechanism:  mechanism,
		capturable: capturable,
	}, true
}

// mustLookupHandler is the panicking variant for code paths
// where the engine has already verified the handler exists
// (e.g., post-preflight Apply / Capture / Rollback). Mirrors
// the registry.MustGet idiom.
func (e *Engine) mustLookupHandler(mechanism string) api.Handler {
	h, ok := e.lookupHandler(mechanism)
	if !ok {
		panic(fmt.Sprintf("engine: handler %q not found (pre-flight should have caught this)", mechanism))
	}
	return h
}

// agentBackedHandler is the engine-internal RemoteHandler
// shim. Implements api.Handler / CaptureHandler /
// RollbackHandler by forwarding to the engine's
// AgentClient. The L-014 peer review identified an earlier
// duplicate in internal/agent/remotehandler/ (with no
// callers outside its own test) and recommended dedup;
// that package was deleted and this engine-internal
// implementation is the only one.
type agentBackedHandler struct {
	client     AgentClient
	mechanism  string
	capturable bool
}

func (h *agentBackedHandler) Name() string     { return h.mechanism }
func (h *agentBackedHandler) Capturable() bool { return h.capturable }

func (h *agentBackedHandler) Apply(ctx context.Context, _ api.Transport, params api.Params, pre *api.PreState) (*api.StepResult, error) {
	return h.client.Apply(ctx, h.mechanism, params, pre)
}

func (h *agentBackedHandler) Capture(ctx context.Context, _ api.Transport, params api.Params) (*api.PreState, error) {
	return h.client.Capture(ctx, h.mechanism, params)
}

func (h *agentBackedHandler) Rollback(ctx context.Context, _ api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil {
		return nil, errors.New("engine: agent-mode rollback called with nil PreState")
	}
	return h.client.Rollback(ctx, *pre)
}
