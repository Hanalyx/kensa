package api

import (
	"context"

	"github.com/google/uuid"
)

// Kensa is the top-level entry point for programmatic consumers. The
// kensa CLI wraps it; OpenWatch imports it directly; future AI-agent
// surfaces (exposed by OpenWatch, not by this package — see
// docs/KENSA_OPENWATCH_RESPONSE_2026-04-14.md §4.1) mediate through it.
//
// The method set is organized around the OpenWatch identities defined
// in docs/OPENWATCH_VISION.md:
//
//   - Execution    — [Kensa.Transact] / [Kensa.Scan] / [Kensa.Remediate] / [Kensa.Rollback]
//   - Control Plane — [Kensa.Plan] / [Kensa.Execute]
//   - Heartbeat   — [Kensa.Subscribe]
//   - Eye         — [Kensa.TransactionLog] / [Kensa.VerifyEnvelope]
//   - Deadman    — [Kensa.CancelDeadman] / [Kensa.DeadmanStatus]
//
// Every method is v1-stable from commit 1. Methods whose
// implementations land in later milestones return
// [ErrNotYetImplemented] until then; signatures do not change.
type Kensa struct {
	// unexported internals populated by [New].
	config Config
}

// Config configures [New]. The bare config (zero-value) yields a
// stub Kensa whose execution methods all return [ErrNotYetImplemented];
// useful for OpenWatch's compile-against-the-API pattern. The kensa
// factory package (github.com/Hanalyx/kensa-go/pkg/kensa) provides a
// Default constructor that fills the [Config.Engine],
// [Config.TransportFactory], [Config.Log], and [Config.Verifier]
// fields with the standard internal implementations.
type Config struct {
	// StorePath is the filesystem path to the SQLite transaction
	// log. The default ".kensa/results.db" is used when StorePath is
	// empty.
	StorePath string

	// SigningKeyPath is the path to the Ed25519 private key used for
	// signing evidence envelopes. The default is a per-deployment
	// path managed by kensa-keygen.
	SigningKeyPath string

	// Engine, when set, backs [Kensa.Transact], [Kensa.Rollback],
	// and [Kensa.Execute]. If nil, those methods return
	// [ErrNotYetImplemented].
	Engine Engine

	// TransportFactory, when set, lets execution methods construct
	// an SSH transport from a [HostConfig]. If nil, execution
	// methods return [ErrNotYetImplemented].
	TransportFactory TransportFactory

	// Log, when set, backs [Kensa.TransactionLog]. If nil,
	// [Kensa.TransactionLog] returns nil.
	Log LogQuery

	// Verifier, when set, backs [Kensa.VerifyEnvelope]. If nil,
	// [Kensa.VerifyEnvelope] returns [ErrNotYetImplemented].
	Verifier EnvelopeVerifier
}

// Engine is the interface [Kensa] delegates execution methods to. The
// production implementation lives in internal/engine; tests may
// substitute a fake by implementing this interface directly.
//
// Engine is satisfied implicitly by *internal/engine.Engine because
// Go interface satisfaction is structural — api/ does not import the
// internal package.
type Engine interface {
	// Run executes txn against transport and returns the result. The
	// nonBlocking flag selects [ErrHostBusy]-vs-wait behavior on
	// per-host mutex contention.
	Run(ctx context.Context, transport Transport, txn *Transaction, nonBlocking bool) (*TransactionResult, error)
}

// TransportFactory constructs a [Transport] from a [HostConfig].
// [Kensa] uses this to translate the consumer-facing host description
// into a connected SSH session before invoking [Engine.Run].
type TransportFactory interface {
	Connect(ctx context.Context, host HostConfig) (Transport, error)
}

// HostConfig identifies a target host for execution methods.
type HostConfig struct {
	Hostname string
	User     string
	Port     int
	// Sudo, when true, wraps remote commands in `sudo -n sh -c`.
	Sudo bool
	// FleetID is the optional fleet membership; populated into
	// [Event.HostID] context and into the transaction log's
	// FleetID column.
	FleetID string
	// KeyPath is the SSH key path. Empty means use ssh-agent and
	// ~/.ssh/config.
	KeyPath string
}

// ScanResult is the outcome of [Kensa.Scan]. Each entry in
// [ScanResult.Transactions] is a check-only [TransactionResult] —
// no apply, no rollback, no signed envelope.
type ScanResult struct {
	HostID       string
	Transactions []TransactionResult
}

// RemediationResult is the outcome of [Kensa.Remediate]. Each entry
// in [RemediationResult.Transactions] is a full transaction for a
// rule whose check failed during the scan phase.
type RemediationResult struct {
	HostID       string
	Transactions []TransactionResult
}

// New returns a [Kensa] configured by cfg.
func New(cfg Config) (*Kensa, error) {
	return &Kensa{config: cfg}, nil
}

// ─── Execution ─────────────────────────────────────────────────────────

// Transact runs txn against host end-to-end and returns the resulting
// [TransactionResult]. The result's [TransactionResult.Status] is
// always one of the four [TransactionStatus] values.
//
// Returns [ErrNotYetImplemented] when the engine is not wired (zero-
// value [Config]). Use the Default constructor in pkg/kensa to wire up
// the standard engine + SSH transport.
func (k *Kensa) Transact(ctx context.Context, host HostConfig, txn *Transaction, opts ...RunOption) (*TransactionResult, error) {
	if k.config.Engine == nil || k.config.TransportFactory == nil {
		return nil, ErrNotYetImplemented
	}
	transport, err := k.config.TransportFactory.Connect(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = transport.Close() }()

	nonBlocking := optsToNonBlocking(opts)
	if txn != nil && txn.HostID == "" {
		txn.HostID = host.Hostname
	}
	if txn != nil && txn.FleetID == "" {
		txn.FleetID = host.FleetID
	}
	return k.config.Engine.Run(ctx, transport, txn, nonBlocking)
}

// Scan runs the read-only check phase of every rule in rules against
// host and returns a [ScanResult]. No apply runs and no signed
// envelopes are produced.
//
// Always returns [ErrNotYetImplemented] in v0.x: the rule parser plus
// check-method dispatcher land Week 21 per docs/KENSA_GO_DAY1_PLAN.md
// §11.5.
func (k *Kensa) Scan(ctx context.Context, host HostConfig, rules []*Rule, opts ...RunOption) (*ScanResult, error) {
	return nil, ErrNotYetImplemented
}

// Remediate runs full transactions for every rule whose check fails
// during the scan phase and returns a [RemediationResult].
//
// Always returns [ErrNotYetImplemented] until the rule parser lands
// Week 21.
func (k *Kensa) Remediate(ctx context.Context, host HostConfig, rules []*Rule, opts ...RunOption) (*RemediationResult, error) {
	return nil, ErrNotYetImplemented
}

// Rollback executes rollback for the past transaction identified by
// txnID, using pre-state loaded from the transaction log. Returns
// the [RollbackResult] for the operation.
//
// Returns [ErrNotYetImplemented] when [Config.Log] is nil. Wiring
// requires both a log to load pre-state from and an engine to invoke
// the rollback handlers; the Default constructor in pkg/kensa does
// this.
func (k *Kensa) Rollback(ctx context.Context, host HostConfig, txnID uuid.UUID) (*RollbackResult, error) {
	return nil, ErrNotYetImplemented
}

// optsToNonBlocking inspects opts for [WithNonBlocking].
func optsToNonBlocking(opts []RunOption) bool {
	o := &runOptions{}
	for _, opt := range opts {
		opt(o)
	}
	return o.nonBlocking
}

// ─── Control Plane: preview-then-execute ───────────────────────────────

// Plan produces a full [Plan] for rule against host without mutating
// the host. The plan includes captured pre-state, apply steps,
// validators, and the rollback plan.
func (k *Kensa) Plan(ctx context.Context, host HostConfig, rule *Rule) (*Plan, error) {
	return nil, ErrNotYetImplemented
}

// Execute runs a previously-produced plan against host. Returns
// [PlanStaleError] if host state has diverged since planning; the
// caller must re-plan and seek fresh approval before retrying.
func (k *Kensa) Execute(ctx context.Context, host HostConfig, plan *Plan, opts ...RunOption) (*TransactionResult, error) {
	return nil, ErrNotYetImplemented
}

// ─── Heartbeat: event subscription ─────────────────────────────────────

// Subscribe returns a channel of events matching filter. The channel
// closes when ctx is done. See [EventSubscriber] for back-pressure
// semantics.
func (k *Kensa) Subscribe(ctx context.Context, filter EventFilter) (<-chan Event, error) {
	return nil, ErrNotYetImplemented
}

// ─── Eye: historical query and envelope verification ───────────────────

// TransactionLog returns the [LogQuery] interface over the persisted
// transaction log. Returns nil when [Config.Log] is unset; the
// Default constructor in pkg/kensa wires up a SQLite-backed
// implementation.
func (k *Kensa) TransactionLog() LogQuery {
	return k.config.Log
}

// VerifyEnvelope checks the signature on envelope against the
// deployment's registered keys and returns the [VerifyResult]. See
// [EnvelopeVerifier.VerifyEnvelope] for the contract.
//
// Returns [ErrNotYetImplemented] when [Config.Verifier] is unset.
func (k *Kensa) VerifyEnvelope(envelope *EvidenceEnvelope) (*VerifyResult, error) {
	if k.config.Verifier == nil {
		return nil, ErrNotYetImplemented
	}
	return k.config.Verifier.VerifyEnvelope(envelope)
}

// ─── Deadman control ───────────────────────────────────────────────────

// CancelDeadman performs an in-band rollback of the transaction
// identified by txnID and cancels the scheduled deadman script on
// host. See [DeadmanControl.CancelDeadman] for the full contract.
func (k *Kensa) CancelDeadman(ctx context.Context, host HostConfig, txnID uuid.UUID) (*RollbackResult, error) {
	return nil, ErrNotYetImplemented
}

// DeadmanStatus returns the armed-timer state for the transaction
// identified by txnID on host, or [ErrNoActiveDeadman] if no timer
// is armed.
func (k *Kensa) DeadmanStatus(ctx context.Context, host HostConfig, txnID uuid.UUID) (*DeadmanState, error) {
	return nil, ErrNotYetImplemented
}
