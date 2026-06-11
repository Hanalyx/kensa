package api

import (
	"context"
	"fmt"

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
// factory package (github.com/Hanalyx/kensa/pkg/kensa) provides a
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

	// Scanner, when set, backs [Kensa.Scan] and [Kensa.Remediate].
	// If nil, those methods return [ErrNotYetImplemented].
	Scanner ScannerBackend
}

// ScannerBackend is the interface backing [Kensa.Scan] and
// [Kensa.Remediate]. The production implementation lives in
// internal/scan; tests may substitute a fake.
type ScannerBackend interface {
	// Scan checks every rule against the host reachable via transport.
	Scan(ctx context.Context, transport Transport, rules []*Rule) (*ScanResult, error)
	// Remediate checks every rule and runs transactions for failing ones.
	Remediate(ctx context.Context, transport Transport, rules []*Rule) (*RemediationResult, error)
}

// ScannerWithOverrides is the optional capability-override surface
// for a [ScannerBackend]. Implementations that support this
// interface honor [HostConfig.Capabilities] passed via [Kensa.Scan]
// / [Kensa.Remediate]: detected capabilities are merged with
// `overrides` (operator-supplied keys override probed values)
// before rule selection.
//
// Added in C-028 of the CLI migration. Provided as an
// optional extension rather than amending [ScannerBackend] so
// existing in-tree and out-of-tree backends continue to satisfy
// the original contract; type-assert to this surface to opt in.
type ScannerWithOverrides interface {
	ScanWithOverrides(ctx context.Context, transport Transport, rules []*Rule, overrides CapabilitySet) (*ScanResult, error)
	RemediateWithOverrides(ctx context.Context, transport Transport, rules []*Rule, overrides CapabilitySet) (*RemediationResult, error)
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

	// RollbackTransaction performs a manual rollback of a past
	// transaction from its persisted [TransactionRecord]. Satisfies
	// the rollback path for [Kensa.Rollback].
	RollbackTransaction(ctx context.Context, transport Transport, record *TransactionRecord) (*RollbackResult, error)

	// PlanTransaction performs capability-selection and the read-only
	// capture phase for rule and returns a [Plan] without mutating the
	// host. Satisfies [Planner].
	PlanTransaction(ctx context.Context, transport Transport, rule *Rule) (*Plan, error)

	// ExecutePlan runs a previously-produced [Plan] against transport.
	// Returns [PlanStaleError] when host state has diverged since
	// planning. Satisfies [Executor].
	ExecutePlan(ctx context.Context, transport Transport, plan *Plan) (*TransactionResult, error)
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
	// Password is the SSH password for password-auth hosts. Wired
	// in C-026 of the CLI migration. Empty defers to
	// key-based auth (KeyPath, ssh-agent, ~/.ssh/config). When
	// non-empty, the SSH transport requires `sshpass` on the host
	// running kensa.
	Password string
	// StrictHostKeys controls SSH host-key verification policy.
	// When true, the transport sets StrictHostKeyChecking=yes:
	// unknown host keys cause connect failure rather than silent
	// trust-on-first-use. When false (default), the transport sets
	// StrictHostKeyChecking=accept-new, matching Python kensa's
	// default. Wired in C-027 of the CLI migration.
	StrictHostKeys bool
	// Capabilities is an optional capability override map. Keys
	// present here override the values produced by the host's
	// capability probes — they're applied AFTER detection and
	// before rule selection. Wired in C-028 of the CLI
	// migration. Empty means "no overrides; use detected
	// capabilities verbatim". Used by Scan and Remediate; Plan
	// does not currently capability-gate selection.
	Capabilities CapabilitySet
}

// ScanResult is the outcome of [Kensa.Scan].
//
// [ScanResult.Outcomes] is the canonical compliance result: one [RuleOutcome]
// per scanned rule, in input order, each with a [ComplianceStatus] of
// pass/fail/skipped/error. Consumers mapping into a compliance model should
// read Outcomes.
//
// [ScanResult.Transactions] is retained for backward compatibility. Each entry
// is a check-only [TransactionResult] — no apply, no rollback, no signed
// envelope — in which the [TransactionStatus] is reused to carry the verdict:
// StatusCommitted means compliant and StatusRolledBack means non-compliant.
// That reuse predates Outcomes and overloads a vocabulary whose doc comments
// describe apply-path semantics (StatusRolledBack documents a reversal that
// never happens in a scan); prefer Outcomes for an unambiguous verdict.
type ScanResult struct {
	HostID       string
	Transactions []TransactionResult
	Outcomes     []RuleOutcome
}

// RemediationResult is the outcome of [Kensa.Remediate]. Each entry
// in [RemediationResult.Transactions] is a full transaction for a
// rule whose check failed during the scan phase.
//
// Unlike [ScanResult], this type does NOT yet expose a [RuleOutcome] surface,
// and its already-compliant entries reuse StatusCommitted with a synthetic
// "check" step — the same transaction-status overload that [ScanResult.Outcomes]
// was introduced to replace. Giving Remediate a compliance-verdict surface is
// tracked as a follow-up; for now read [TransactionResult.Status] with that
// caveat in mind.
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
// Returns [ErrNotYetImplemented] when [Config.Scanner] is nil. Use
// the Default constructor in pkg/kensa to wire up the standard scanner.
func (k *Kensa) Scan(ctx context.Context, host HostConfig, rules []*Rule, opts ...RunOption) (*ScanResult, error) {
	if k.config.Scanner == nil || k.config.TransportFactory == nil {
		return nil, ErrNotYetImplemented
	}
	transport, err := k.config.TransportFactory.Connect(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = transport.Close() }()

	result, err := scanWithOptionalOverrides(ctx, k.config.Scanner, transport, rules, host.Capabilities)
	if err != nil {
		return nil, err
	}
	result.HostID = host.Hostname
	return result, nil
}

// scanWithOptionalOverrides dispatches to the override-capable
// scanner method when host.Capabilities is non-empty AND the
// configured Scanner implements [ScannerWithOverrides]; otherwise
// falls back to the legacy Scan method. When overrides are
// requested but the Scanner does not support them, returns an
// error so the operator sees the configuration mismatch instead
// of silently scanning with detected-only caps.
func scanWithOptionalOverrides(ctx context.Context, scanner ScannerBackend, transport Transport, rules []*Rule, overrides CapabilitySet) (*ScanResult, error) {
	if len(overrides) == 0 {
		return scanner.Scan(ctx, transport, rules)
	}
	sw, ok := scanner.(ScannerWithOverrides)
	if !ok {
		return nil, fmt.Errorf("scan: capability overrides requested but configured Scanner does not implement ScannerWithOverrides")
	}
	return sw.ScanWithOverrides(ctx, transport, rules, overrides)
}

// Remediate runs full transactions for every rule whose check fails
// during the scan phase and returns a [RemediationResult].
//
// Returns [ErrNotYetImplemented] when [Config.Scanner] is nil.
func (k *Kensa) Remediate(ctx context.Context, host HostConfig, rules []*Rule, opts ...RunOption) (*RemediationResult, error) {
	if k.config.Scanner == nil || k.config.TransportFactory == nil {
		return nil, ErrNotYetImplemented
	}
	transport, err := k.config.TransportFactory.Connect(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = transport.Close() }()

	result, err := remediateWithOptionalOverrides(ctx, k.config.Scanner, transport, rules, host.Capabilities)
	if err != nil {
		return nil, err
	}
	result.HostID = host.Hostname
	return result, nil
}

// remediateWithOptionalOverrides mirrors [scanWithOptionalOverrides]
// for the Remediate path.
func remediateWithOptionalOverrides(ctx context.Context, scanner ScannerBackend, transport Transport, rules []*Rule, overrides CapabilitySet) (*RemediationResult, error) {
	if len(overrides) == 0 {
		return scanner.Remediate(ctx, transport, rules)
	}
	sw, ok := scanner.(ScannerWithOverrides)
	if !ok {
		return nil, fmt.Errorf("remediate: capability overrides requested but configured Scanner does not implement ScannerWithOverrides")
	}
	return sw.RemediateWithOverrides(ctx, transport, rules, overrides)
}

// Rollback executes rollback for the past transaction identified by
// txnID, using pre-state loaded from the transaction log. Returns
// the [RollbackResult] for the operation.
//
// Returns [ErrNotYetImplemented] when [Config.Log] is nil or
// [Config.Engine] is nil.
func (k *Kensa) Rollback(ctx context.Context, host HostConfig, txnID uuid.UUID) (*RollbackResult, error) {
	if k.config.Engine == nil || k.config.Log == nil || k.config.TransportFactory == nil {
		return nil, ErrNotYetImplemented
	}

	record, err := k.config.Log.Get(ctx, txnID)
	if err != nil {
		return nil, err
	}

	transport, err := k.config.TransportFactory.Connect(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = transport.Close() }()

	return k.config.Engine.RollbackTransaction(ctx, transport, record)
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
//
// Returns [ErrNotYetImplemented] when [Config.Engine] or
// [Config.TransportFactory] is nil.
func (k *Kensa) Plan(ctx context.Context, host HostConfig, rule *Rule) (*Plan, error) {
	if k.config.Engine == nil || k.config.TransportFactory == nil {
		return nil, ErrNotYetImplemented
	}
	transport, err := k.config.TransportFactory.Connect(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = transport.Close() }()
	return k.config.Engine.PlanTransaction(ctx, transport, rule)
}

// Execute runs a previously-produced plan against host. Returns
// [PlanStaleError] if host state has diverged since planning; the
// caller must re-plan and seek fresh approval before retrying.
//
// Returns [ErrNotYetImplemented] when [Config.Engine] or
// [Config.TransportFactory] is nil.
func (k *Kensa) Execute(ctx context.Context, host HostConfig, plan *Plan, opts ...RunOption) (*TransactionResult, error) {
	if k.config.Engine == nil || k.config.TransportFactory == nil {
		return nil, ErrNotYetImplemented
	}
	transport, err := k.config.TransportFactory.Connect(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = transport.Close() }()
	// nonBlocking is accepted for API consistency but ExecutePlan does
	// not currently expose the flag (the staleness check provides its
	// own fast-fail path).
	_ = optsToNonBlocking(opts)
	return k.config.Engine.ExecutePlan(ctx, transport, plan)
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
