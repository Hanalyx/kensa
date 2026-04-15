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

// Config configures [New].
type Config struct {
	// StorePath is the filesystem path to the SQLite transaction
	// log. The default ".kensa/results.db" is used when StorePath is
	// empty.
	StorePath string

	// SigningKeyPath is the path to the Ed25519 private key used for
	// signing evidence envelopes. The default is a per-deployment
	// path managed by kensa-keygen.
	SigningKeyPath string
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
func (k *Kensa) Transact(ctx context.Context, host HostConfig, txn *Transaction, opts ...RunOption) (*TransactionResult, error) {
	return nil, ErrNotYetImplemented
}

// Scan runs the read-only check phase of every rule in rules against
// host and returns a [ScanResult]. No apply runs and no signed
// envelopes are produced.
func (k *Kensa) Scan(ctx context.Context, host HostConfig, rules []*Rule, opts ...RunOption) (*ScanResult, error) {
	return nil, ErrNotYetImplemented
}

// Remediate runs full transactions for every rule whose check fails
// during the scan phase and returns a [RemediationResult].
func (k *Kensa) Remediate(ctx context.Context, host HostConfig, rules []*Rule, opts ...RunOption) (*RemediationResult, error) {
	return nil, ErrNotYetImplemented
}

// Rollback executes rollback for the past transaction identified by
// txnID, using pre-state loaded from the transaction log. Returns
// the [RollbackResult] for the operation.
func (k *Kensa) Rollback(ctx context.Context, host HostConfig, txnID uuid.UUID) (*RollbackResult, error) {
	return nil, ErrNotYetImplemented
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
// transaction log. Returns nil until the implementation lands per
// docs/KENSA_GO_DAY1_PLAN.md §11.5.
func (k *Kensa) TransactionLog() LogQuery {
	return nil
}

// VerifyEnvelope checks the signature on envelope against the
// deployment's registered keys and returns the [VerifyResult]. See
// [EnvelopeVerifier.VerifyEnvelope] for the contract.
func (k *Kensa) VerifyEnvelope(envelope *EvidenceEnvelope) (*VerifyResult, error) {
	return nil, ErrNotYetImplemented
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
