package api

import (
	"context"

	"github.com/google/uuid"
)

// Kensa is the top-level entry point for programmatic consumers.
// OpenWatch imports this type; the kensa CLI wraps it; future AI-agent
// surfaces (exposed by OpenWatch, not directly by Kensa — see
// KENSA_OPENWATCH_RESPONSE_2026-04-14.md §4.1) mediate through it.
//
// The method set is organized around three identities per
// OPENWATCH_VISION.md:
//
//   - Execution   — Transact / Scan / Remediate / Rollback
//   - Control Plane — Plan / Execute
//   - Heartbeat  — Subscribe
//   - Eye        — TransactionLog / VerifyEnvelope
//   - Deadman    — CancelDeadman / DeadmanStatus
//
// Every method is v1-stable from commit 1. Deferred methods return
// ErrNotYetImplemented until their milestone lands per
// KENSA_GO_DAY1_PLAN.md §11.
type Kensa struct {
	// unexported internals populated by New()
	config Config
}

// Config is the configuration for New.
type Config struct {
	// StorePath is the filesystem path to the SQLite transaction log.
	// Defaults to ".kensa/results.db" when empty.
	StorePath string

	// SigningKeyPath is the path to the Ed25519 private key used for
	// evidence envelope signing. Defaults to a per-deployment path
	// managed by kensa-keygen.
	SigningKeyPath string
}

// HostConfig identifies a target host for execution.
type HostConfig struct {
	Hostname string
	User     string
	Port     int
	Sudo     bool
	FleetID  string // Optional fleet membership; used in event/log FleetID fields
	KeyPath  string // SSH key path; empty means use agent / ~/.ssh/config
}

// ScanResult is the output of Scan (read-only checks, no mutation).
type ScanResult struct {
	HostID       string
	Transactions []TransactionResult // One per scanned rule
}

// RemediationResult is the output of Remediate (check + fix failing).
type RemediationResult struct {
	HostID       string
	Transactions []TransactionResult
}

// New creates a Kensa instance with the given configuration.
func New(cfg Config) (*Kensa, error) {
	return &Kensa{config: cfg}, nil
}

// ─── Execution ─────────────────────────────────────────────────────────

// Transact runs a single transaction end-to-end.
func (k *Kensa) Transact(ctx context.Context, host HostConfig, txn *Transaction, opts ...RunOption) (*TransactionResult, error) {
	return nil, ErrNotYetImplemented
}

// Scan runs read-only checks against a host for the specified rules.
func (k *Kensa) Scan(ctx context.Context, host HostConfig, rules []*Rule, opts ...RunOption) (*ScanResult, error) {
	return nil, ErrNotYetImplemented
}

// Remediate runs transactions for every failing rule.
func (k *Kensa) Remediate(ctx context.Context, host HostConfig, rules []*Rule, opts ...RunOption) (*RemediationResult, error) {
	return nil, ErrNotYetImplemented
}

// Rollback executes rollback for a past transaction by ID, using
// pre-state from the transaction log.
func (k *Kensa) Rollback(ctx context.Context, host HostConfig, txnID uuid.UUID) (*RollbackResult, error) {
	return nil, ErrNotYetImplemented
}

// ─── Control Plane: preview-then-execute ───────────────────────────────

// Plan produces a full transaction plan without executing it.
func (k *Kensa) Plan(ctx context.Context, host HostConfig, rule *Rule) (*Plan, error) {
	return nil, ErrNotYetImplemented
}

// Execute runs a previously-produced Plan. Returns PlanStaleError if
// host state has diverged since planning.
func (k *Kensa) Execute(ctx context.Context, host HostConfig, plan *Plan, opts ...RunOption) (*TransactionResult, error) {
	return nil, ErrNotYetImplemented
}

// ─── Heartbeat: event subscription ─────────────────────────────────────

// Subscribe returns a channel of events matching filter.
func (k *Kensa) Subscribe(ctx context.Context, filter EventFilter) (<-chan Event, error) {
	return nil, ErrNotYetImplemented
}

// ─── Eye: historical query + envelope verification ─────────────────────

// TransactionLog returns a query interface over the persisted log.
func (k *Kensa) TransactionLog() LogQuery {
	return nil
}

// VerifyEnvelope checks an evidence envelope's signature.
func (k *Kensa) VerifyEnvelope(envelope *EvidenceEnvelope) (*VerifyResult, error) {
	return nil, ErrNotYetImplemented
}

// ─── Deadman control ───────────────────────────────────────────────────

// CancelDeadman executes an in-band clean rollback and cancels the
// scheduled deadman script for a transaction.
func (k *Kensa) CancelDeadman(ctx context.Context, host HostConfig, txnID uuid.UUID) (*RollbackResult, error) {
	return nil, ErrNotYetImplemented
}

// DeadmanStatus returns the armed state of a transaction's deadman timer.
func (k *Kensa) DeadmanStatus(ctx context.Context, host HostConfig, txnID uuid.UUID) (*DeadmanState, error) {
	return nil, ErrNotYetImplemented
}
