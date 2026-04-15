package api

import (
	"time"

	"github.com/google/uuid"
)

// TransactionStatus is the terminal state of a [Transaction]. The engine
// guarantees that every transaction ends in exactly one of the four
// values below; no other state is permitted.
type TransactionStatus string

// Terminal statuses for a [Transaction].
const (
	// StatusCommitted indicates every apply step succeeded and every
	// validator passed. The host is in the target state and the
	// evidence envelope is signed and persisted.
	StatusCommitted TransactionStatus = "committed"

	// StatusRolledBack indicates apply or validate failed and every
	// applied capturable step was reversed using captured pre-state.
	// The host is in the exact pre-change state.
	StatusRolledBack TransactionStatus = "rolled_back"

	// StatusPartiallyApplied indicates that for a transactional:false
	// rule, at least one non-capturable step ran before a failure.
	// Those steps are not reversed; per-step Stranded flags in
	// [TransactionResult.Steps] identify which ones.
	StatusPartiallyApplied TransactionStatus = "partially_applied"

	// StatusErrored indicates the engine could not complete a phase
	// within the transaction deadline. The error in
	// [TransactionResult.Error] identifies which phase failed.
	StatusErrored TransactionStatus = "errored"
)

// Phase identifies one of the four transaction phases from the V1
// transaction model. Used by [LogFilter.Phases] and the [PhaseCompleted]
// event payload.
type Phase string

// The four transaction phases, in execution order.
const (
	// PhaseCapture records pre-state for every capturable step. Always
	// runs before any mutation. Failure aborts the transaction.
	PhaseCapture Phase = "capture"
	// PhaseApply executes remediation steps in order. Halts on first
	// failure.
	PhaseApply Phase = "apply"
	// PhaseValidate runs the rule's check plus any declared validators
	// (service health, config syntax, control-channel reachability).
	PhaseValidate Phase = "validate"
	// PhaseCommit finalizes a successful transaction: cancels the
	// deadman timer if armed, writes the signed evidence envelope.
	PhaseCommit Phase = "commit"
	// PhaseRollback restores pre-state for every applied capturable
	// step in reverse order.
	PhaseRollback Phase = "rollback"
)

// Transaction represents a single rule's mutation against a single host.
// It is the unit of atomicity: the engine guarantees that every
// transaction terminates in exactly one [TransactionStatus].
type Transaction struct {
	// ID is the unique transaction identifier, assigned at creation.
	ID uuid.UUID
	// RuleID is the canonical rule the transaction implements.
	RuleID string
	// HostID identifies the target host.
	HostID string
	// FleetID is the optional fleet membership; populated when the host
	// belongs to a managed fleet.
	FleetID string
	// Steps are the mechanism invocations that compose the rule's
	// remediation, in execution order.
	Steps []Step
	// StartedAt is when the engine entered the capture phase.
	StartedAt time.Time
	// Deadline is the maximum wall time before the engine aborts and
	// records [StatusErrored].
	Deadline time.Time
	// Transactional declares whether this transaction can offer the
	// atomicity guarantee. The value comes from the rule YAML's
	// `transactional` field per docs/CANONICAL_RULE_SCHEMA_V1.md §3.2.
	// Pre-flight rejects a transaction where Transactional is true but
	// any [Step] uses a non-capturable mechanism.
	Transactional bool
}

// Step is one mechanism invocation within a [Transaction].
type Step struct {
	// Index is the zero-based position in [Transaction.Steps].
	Index int
	// Mechanism must match a registered [Handler.Name].
	Mechanism string
	// Params are decoded by the handler at apply time.
	Params Params
}

// TransactionResult is the outcome of executing a [Transaction]. The
// [TransactionResult.Status] field is always one of the four
// [TransactionStatus] values.
type TransactionResult struct {
	// TransactionID matches the source [Transaction.ID].
	TransactionID uuid.UUID
	// Status is the terminal state.
	Status TransactionStatus
	// Steps records the per-step outcomes in execution order.
	Steps []StepResult
	// PreStates is the captured pre-state bundle, persisted before
	// any apply ran.
	PreStates []PreState
	// StartedAt is when the engine entered the capture phase.
	StartedAt time.Time
	// FinishedAt is when the engine reached a terminal status.
	FinishedAt time.Time
	// CommittedAt is non-nil if and only if Status is
	// [StatusCommitted].
	CommittedAt *time.Time
	// RolledBackAt is non-nil if and only if Status is
	// [StatusRolledBack].
	RolledBackAt *time.Time
	// Envelope is the signed evidence record for this transaction.
	Envelope *EvidenceEnvelope
	// Error is non-nil only when Status is [StatusErrored]. For
	// committed and rolled-back transactions the engine considers
	// the outcome a success and returns nil.
	Error error
}

// StepResult records the outcome of one mechanism invocation.
type StepResult struct {
	// StepIndex matches [Step.Index].
	StepIndex int
	// Mechanism matches [Step.Mechanism].
	Mechanism string
	// Capturable mirrors [Handler.Capturable] for this step's mechanism.
	Capturable bool
	// Success is true if the step's apply returned without error.
	Success bool
	// Detail is human-readable per-step output suitable for logs and UI.
	Detail string
	// Stranded is true for non-capturable steps that succeeded before
	// a later failure left the rule [StatusPartiallyApplied]. Such
	// steps are not reversed by rollback.
	Stranded bool
}

// PreState is the captured pre-change state for one step. The shape of
// [PreState.Data] is mechanism-specific — each capturable handler
// defines its own serialized data layout.
type PreState struct {
	// StepIndex matches the source [Step.Index].
	StepIndex int
	// Mechanism matches [Step.Mechanism].
	Mechanism string
	// Capturable is false for steps whose mechanism cannot capture
	// pre-state (these appear in [TransactionResult.PreStates] as
	// markers, not as restorable state).
	Capturable bool
	// Data is the mechanism-specific serialized pre-state. Empty for
	// non-capturable steps.
	Data map[string]interface{}
	// CapturedAt is when the capture handler ran.
	CapturedAt time.Time
}

// RollbackResult records the outcome of reversing one applied step.
type RollbackResult struct {
	// StepIndex matches the source [Step.Index].
	StepIndex int
	// Mechanism matches [Step.Mechanism].
	Mechanism string
	// Success is true if the rollback completed without error.
	Success bool
	// Detail is human-readable per-step output suitable for logs.
	Detail string
	// PartialRestore is true when the primary state was restored but
	// a downstream side effect (for example, a service reload that
	// failed) requires operator attention.
	PartialRestore bool
	// Source identifies which path executed the rollback:
	// "inline" (engine ran it during commit-or-rollback),
	// "deadman" (the scheduled out-of-band script fired), or
	// "manual" (kensa rollback --start).
	Source string
	// ExecutedAt is when the rollback ran on the host.
	ExecutedAt time.Time
}

// EvidenceEnvelope is the signed record of a transaction. Auditors,
// OpenWatch's audit UI, and third-party verification tools consume it
// as proof of what happened on a host.
//
// The canonical schema, canonicalization rules, and Ed25519 signature
// contract live in the evidence-envelope spec
// (specs/evidence/envelope.spec.yaml). The wire format is mirrored at
// kensa-spec/specs/evidence/envelope-v1.yaml so polyglot consumers
// share one source of truth.
type EvidenceEnvelope struct {
	SchemaVersion    string            `json:"schema_version"`
	TransactionID    uuid.UUID         `json:"transaction_id"`
	RuleID           string            `json:"rule_id"`
	HostID           string            `json:"host_id"`
	FleetID          string            `json:"fleet_id,omitempty"`
	StartedAt        time.Time         `json:"started_at"`
	FinishedAt       time.Time         `json:"finished_at"`
	PreStateBundle   []PreState        `json:"pre_state_bundle"`
	ApplySteps       []StepResult      `json:"apply_steps"`
	ValidatorResults []ValidatorResult `json:"validator_results"`
	Decision         TransactionStatus `json:"decision"`
	PostStateBundle  []PreState        `json:"post_state_bundle"`
	FrameworkRefs    []FrameworkRef    `json:"framework_refs"`
	SigningKeyID     string            `json:"signing_key_id"`
	Signature        []byte            `json:"signature"`
}

// ValidatorResult is the outcome of one post-apply validator (for
// example, a service-health check or a config-syntax verifier).
type ValidatorResult struct {
	// Name identifies the validator (e.g., "sshd_t_syntax_check").
	Name string
	// Passed is true when the validator confirmed the post-apply state.
	Passed bool
	// Detail is human-readable validator output for logs and UI.
	Detail string
	// Evidence is the raw command output the validator captured, for
	// auditor review without re-running on the host.
	Evidence string
}
