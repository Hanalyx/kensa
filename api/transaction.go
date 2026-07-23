package api

import (
	"time"

	"github.com/google/uuid"
)

// TransactionStatus is the terminal state of a [Transaction]. The engine
// guarantees that every transaction ends in exactly one of the values
// below; no other state is permitted. RollbackFailed and Recovered are
// reserved by the contract and produced by later milestones.
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
	// within the transaction deadline, or a terminal infrastructure
	// step (signing, persistence) failed. The error in
	// [TransactionResult.Error] identifies which phase failed.
	// [TransactionResult.HostUnchanged] distinguishes an errored abort
	// that never mutated the host from one that left a mutation behind.
	StatusErrored TransactionStatus = "errored"

	// StatusRollbackFailed indicates apply or validate failed and the
	// engine attempted to reverse the applied steps, but the restoration
	// could NOT be machine-verified as complete (a rollback step failed
	// or reported PartialRestore, or the recaptured post-state did not
	// match the captured pre-state). The host is in an unconfirmed state;
	// per-step detail is in [TransactionResult.RollbackResults]. Produced
	// by the engine when a reversed step fails or reports a partial
	// restore (the verdict-computed rollback status).
	StatusRollbackFailed TransactionStatus = "rollback_failed"

	// StatusRecovered indicates an interrupted transaction (the process
	// died after pre-state persistence but before a terminal record was
	// written) was reversed by the out-of-band recovery replay using the
	// durable journal. Produced by `kensa recover` (Engine.Recover).
	StatusRecovered TransactionStatus = "recovered"

	// StatusStaged indicates apply wrote the reboot-deferred persist layer
	// but could NOT converge the runtime, so the change takes effect only on
	// the next reboot. The sole producer is an apply step whose mechanism
	// cannot mutate live kernel state under the host's current configuration —
	// today, audit_rule_set on a host with an immutable audit config
	// (`auditctl -s` reports `enabled 2`), where the kernel refuses all
	// runtime rule loads until reboot. The host IS mutated (the persist file
	// is written and captured), but the runtime is NOT yet in the target
	// state, so a re-scan still reports the rule non-compliant until reboot.
	// The engine does NOT run the post-apply runtime re-check for a staged
	// step (it would fail) and does NOT roll back; `kensa rollback` still
	// reverses it byte-perfect from captured pre-state. Distinct from
	// StatusCommitted (runtime converged) and StatusPartiallyApplied
	// (stranded non-capturable steps after a FAILURE).
	StatusStaged TransactionStatus = "staged"
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
	// Severity is the rule severity (critical, high, medium, low).
	// Denormalised here so the store can index it without a rule join.
	Severity string
	// FrameworkRefs are the compliance-framework references for the
	// rule, expanded from the rule YAML references block by
	// internal/mappings. The engine records them in the evidence
	// envelope and in the framework_refs table.
	FrameworkRefs []FrameworkRef
	// Check is the selected implementation's desired-state check. The
	// engine re-runs it in the VALIDATE phase, after apply, to confirm
	// the change actually achieved the rule's intent before committing
	// (a clean failure drives rollback). Empty Method (and no sub-checks)
	// means no post-apply verification runs for this transaction.
	Check Check
}

// JournalEntry is one row of the crash-recovery intent journal. The engine
// writes it in the PREPARE phase — atomically with the captured pre-states,
// before any host mutation — so a transaction that crashes mid-flight can be
// found and compensated (rolled back) by out-of-band recovery. The entry is
// cleared once the transaction reaches a terminal status (its persisted
// result is the commit marker); an entry with no terminal result is an
// in-flight transaction the engine started but never finished.
type JournalEntry struct {
	// TxnID is the transaction this entry journals.
	TxnID uuid.UUID
	// HostID identifies the target host; recovery reconnects to it.
	HostID string
	// RuleID is the rule whose remediation is in flight.
	RuleID string
	// Transactional mirrors [Transaction.Transactional].
	Transactional bool
	// SessionID groups the entry with its CLI invocation; may be empty.
	SessionID string
	// Phase is the last recorded lifecycle phase ("prepared", "applying").
	Phase string
	// Cursor is the highest step index whose mutation may have begun
	// (advanced write-ahead during APPLY); -1 means nothing was applied.
	Cursor int
	// Intent is the transaction's steps, enough to reconstruct compensation
	// during recovery.
	Intent []Step
	// CreatedAt is when the entry was written (PREPARE time).
	CreatedAt time.Time
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
// [TransactionResult.Status] field is always one of the
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
	// RollbackResults records the per-step outcome of reversing applied
	// steps, when a rollback ran. Empty for committed transactions and
	// for pre-apply failures (nothing was applied to reverse). Carried
	// here and on [EvidenceEnvelope.RollbackResults] so the audit record
	// proves what restoration was attempted and whether it succeeded.
	RollbackResults []RollbackResult
	// HostUnchanged is true if and only if the host is provably in its
	// pre-transaction state at terminal time: a failure that reached no
	// later than pre-apply (preflight, capture, or pre-state
	// persistence), or a verified RolledBack outcome. It is false
	// whenever a mutation was applied and not verified-reversed —
	// including a signer or persistence failure AFTER a successful apply,
	// and any [StatusPartiallyApplied] outcome. Consumers use it to tell
	// a clean abort apart from a mutated-but-errored host.
	HostUnchanged bool
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
	// Success is true if the step's apply returned without error. In a
	// check-only [ScanResult.Transactions] entry no apply runs; there Success
	// carries the check verdict (true == compliant). Prefer
	// [ScanResult.Outcomes] for an unambiguous scan verdict.
	Success bool
	// Detail is human-readable per-step output suitable for logs and UI.
	Detail string
	// Stranded is true for non-capturable steps that succeeded before
	// a later failure left the rule [StatusPartiallyApplied]. Such
	// steps are not reversed by rollback.
	Stranded bool
	// Staged is true when the mechanism could not converge live state and
	// instead wrote a reboot-deferred persist change (audit_rule_set on an
	// immutable audit config, `enabled 2`). The engine terminates a
	// transaction with any Staged apply step as [StatusStaged], skipping the
	// runtime-recheck-driven rollback. The step is still capturable, so
	// [TransactionResult.PreStates] restores it byte-perfect on rollback.
	Staged bool
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
	//
	// Type-widening contract (relevant when this PreState has been
	// round-tripped through the agent wire format, L-007+): all Go
	// integer types in Data widen to int64 across the wire, and
	// time.Time values widen to RFC3339Nano strings. Handler code
	// that previously type-asserted .(int) or .(time.Time) after a
	// Capture must use .(int64) and the wirev1.DecodeTime helper
	// (or time.Parse(time.RFC3339Nano, ...)) respectively.
	//
	// Integers whose magnitude exceeds 2^53 are REJECTED at encode
	// time by the wire layer (float64 cannot represent them exactly).
	// Handlers that need larger integers must encode as strings.
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
	// RollbackResults records, per reversed step, whether restoration
	// succeeded and whether it was only partial. Empty when no rollback
	// ran (committed, or pre-apply failure). Part of the signed record.
	RollbackResults []RollbackResult  `json:"rollback_results,omitempty"`
	Decision        TransactionStatus `json:"decision"`
	// Severity is denormalised from the rule at write time so the
	// store can index by severity without joining against the rule
	// corpus. Populated from [Transaction.Severity].
	Severity        string         `json:"severity,omitempty"`
	PostStateBundle []PreState     `json:"post_state_bundle"`
	FrameworkRefs   []FrameworkRef `json:"framework_refs"`
	SigningKeyID    string         `json:"signing_key_id"`
	Signature       []byte         `json:"signature"`
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
