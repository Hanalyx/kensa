package api

import (
	"time"

	"github.com/google/uuid"
)

// TransactionStatus is the terminal state of a Transaction.
//
// Per engine-transaction spec C-01, a transaction MUST end in exactly one
// of these four values. No other state is permitted.
type TransactionStatus string

const (
	// StatusCommitted: every apply step succeeded and every validator
	// passed. System is in the target state.
	StatusCommitted TransactionStatus = "committed"

	// StatusRolledBack: apply or validate failed; every applied capturable
	// step has been reversed using captured pre-state. System is in the
	// exact pre-change state.
	StatusRolledBack TransactionStatus = "rolled_back"

	// StatusPartiallyApplied: only for transactional:false rules. At least
	// one non-capturable step ran before a failure; those steps are not
	// reversed. Explicit per-step stranded flags are in the StepResult.
	StatusPartiallyApplied TransactionStatus = "partially_applied"

	// StatusErrored: the engine could not complete a phase within the
	// transaction deadline. A typed error identifies which phase failed.
	StatusErrored TransactionStatus = "errored"
)

// Phase identifies the four transaction phases from the V1 model
// (TECHNICAL_REMEDIATION_MP_V1.md §3.5). Used in LogFilter.Phases and
// EventKind PhaseCompleted events.
type Phase string

const (
	PhaseCapture  Phase = "capture"
	PhaseApply    Phase = "apply"
	PhaseValidate Phase = "validate"
	PhaseCommit   Phase = "commit"
	PhaseRollback Phase = "rollback"
)

// Transaction represents a single rule's mutation against a single host.
// It is the unit of atomicity.
type Transaction struct {
	ID        uuid.UUID
	RuleID    string
	HostID    string
	FleetID   string // Optional; populated when the host belongs to a fleet
	Steps     []Step
	StartedAt time.Time
	Deadline  time.Time

	// Transactional declares whether this transaction can offer the
	// atomicity guarantee. Set from the rule YAML's `transactional`
	// field (CANONICAL_RULE_SCHEMA_V1.md §3.2). Pre-flight rejects a
	// transaction where Transactional=true but any Step uses a
	// non-capturable mechanism.
	Transactional bool
}

// Step is one mechanism invocation within a transaction.
type Step struct {
	Index     int
	Mechanism string // Must match a registered Handler's Name()
	Params    Params
}

// TransactionResult is the outcome of executing a Transaction.
type TransactionResult struct {
	TransactionID uuid.UUID
	Status        TransactionStatus
	Steps         []StepResult
	PreStates     []PreState
	StartedAt     time.Time
	FinishedAt    time.Time
	CommittedAt   *time.Time // Non-nil iff Status == StatusCommitted
	RolledBackAt  *time.Time // Non-nil iff Status == StatusRolledBack
	Envelope      *EvidenceEnvelope
	Error         error // Non-nil only on StatusErrored
}

// StepResult records the outcome of a single mechanism invocation.
type StepResult struct {
	StepIndex  int
	Mechanism  string
	Capturable bool
	Success    bool
	Detail     string
	Stranded   bool // true for partially-applied non-capturable steps
}

// PreState is the captured pre-change state for one step. The shape is
// mechanism-specific — each capturable handler defines its own PreState
// data under Data.
type PreState struct {
	StepIndex  int
	Mechanism  string
	Capturable bool
	Data       map[string]interface{} // Mechanism-specific serialized state
	CapturedAt time.Time
}

// RollbackResult records the outcome of reversing one applied step.
type RollbackResult struct {
	StepIndex      int
	Mechanism      string
	Success        bool
	Detail         string
	PartialRestore bool   // true if restore completed but a side effect remains
	Source         string // "inline" | "deadman" | "manual"
	ExecutedAt     time.Time
}

// EvidenceEnvelope is the signed record of a transaction. See the
// evidence-envelope spec (specs/evidence/envelope.spec.yaml) for the
// canonical schema.
type EvidenceEnvelope struct {
	SchemaVersion    string             `json:"schema_version"`
	TransactionID    uuid.UUID          `json:"transaction_id"`
	RuleID           string             `json:"rule_id"`
	HostID           string             `json:"host_id"`
	FleetID          string             `json:"fleet_id,omitempty"`
	StartedAt        time.Time          `json:"started_at"`
	FinishedAt       time.Time          `json:"finished_at"`
	PreStateBundle   []PreState         `json:"pre_state_bundle"`
	ApplySteps       []StepResult       `json:"apply_steps"`
	ValidatorResults []ValidatorResult  `json:"validator_results"`
	Decision         TransactionStatus  `json:"decision"`
	PostStateBundle  []PreState         `json:"post_state_bundle"`
	FrameworkRefs    []FrameworkRef     `json:"framework_refs"`
	SigningKeyID     string             `json:"signing_key_id"`
	Signature        []byte             `json:"signature"`
}

// ValidatorResult is the outcome of one post-apply validator.
type ValidatorResult struct {
	Name    string
	Passed  bool
	Detail  string
	Evidence string
}
