package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Planner produces a full transaction plan without executing it.
// OpenWatch's Control Plane (see docs/OPENWATCH_VISION.md §3.3) uses
// the plan to render the preview UI before a human approves
// execution.
type Planner interface {
	// PlanTransaction performs capability detection and
	// implementation selection for rule against the host reachable
	// via transport, runs the read-only portions of the capture
	// phase to populate [Plan.PreStates], and returns a [Plan]
	// describing every phase. PlanTransaction does not mutate the
	// host.
	PlanTransaction(ctx context.Context, transport Transport, rule *Rule) (*Plan, error)
}

// Executor runs a previously-produced [Plan]. The plan acts as a
// commitment: if host state has diverged from the plan's pre-state
// since planning, Execute returns a [PlanStaleError] and the caller
// must re-plan.
type Executor interface {
	// Execute runs plan against the host reachable via transport
	// and returns the resulting [TransactionResult]. A non-nil
	// [PlanStaleError] indicates the host's state has changed since
	// planning; the caller should re-invoke [Planner.PlanTransaction]
	// and seek fresh approval before retrying.
	Execute(ctx context.Context, transport Transport, plan *Plan) (*TransactionResult, error)
}

// Plan is the structured preview of a transaction. It contains every
// piece of information a reviewer needs to approve or reject the
// proposed change — pre-state, apply steps, validators, rollback plan,
// and explicit warnings such as the transactional:false escape hatch.
type Plan struct {
	// ID is the unique plan identifier; surfaces in [PlanStaleError].
	ID uuid.UUID
	// RuleID is the rule the plan implements.
	RuleID string
	// HostID identifies the target host.
	HostID string
	// SelectedImpl is the capability-gated [Implementation] chosen by
	// the planner for this host.
	SelectedImpl *Implementation
	// Capabilities is the host's detected [CapabilitySet] at planning
	// time.
	Capabilities CapabilitySet
	// Transactional mirrors the rule YAML's `transactional` field.
	Transactional bool
	// ControlChannelSensitive is true when at least one apply step
	// affects SSH, networking, PAM, or firewall state. The engine
	// arms a deadman timer before applying such transactions.
	ControlChannelSensitive bool
	// PreStates are the captured pre-state bundles, one per
	// capturable apply step. Populated by the capture phase that
	// [Planner.PlanTransaction] runs (read-only).
	PreStates []PreState
	// ApplySteps describes what apply would do, in order.
	ApplySteps []StepPreview
	// Validators describes the post-apply validators that would run.
	Validators []ValidatorPreview
	// RollbackPlan describes how each applied capturable step would
	// be reversed if validate or apply fails. In execution order:
	// element zero corresponds to the first apply step, but rollback
	// runs the slice in reverse.
	RollbackPlan []RollbackStepPreview
	// EstimatedDuration is the planner's wall-clock estimate.
	EstimatedDuration time.Duration
	// Warnings are operator-facing notices, such as
	// "rule is transactional:false".
	Warnings []string
	// CreatedAt is when the planner produced this plan.
	CreatedAt time.Time
}

// Preview renders the plan for human display. The CLI and OpenWatch
// UI both call Preview so audit logs and approval-queue UIs show the
// same canonical representation. Consumers may build richer
// interactive views over the struct fields, but the canonical form
// always goes through Preview.
//
// Preview returns [ErrNotYetImplemented] until the engine
// implementation lands per docs/KENSA_GO_DAY1_PLAN.md §11.5.
func (p *Plan) Preview(format PreviewFormat) (string, error) {
	return "", ErrNotYetImplemented
}

// PreviewFormat selects the rendering style for [Plan.Preview].
type PreviewFormat string

// Supported [PreviewFormat] values.
const (
	// PreviewText is ANSI-formatted CLI output.
	PreviewText PreviewFormat = "text"
	// PreviewMarkdown is markdown for OpenWatch UI and documentation.
	PreviewMarkdown PreviewFormat = "markdown"
	// PreviewJSON is structured machine-readable output.
	PreviewJSON PreviewFormat = "json"
	// PreviewPlain is unformatted text suitable for log embedding.
	PreviewPlain PreviewFormat = "plain"
)

// StepPreview describes one apply step without executing it.
type StepPreview struct {
	// Index is the zero-based position in [Plan.ApplySteps].
	Index int
	// Mechanism matches [Handler.Name].
	Mechanism string
	// Params are the resolved parameters for the step.
	Params Params
	// Capturable mirrors [Handler.Capturable].
	Capturable bool
	// Summary is a short human-readable description, for example
	// "Set PermitRootLogin=no in sshd_config.d/00-kensa.conf".
	Summary string
}

// ValidatorPreview describes one post-apply validator without
// executing it.
type ValidatorPreview struct {
	// Name identifies the validator.
	Name string
	// Summary describes what the validator checks.
	Summary string
}

// RollbackStepPreview describes how one apply step would be reversed.
type RollbackStepPreview struct {
	// Index matches the corresponding [StepPreview.Index].
	Index int
	// Mechanism matches the corresponding [StepPreview.Mechanism].
	Mechanism string
	// Summary is a human-readable description of the rollback action.
	Summary string
}

// Rule is the parsed canonical rule YAML. The full rule-parser
// machinery lives in internal/rule; the type is declared here so the
// [Planner] signature is self-contained at the api boundary.
type Rule struct {
	ID          string
	Title       string
	Description string
	Rationale   string
	Severity    string
	Category    string
	Tags        []string
	// Transactional comes from the rule YAML's `transactional` field
	// per docs/CANONICAL_RULE_SCHEMA_V1.md §3.2.
	Transactional   bool
	Platforms       []Platform
	Implementations []Implementation
	References      map[string]interface{}
	DependsOn       []string
	ConflictsWith   []string
	Supersedes      []string
}

// Platform captures one OS-scope entry for a [Rule].
type Platform struct {
	Family      string
	MinVersion  int
	MaxVersion  int
	Derivatives bool
}

// Implementation is one capability-gated check-and-remediation pair.
type Implementation struct {
	// Default marks the implementation selected when no other
	// capability gate matches.
	Default bool
	// When is the capability gate; the rule selector decodes the
	// shape (single capability, all/any/not combinator).
	When        interface{}
	Check       Check
	Remediation Remediation
}

// Check describes how to verify the desired state.
type Check struct {
	// Method is the check method identifier (for example,
	// "config_value", "sysctl_value", "command").
	Method string
	// Params are the method-specific parameters.
	Params Params
	// Checks composes multiple checks with AND semantics. When
	// non-empty, [Check.Method] and [Check.Params] are ignored.
	Checks []Check
}

// Remediation describes how to bring the system into the desired
// state. Single-step remediations populate [Remediation.Mechanism]
// and [Remediation.Params]; multi-step remediations populate
// [Remediation.Steps] instead.
type Remediation struct {
	Mechanism string
	Params    Params
	Steps     []RemediationStep
	// Reload names a service to systemctl-reload after the change.
	Reload string
	// Restart names a service to systemctl-restart after the change.
	Restart string
	// Notify names a handler to trigger at end of run, useful for
	// batching restarts.
	Notify string
}

// RemediationStep is one step of a multi-step [Remediation].
type RemediationStep struct {
	Mechanism string
	Params    Params
}

// CapabilitySet is the flat key-value map of detected capabilities for
// a host. Keys are capability names ("sshd_config_d", "authselect");
// values are booleans.
type CapabilitySet map[string]bool
