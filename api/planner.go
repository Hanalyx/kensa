package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Planner produces a full transaction plan without executing it.
// OpenWatch's Control Plane (OPENWATCH_VISION.md §3.3) uses this to render
// the preview UI before a human approves execution.
type Planner interface {
	// PlanTransaction takes a rule and a target host, performs capability
	// detection and implementation selection, and returns a Plan
	// describing every phase without mutating the host. Runs the
	// Capture phase's pre-read (read-only) so the plan contains the
	// exact captured pre-state.
	PlanTransaction(ctx context.Context, transport Transport, rule *Rule) (*Plan, error)
}

// Executor runs a previously-produced Plan. The plan acts as a commitment:
// if host state has diverged from the plan's pre-state since planning,
// Execute returns PlanStaleError and the caller must re-plan.
type Executor interface {
	Execute(ctx context.Context, transport Transport, plan *Plan) (*TransactionResult, error)
}

// Plan is the structured preview of a transaction.
type Plan struct {
	ID                      uuid.UUID
	RuleID                  string
	HostID                  string
	SelectedImpl            *Implementation
	Capabilities            CapabilitySet
	Transactional           bool
	ControlChannelSensitive bool // Deadman timer will be armed
	PreStates               []PreState
	ApplySteps              []StepPreview
	Validators              []ValidatorPreview
	RollbackPlan            []RollbackStepPreview
	EstimatedDuration       time.Duration
	Warnings                []string // e.g. "rule is transactional:false"
	CreatedAt               time.Time
}

// Preview renders the plan for human display. Kensa owns the rendering
// so the CLI and OpenWatch UI show the same canonical form. See
// PreviewFormat for output options.
//
// OpenWatch may still build richer interactive UIs over the struct
// fields, but the audit log display and CLI display always go through
// Preview for consistency.
func (p *Plan) Preview(format PreviewFormat) (string, error) {
	// Implementation lands with the engine. Returns ErrNotYetImplemented
	// from the v0.1.0 stub.
	return "", ErrNotYetImplemented
}

// PreviewFormat selects the rendering style for Plan.Preview.
type PreviewFormat string

const (
	PreviewText     PreviewFormat = "text"     // ANSI-formatted CLI output
	PreviewMarkdown PreviewFormat = "markdown" // For OpenWatch and docs
	PreviewJSON     PreviewFormat = "json"     // Structured, machine-readable
	PreviewPlain    PreviewFormat = "plain"    // No ANSI, no markdown — for logs
)

// StepPreview describes what Apply would do for one step without running it.
type StepPreview struct {
	Index           int
	Mechanism       string
	Params          Params
	Capturable      bool
	Summary         string // Human-readable: "Set PermitRootLogin=no in sshd_config.d"
}

// ValidatorPreview describes a validator that will run post-apply.
type ValidatorPreview struct {
	Name    string
	Summary string
}

// RollbackStepPreview describes how a step would be reversed.
type RollbackStepPreview struct {
	Index     int
	Mechanism string
	Summary   string // Human-readable rollback description
}

// ─── Rule / Implementation / Capability types used by Plan ─────────────

// Rule is the parsed canonical rule YAML. Full definition lives with the
// rule parser (internal/rule). Declared here at the api layer so Planner
// signatures are self-contained.
type Rule struct {
	ID              string
	Title           string
	Description     string
	Rationale       string
	Severity        string
	Category        string
	Tags            []string
	Transactional   bool // From the V1 schema's `transactional` field
	Platforms       []Platform
	Implementations []Implementation
	References      map[string]interface{} // Framework cross-references
	DependsOn       []string
	ConflictsWith   []string
	Supersedes      []string
}

// Platform captures a rule's OS scope.
type Platform struct {
	Family      string
	MinVersion  int
	MaxVersion  int
	Derivatives bool
}

// Implementation is one capability-gated check+remediation pair.
type Implementation struct {
	Default     bool
	When        interface{} // capability gate; decoded by the selector
	Check       Check
	Remediation Remediation
}

// Check is an implementation's verification logic.
type Check struct {
	Method string
	Params Params
	// Multi-check support via a nested Checks list; single-check uses Method directly.
	Checks []Check
}

// Remediation is an implementation's change-applying logic.
type Remediation struct {
	Mechanism string
	Params    Params
	Steps     []RemediationStep // Multi-step remediations
	Reload    string
	Restart   string
	Notify    string
}

// RemediationStep is one step of a multi-step Remediation.
type RemediationStep struct {
	Mechanism string
	Params    Params
}

// CapabilitySet is the flat key-value map of detected capabilities for
// a host. Keys are capability names ("sshd_config_d", "authselect", ...);
// values are booleans.
type CapabilitySet map[string]bool
