package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// PlanTransaction performs capability-selection and the read-only
// capture phase for rule on the host reachable via transport, and
// returns a Plan describing every phase without mutating the host.
// It satisfies [api.Planner].
func (e *Engine) PlanTransaction(ctx context.Context, transport api.Transport, rule *api.Rule) (*api.Plan, error) {
	impl := selectDefaultImpl(rule)
	if impl == nil {
		return nil, fmt.Errorf("plan: rule %q has no default implementation", rule.ID)
	}

	txn := ruleToTransaction(rule, impl)

	// Run the read-only capture phase. This does not mutate the host.
	preStates, err := e.capture(ctx, transport, txn)
	if err != nil {
		return nil, fmt.Errorf("plan: capture phase: %w", err)
	}

	// Build apply-step previews from the transaction steps.
	applySteps := make([]api.StepPreview, len(txn.Steps))
	for i, step := range txn.Steps {
		h, ok := e.lookupHandler(step.Mechanism)
		capturable := ok && h.Capturable()
		applySteps[i] = api.StepPreview{
			Index:      step.Index,
			Mechanism:  step.Mechanism,
			Params:     step.Params,
			Capturable: capturable,
			Summary:    formatStepSummary(step),
		}
	}

	// Build rollback previews from the capturable pre-states.
	rollbackPlan := make([]api.RollbackStepPreview, 0, len(preStates))
	for _, ps := range preStates {
		if !ps.Capturable {
			continue
		}
		rollbackPlan = append(rollbackPlan, api.RollbackStepPreview{
			Index:     ps.StepIndex,
			Mechanism: ps.Mechanism,
			Summary:   fmt.Sprintf("Rollback %s (restore pre-state)", ps.Mechanism),
		})
	}

	controlChannelSensitive := shouldArmDeadman(txn, e.registry)

	var warnings []string
	if !rule.Transactional {
		warnings = append(warnings, "rule is transactional:false — atomicity is not guaranteed; non-capturable steps will not be reversed on failure")
	}

	plan := &api.Plan{
		ID:                      uuid.New(),
		RuleID:                  rule.ID,
		HostID:                  "",
		SelectedImpl:            impl,
		Capabilities:            api.CapabilitySet{},
		Transactional:           rule.Transactional,
		ControlChannelSensitive: controlChannelSensitive,
		PreStates:               preStates,
		ApplySteps:              applySteps,
		Validators:              nil,
		RollbackPlan:            rollbackPlan,
		EstimatedDuration:       time.Duration(len(txn.Steps)) * 2 * time.Second,
		Warnings:                warnings,
		CreatedAt:               time.Now().UTC(),
	}
	return plan, nil
}

// ExecutePlan runs plan against the host reachable via transport. If host
// state has diverged from plan.PreStates since planning, returns
// [api.PlanStaleError].
// It satisfies [api.Executor].
func (e *Engine) ExecutePlan(ctx context.Context, transport api.Transport, plan *api.Plan) (*api.TransactionResult, error) {
	if plan.SelectedImpl == nil {
		return nil, fmt.Errorf("execute plan: plan has no selected implementation")
	}

	txn := ruleToTransaction(&api.Rule{
		ID:              plan.RuleID,
		Transactional:   plan.Transactional,
		Implementations: []api.Implementation{*plan.SelectedImpl},
	}, plan.SelectedImpl)
	txn.HostID = plan.HostID

	// Verify staleness: re-capture and compare to plan.PreStates.
	freshPreStates, err := e.capture(ctx, transport, txn)
	if err != nil {
		return nil, fmt.Errorf("execute plan: staleness capture: %w", err)
	}

	for i, ps := range plan.PreStates {
		if !ps.Capturable {
			continue
		}
		// Find corresponding fresh pre-state.
		var fresh *api.PreState
		for j := range freshPreStates {
			if freshPreStates[j].StepIndex == ps.StepIndex {
				fresh = &freshPreStates[j]
				break
			}
		}
		if fresh == nil {
			return nil, &api.PlanStaleError{
				PlanID:         plan.ID,
				StaleStepIndex: i,
				Mechanism:      ps.Mechanism,
				Field:          "pre_state",
				Expected:       ps.Data,
				Actual:         nil,
				Message:        fmt.Sprintf("plan stale: step %d (%s) has no corresponding fresh pre-state", i, ps.Mechanism),
			}
		}

		// Compare by JSON serialization.
		oldJSON, err1 := json.Marshal(ps.Data)
		newJSON, err2 := json.Marshal(fresh.Data)
		if err1 != nil || err2 != nil || string(oldJSON) != string(newJSON) {
			return nil, &api.PlanStaleError{
				PlanID:         plan.ID,
				StaleStepIndex: i,
				Mechanism:      ps.Mechanism,
				Field:          "data",
				Expected:       ps.Data,
				Actual:         fresh.Data,
			}
		}
	}

	// Pre-states match; run apply → validate → commit-or-rollback.
	// Use the already-captured plan.PreStates.
	if err := e.preflight(txn); err != nil {
		return e.errored(ctx, txn, time.Now().UTC(), api.PhaseCapture, err), nil
	}

	startedAt := time.Now().UTC()
	txn.StartedAt = startedAt

	if err := e.store.PersistPreStates(ctx, txn.ID, plan.PreStates); err != nil {
		return e.errored(ctx, txn, startedAt, api.PhaseCapture, err), nil
	}

	armed := false
	if plan.ControlChannelSensitive {
		if _, _, err := e.deadman.Arm(ctx, transport, txn.ID, plan.PreStates); err != nil {
			return e.errored(ctx, txn, startedAt, api.PhaseCapture, err), nil
		}
		armed = true
	}

	applyResults, applyOK := e.apply(ctx, transport, txn, plan.PreStates)

	var validators []api.ValidatorResult
	validateOK := applyOK
	if applyOK {
		validators, validateOK = e.validate(ctx, transport, txn)
	}

	if applyOK && validateOK {
		if armed {
			if err := e.deadman.Cancel(ctx, transport, txn.ID); err != nil {
				rb := e.rollback(ctx, transport, applyResults, plan.PreStates, "deadman")
				return e.finalize(ctx, txn, startedAt, api.StatusRolledBack, applyResults, plan.PreStates, validators, rb), nil
			}
		}
		return e.finalize(ctx, txn, startedAt, api.StatusCommitted, applyResults, plan.PreStates, validators, nil), nil
	}

	rb := e.rollback(ctx, transport, applyResults, plan.PreStates, "inline")
	if armed {
		_ = e.deadman.Cancel(ctx, transport, txn.ID)
	}

	status := api.StatusRolledBack
	if !txn.Transactional && hasStrandedNonCapturable(applyResults) {
		status = api.StatusPartiallyApplied
	}
	return e.finalize(ctx, txn, startedAt, status, applyResults, plan.PreStates, validators, rb), nil
}

// FormatPlan renders plan for human display. The CLI calls this
// directly; [api.Plan.Preview] returns [api.ErrNotYetImplemented]
// to avoid an api→internal import cycle.
//
// Supported formats: [api.PreviewText], [api.PreviewMarkdown],
// [api.PreviewJSON], [api.PreviewPlain]. Unknown formats fall back to
// [api.PreviewPlain].
func FormatPlan(plan *api.Plan, format api.PreviewFormat) (string, error) {
	switch format {
	case api.PreviewJSON:
		b, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return "", fmt.Errorf("format plan: json: %w", err)
		}
		return string(b), nil
	case api.PreviewMarkdown:
		return formatPlanMarkdown(plan), nil
	case api.PreviewText, api.PreviewPlain:
		return formatPlanPlain(plan), nil
	default:
		return formatPlanPlain(plan), nil
	}
}

// formatPlanPlain renders a plain-text plan summary.
func formatPlanPlain(plan *api.Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Plan %s\n", plan.ID)
	fmt.Fprintf(&b, "Rule: %s\n", plan.RuleID)
	fmt.Fprintf(&b, "Transactional: %v  ControlChannelSensitive: %v\n", plan.Transactional, plan.ControlChannelSensitive)
	fmt.Fprintf(&b, "EstimatedDuration: %s\n", plan.EstimatedDuration)
	if len(plan.Warnings) > 0 {
		fmt.Fprintf(&b, "Warnings:\n")
		for _, w := range plan.Warnings {
			fmt.Fprintf(&b, "  - %s\n", w)
		}
	}
	fmt.Fprintf(&b, "Apply steps (%d):\n", len(plan.ApplySteps))
	for _, s := range plan.ApplySteps {
		fmt.Fprintf(&b, "  [%d] %s\n", s.Index, s.Summary)
	}
	fmt.Fprintf(&b, "Rollback plan (%d):\n", len(plan.RollbackPlan))
	for _, r := range plan.RollbackPlan {
		fmt.Fprintf(&b, "  [%d] %s\n", r.Index, r.Summary)
	}
	return b.String()
}

// formatPlanMarkdown renders a markdown plan summary.
func formatPlanMarkdown(plan *api.Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Plan `%s`\n\n", plan.ID)
	fmt.Fprintf(&b, "**Rule:** `%s`  \n", plan.RuleID)
	fmt.Fprintf(&b, "**Transactional:** %v  \n", plan.Transactional)
	fmt.Fprintf(&b, "**Control-channel sensitive:** %v  \n", plan.ControlChannelSensitive)
	fmt.Fprintf(&b, "**Estimated duration:** %s  \n\n", plan.EstimatedDuration)
	if len(plan.Warnings) > 0 {
		fmt.Fprintf(&b, "## Warnings\n\n")
		for _, w := range plan.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "## Apply Steps\n\n")
	for _, s := range plan.ApplySteps {
		fmt.Fprintf(&b, "- **[%d]** `%s` — %s\n", s.Index, s.Mechanism, s.Summary)
	}
	fmt.Fprintf(&b, "\n## Rollback Plan\n\n")
	for _, r := range plan.RollbackPlan {
		fmt.Fprintf(&b, "- **[%d]** `%s` — %s\n", r.Index, r.Mechanism, r.Summary)
	}
	return b.String()
}

// ruleToTransaction converts the selected implementation's remediation
// steps into an [api.Transaction].
func ruleToTransaction(rule *api.Rule, impl *api.Implementation) *api.Transaction {
	txn := &api.Transaction{
		ID:            uuid.New(),
		RuleID:        rule.ID,
		Transactional: rule.Transactional,
		StartedAt:     time.Now().UTC(),
		Deadline:      time.Now().UTC().Add(5 * time.Minute),
	}

	rem := impl.Remediation
	if len(rem.Steps) > 0 {
		txn.Steps = make([]api.Step, len(rem.Steps))
		for i, s := range rem.Steps {
			txn.Steps[i] = api.Step{
				Index:     i,
				Mechanism: s.Mechanism,
				Params:    s.Params,
			}
		}
	} else if rem.Mechanism != "" {
		txn.Steps = []api.Step{
			{
				Index:     0,
				Mechanism: rem.Mechanism,
				Params:    rem.Params,
			},
		}
	}
	return txn
}

// selectDefaultImpl returns the first [api.Implementation] with
// Default:true, or nil if none is set.
func selectDefaultImpl(rule *api.Rule) *api.Implementation {
	for i := range rule.Implementations {
		if rule.Implementations[i].Default {
			return &rule.Implementations[i]
		}
	}
	return nil
}

// formatStepSummary returns a short human-readable description of a
// step. Format: "Apply <mechanism>" followed by key=value pairs if
// the params map is non-empty.
func formatStepSummary(step api.Step) string {
	if len(step.Params) == 0 {
		return fmt.Sprintf("Apply %s", step.Mechanism)
	}
	pairs := make([]string, 0, len(step.Params))
	for k, v := range step.Params {
		pairs = append(pairs, fmt.Sprintf("%s=%v", k, v))
	}
	return fmt.Sprintf("Apply %s (%s)", step.Mechanism, strings.Join(pairs, ", "))
}
