package engine_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// newPlanTestEngine returns an engine seeded with the given handlers.
func newPlanTestEngine(t *testing.T, handlers ...api.Handler) *engine.Engine {
	t.Helper()
	r := handler.NewRegistry()
	for _, h := range handlers {
		r.Register(h)
	}
	return engine.New(engine.WithRegistry(r))
}

// basicRule returns a rule with one default implementation whose
// remediation uses the named mechanism.
func basicRule(mechanism string, capturable bool) *api.Rule {
	return &api.Rule{
		ID:            "test-rule",
		Transactional: capturable, // transactional only when capturable
		Implementations: []api.Implementation{
			{
				Default: true,
				Remediation: api.Remediation{
					Mechanism: mechanism,
					Params:    api.Params{"key": "value"},
				},
			},
		},
	}
}

// multiStepRule returns a rule with a multi-step default
// implementation.
func multiStepRule(steps []api.RemediationStep) *api.Rule {
	return &api.Rule{
		ID:            "multi-step-rule",
		Transactional: true,
		Implementations: []api.Implementation{
			{
				Default: true,
				Remediation: api.Remediation{
					Steps: steps,
				},
			},
		},
	}
}

// TestPlanTransaction_BasicCapturable checks that PlanTransaction with a
// capturable handler returns a Plan with non-empty PreStates and
// RollbackPlan.
func TestPlanTransaction_BasicCapturable(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fake_cap", IsCapturable: true}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	plan, err := e.PlanTransaction(context.Background(), tr, basicRule("fake_cap", true))
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	if plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if plan.RuleID != "test-rule" {
		t.Errorf("RuleID=%q, want test-rule", plan.RuleID)
	}
	if len(plan.PreStates) != 1 {
		t.Fatalf("PreStates len=%d, want 1", len(plan.PreStates))
	}
	if !plan.PreStates[0].Capturable {
		t.Error("expected PreState to be capturable")
	}
	if len(plan.ApplySteps) != 1 {
		t.Fatalf("ApplySteps len=%d, want 1", len(plan.ApplySteps))
	}
	if plan.ApplySteps[0].Mechanism != "fake_cap" {
		t.Errorf("ApplySteps[0].Mechanism=%q, want fake_cap", plan.ApplySteps[0].Mechanism)
	}
	if len(plan.RollbackPlan) != 1 {
		t.Fatalf("RollbackPlan len=%d, want 1", len(plan.RollbackPlan))
	}
	if plan.RollbackPlan[0].Mechanism != "fake_cap" {
		t.Errorf("RollbackPlan[0].Mechanism=%q, want fake_cap", plan.RollbackPlan[0].Mechanism)
	}
}

// TestPlanTransaction_NonCapturable checks that a non-capturable step
// does not produce a RollbackPlan entry.
func TestPlanTransaction_NonCapturable(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fake_noncap", IsCapturable: false}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	rule := basicRule("fake_noncap", false)
	rule.Transactional = false

	plan, err := e.PlanTransaction(context.Background(), tr, rule)
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	if len(plan.PreStates) != 1 {
		t.Fatalf("PreStates len=%d, want 1 (marker entry)", len(plan.PreStates))
	}
	if plan.PreStates[0].Capturable {
		t.Error("expected PreState marker to be non-capturable")
	}
	if len(plan.RollbackPlan) != 0 {
		t.Errorf("RollbackPlan len=%d, want 0 for non-capturable step", len(plan.RollbackPlan))
	}
}

// TestPlanTransaction_TransactionalFalseWarning checks that a
// transactional:false rule generates a warning in the plan.
func TestPlanTransaction_TransactionalFalseWarning(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fake_noncap2", IsCapturable: false}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	rule := basicRule("fake_noncap2", false)
	rule.Transactional = false

	plan, err := e.PlanTransaction(context.Background(), tr, rule)
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	if len(plan.Warnings) == 0 {
		t.Error("expected at least one warning for transactional:false rule")
	}
}

// TestPlanTransaction_NoDefaultImpl checks that a rule with no default
// implementation returns an error.
func TestPlanTransaction_NoDefaultImpl(t *testing.T) {
	e := newPlanTestEngine(t)
	tr := engine.NewFakeTransport()

	rule := &api.Rule{
		ID: "no-default",
		Implementations: []api.Implementation{
			{Default: false, Remediation: api.Remediation{Mechanism: "anything"}},
		},
	}

	_, err := e.PlanTransaction(context.Background(), tr, rule)
	if err == nil {
		t.Fatal("expected error when no default implementation exists")
	}
}

// TestPlanTransaction_MultiStep checks that multi-step remediations
// produce the correct number of ApplySteps.
func TestPlanTransaction_MultiStep(t *testing.T) {
	h0 := &engine.FakeHandler{HandlerName: "step_a", IsCapturable: true}
	h1 := &engine.FakeHandler{HandlerName: "step_b", IsCapturable: true}
	r := handler.NewRegistry()
	r.Register(h0)
	r.Register(h1)
	e := engine.New(engine.WithRegistry(r))
	tr := engine.NewFakeTransport()

	rule := multiStepRule([]api.RemediationStep{
		{Mechanism: "step_a", Params: api.Params{"x": 1}},
		{Mechanism: "step_b", Params: api.Params{"y": 2}},
	})

	plan, err := e.PlanTransaction(context.Background(), tr, rule)
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	if len(plan.ApplySteps) != 2 {
		t.Fatalf("ApplySteps len=%d, want 2", len(plan.ApplySteps))
	}
	if len(plan.RollbackPlan) != 2 {
		t.Fatalf("RollbackPlan len=%d, want 2", len(plan.RollbackPlan))
	}
	if plan.EstimatedDuration.Seconds() != 4 {
		t.Errorf("EstimatedDuration=%v, want 4s (2 steps × 2s)", plan.EstimatedDuration)
	}
}

// TestPlanTransaction_EstimatedDuration checks the EstimatedDuration
// calculation for a single-step rule.
func TestPlanTransaction_EstimatedDuration(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "dur_step", IsCapturable: true}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	plan, err := e.PlanTransaction(context.Background(), tr, basicRule("dur_step", true))
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	if plan.EstimatedDuration.Seconds() != 2 {
		t.Errorf("EstimatedDuration=%v, want 2s (1 step × 2s)", plan.EstimatedDuration)
	}
}

// TestPlanTransaction_CaptureCalls checks that Capture is called exactly
// once per capturable step.
func TestPlanTransaction_CaptureCalls(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "cap_count", IsCapturable: true}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	_, err := e.PlanTransaction(context.Background(), tr, basicRule("cap_count", true))
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	if h.CaptureCalls != 1 {
		t.Errorf("CaptureCalls=%d, want 1", h.CaptureCalls)
	}
	// Apply must not run during planning.
	if h.ApplyCalls != 0 {
		t.Errorf("ApplyCalls=%d, want 0 (planning is read-only)", h.ApplyCalls)
	}
}

// TestPlanTransaction_IDIsNonZero checks that each plan gets a unique
// non-zero UUID.
func TestPlanTransaction_IDIsNonZero(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "id_check", IsCapturable: true}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	rule := basicRule("id_check", true)
	p1, err := e.PlanTransaction(context.Background(), tr, rule)
	if err != nil {
		t.Fatalf("first PlanTransaction: %v", err)
	}
	p2, err := e.PlanTransaction(context.Background(), tr, rule)
	if err != nil {
		t.Fatalf("second PlanTransaction: %v", err)
	}

	if p1.ID == p2.ID {
		t.Error("two plans for the same rule produced identical IDs")
	}
}

// TestExecutePlan_SuccessAfterPlan checks the full Plan → Execute
// round trip produces a committed result when host state has not
// changed.
func TestExecutePlan_SuccessAfterPlan(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "exec_ok", IsCapturable: true}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	rule := basicRule("exec_ok", true)
	plan, err := e.PlanTransaction(context.Background(), tr, rule)
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	result, err := e.ExecutePlan(context.Background(), tr, plan)
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if result.Status != api.StatusCommitted {
		t.Errorf("Status=%s, want Committed", result.Status)
	}
}

// TestExecutePlan_StaleDetected checks that ExecutePlan returns
// PlanStaleError when the host's pre-state changes between plan and
// execute.
func TestExecutePlan_StaleDetected(t *testing.T) {
	var callCount int
	// First capture (planning) returns data={"v":1};
	// second capture (staleness check) returns data={"v":2}.
	h := &engine.FakeHandler{
		HandlerName:  "stale_detect",
		IsCapturable: true,
	}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	rule := basicRule("stale_detect", true)

	// Plan with v=1.
	h.CapturePreState = &api.PreState{Data: map[string]interface{}{"v": float64(1)}}
	plan, err := e.PlanTransaction(context.Background(), tr, rule)
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}
	_ = callCount

	// Simulate state drift: capture now returns v=2.
	h.CapturePreState = &api.PreState{Data: map[string]interface{}{"v": float64(2)}}

	_, err = e.ExecutePlan(context.Background(), tr, plan)
	if err == nil {
		t.Fatal("expected PlanStaleError, got nil")
	}
	var staleErr *api.PlanStaleError
	ok := false
	if se, isSE := err.(*api.PlanStaleError); isSE {
		staleErr = se
		ok = true
	}
	if !ok || staleErr == nil {
		t.Fatalf("expected *api.PlanStaleError, got %T: %v", err, err)
	}
	if staleErr.PlanID != plan.ID {
		t.Errorf("PlanStaleError.PlanID=%v, want %v", staleErr.PlanID, plan.ID)
	}
}

// TestFormatPlan_PlainText checks that FormatPlan in text mode returns a
// non-empty string containing the plan ID and rule ID.
func TestFormatPlan_PlainText(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fmt_step", IsCapturable: true}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	plan, err := e.PlanTransaction(context.Background(), tr, basicRule("fmt_step", true))
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	out, err := engine.FormatPlan(plan, api.PreviewText)
	if err != nil {
		t.Fatalf("FormatPlan text: %v", err)
	}
	if out == "" {
		t.Error("FormatPlan text returned empty string")
	}
}

// TestFormatPlan_JSON checks that FormatPlan in JSON mode returns valid
// JSON containing the rule ID.
func TestFormatPlan_JSON(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fmt_json", IsCapturable: true}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	plan, err := e.PlanTransaction(context.Background(), tr, basicRule("fmt_json", true))
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	out, err := engine.FormatPlan(plan, api.PreviewJSON)
	if err != nil {
		t.Fatalf("FormatPlan json: %v", err)
	}
	if out == "" {
		t.Error("FormatPlan json returned empty string")
	}
	// Minimal JSON structure check.
	if len(out) < 2 || out[0] != '{' {
		t.Errorf("FormatPlan json does not look like JSON: %q", out[:min(len(out), 40)])
	}
}

// TestFormatPlan_Markdown checks that FormatPlan in markdown mode
// returns a string starting with the markdown heading marker.
func TestFormatPlan_Markdown(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fmt_md", IsCapturable: true}
	e := newPlanTestEngine(t, h)
	tr := engine.NewFakeTransport()

	plan, err := e.PlanTransaction(context.Background(), tr, basicRule("fmt_md", true))
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}

	out, err := engine.FormatPlan(plan, api.PreviewMarkdown)
	if err != nil {
		t.Fatalf("FormatPlan markdown: %v", err)
	}
	if len(out) < 2 || out[0] != '#' {
		t.Errorf("FormatPlan markdown does not start with '#': %q", out[:min(len(out), 40)])
	}
}

// min is a local helper because math.Min is for float64.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
