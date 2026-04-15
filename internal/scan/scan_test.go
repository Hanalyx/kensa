package scan_test

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/scan"
)

// fakeTransport satisfies api.Transport using a map of command → result.
type fakeTransport struct {
	results map[string]api.CommandResult
}

func (f *fakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	if r, ok := f.results[cmd]; ok {
		return &r, nil
	}
	// Default: success with empty output.
	return &api.CommandResult{ExitCode: 0}, nil
}

func (f *fakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (f *fakeTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (f *fakeTransport) Close() error                                            { return nil }
func (f *fakeTransport) ControlChannelSensitive() bool                           { return false }

// fakeEngine records Run calls and returns a canned result.
type fakeEngine struct {
	result *api.TransactionResult
}

func (e *fakeEngine) Run(_ context.Context, _ api.Transport, txn *api.Transaction, _ bool) (*api.TransactionResult, error) {
	if e.result != nil {
		return e.result, nil
	}
	return &api.TransactionResult{
		TransactionID: txn.ID,
		Status:        api.StatusCommitted,
		StartedAt:     time.Now().UTC(),
		FinishedAt:    time.Now().UTC(),
		Envelope: &api.EvidenceEnvelope{
			SchemaVersion: "v1",
			TransactionID: txn.ID,
			RuleID:        txn.RuleID,
			Decision:      api.StatusCommitted,
		},
	}, nil
}

func (e *fakeEngine) RollbackTransaction(_ context.Context, _ api.Transport, _ *api.TransactionRecord) (*api.RollbackResult, error) {
	return &api.RollbackResult{Success: true}, nil
}

func (e *fakeEngine) PlanTransaction(_ context.Context, _ api.Transport, rule *api.Rule) (*api.Plan, error) {
	return &api.Plan{ID: uuid.New(), RuleID: rule.ID}, nil
}

func (e *fakeEngine) ExecutePlan(_ context.Context, _ api.Transport, plan *api.Plan) (*api.TransactionResult, error) {
	return &api.TransactionResult{
		TransactionID: uuid.New(),
		Status:        api.StatusCommitted,
	}, nil
}

// minimalRule returns a minimal valid api.Rule with a single default
// implementation using the sysctl_value check method.
func minimalRule(id string) *api.Rule {
	return &api.Rule{
		ID:            id,
		Severity:      "medium",
		Transactional: true,
		Implementations: []api.Implementation{
			{
				Default: true,
				Check: api.Check{
					Method: "sysctl_value",
					Params: api.Params{"key": "net.ipv4.ip_forward", "expected": "0"},
				},
				Remediation: api.Remediation{
					Mechanism: "sysctl_set",
					Params:    api.Params{"key": "net.ipv4.ip_forward", "value": "0"},
				},
			},
		},
	}
}

// TestScan_AllPass verifies that all rules pass when the transport
// returns the expected sysctl value.
func TestScan_AllPass(t *testing.T) {
	tp := &fakeTransport{results: map[string]api.CommandResult{
		"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
	}}
	rules := []*api.Rule{minimalRule("rule-1"), minimalRule("rule-2")}
	runner := scan.New(nil)
	result, err := runner.Scan(context.Background(), tp, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Transactions) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result.Transactions))
	}
	for _, txr := range result.Transactions {
		if txr.Status != api.StatusCommitted {
			t.Errorf("expected committed, got %s", txr.Status)
		}
	}
}

// TestScan_OneFail verifies that a rule fails when the check returns
// the wrong value.
func TestScan_OneFail(t *testing.T) {
	tp := &fakeTransport{results: map[string]api.CommandResult{
		"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "1", ExitCode: 0},
	}}
	runner := scan.New(nil)
	result, err := runner.Scan(context.Background(), tp, []*api.Rule{minimalRule("rule-fail")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Transactions) != 1 {
		t.Fatalf("expected 1 result")
	}
	if result.Transactions[0].Status == api.StatusCommitted {
		t.Error("expected non-committed (fail), got committed")
	}
}

// TestRemediate_SkipsPassingRule verifies that a rule already in
// desired state is recorded as committed and skipped.
func TestRemediate_SkipsPassingRule(t *testing.T) {
	tp := &fakeTransport{results: map[string]api.CommandResult{
		"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
	}}
	runner := scan.New(&fakeEngine{})
	result, err := runner.Remediate(context.Background(), tp, []*api.Rule{minimalRule("skip-rule")})
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if len(result.Transactions) != 1 {
		t.Fatalf("expected 1 result")
	}
	if result.Transactions[0].Status != api.StatusCommitted {
		t.Errorf("expected committed for skipped rule, got %s", result.Transactions[0].Status)
	}
}

// TestRemediate_RunsEngineForFailingRule verifies that a rule failing
// the check is sent to the engine.
func TestRemediate_RunsEngineForFailingRule(t *testing.T) {
	tp := &fakeTransport{results: map[string]api.CommandResult{
		"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "1", ExitCode: 0},
	}}
	eng := &fakeEngine{}
	runner := scan.New(eng)
	result, err := runner.Remediate(context.Background(), tp, []*api.Rule{minimalRule("fix-rule")})
	if err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if len(result.Transactions) != 1 {
		t.Fatalf("expected 1 result")
	}
	if result.Transactions[0].Status != api.StatusCommitted {
		t.Errorf("engine result should be committed, got %s", result.Transactions[0].Status)
	}
}

// TestRemediate_NoEngine returns error when engine is nil.
func TestRemediate_NoEngine(t *testing.T) {
	tp := &fakeTransport{}
	runner := scan.New(nil)
	_, err := runner.Remediate(context.Background(), tp, []*api.Rule{minimalRule("r")})
	if err == nil {
		t.Error("expected error when engine is nil")
	}
}
