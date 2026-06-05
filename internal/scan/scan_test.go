package scan_test

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
	"github.com/Hanalyx/kensa/internal/scan"
)

// recordingSink records every Update delivered to it.
type recordingSink struct {
	got []progress.Update
}

func (r *recordingSink) Update(u progress.Update) { r.got = append(r.got, u) }

// panicSink panics on every Update, exercising the cosmetic-subordinate
// guarantee that a misbehaving sink cannot break a scan/detect run.
type panicSink struct{}

func (panicSink) Update(progress.Update) { panic("sink boom") }

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

// TestScan_NoSinkUnchanged verifies scan.New is variadic and that with no
// WithProgress option the ScanResult is identical to a Runner built with an
// explicit nil sink — the sink is the only added effect.
//
// @spec progress-emission
// @ac AC-01
func TestScan_NoSinkUnchanged(t *testing.T) {
	t.Run("progress-emission/AC-01", func(t *testing.T) {
		tp := &fakeTransport{results: map[string]api.CommandResult{
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
		}}
		rules := []*api.Rule{minimalRule("r1"), minimalRule("r2")}

		// No option (current call-site form).
		bare, err := scan.New(nil).Scan(context.Background(), tp, rules)
		if err != nil {
			t.Fatalf("bare Scan: %v", err)
		}
		// Explicit nil sink option — must be byte-identical in outcome.
		withNil, err := scan.New(nil, scan.WithProgress(nil)).Scan(context.Background(), tp, rules)
		if err != nil {
			t.Fatalf("nil-sink Scan: %v", err)
		}

		if len(bare.Transactions) != len(withNil.Transactions) {
			t.Fatalf("tx count differs: bare=%d nil-sink=%d",
				len(bare.Transactions), len(withNil.Transactions))
		}
		for i := range bare.Transactions {
			if bare.Transactions[i].Status != withNil.Transactions[i].Status {
				t.Errorf("tx[%d] status differs: bare=%s nil-sink=%s",
					i, bare.Transactions[i].Status, withNil.Transactions[i].Status)
			}
		}
		if len(bare.Transactions) != 2 {
			t.Fatalf("expected 2 results, got %d", len(bare.Transactions))
		}
	})
}

// TestScan_EmitsRuleChecked verifies that with a recording sink wired,
// ScanWithOverrides emits exactly one RuleChecked Update per rule, in order,
// each carrying the rule's RuleID, a 1-based Index, the total count, and OK
// matching the check outcome.
//
// @spec progress-emission
// @ac AC-02
func TestScan_EmitsRuleChecked(t *testing.T) {
	t.Run("progress-emission/AC-02", func(t *testing.T) {
		// r-pass passes (sysctl == 0), r-fail fails (sysctl == 1).
		passTp := minimalRule("r-pass")
		failTp := minimalRule("r-fail")
		failTp.Implementations[0].Check.Params = api.Params{
			"key": "net.ipv4.conf.all.rp_filter", "expected": "1",
		}
		tp := &fakeTransport{results: map[string]api.CommandResult{
			"sysctl -n 'net.ipv4.ip_forward'":         {Stdout: "0", ExitCode: 0},
			"sysctl -n 'net.ipv4.conf.all.rp_filter'": {Stdout: "0", ExitCode: 0},
		}}

		sink := &recordingSink{}
		runner := scan.New(nil, scan.WithProgress(sink))
		rules := []*api.Rule{passTp, failTp}
		if _, err := runner.Scan(context.Background(), tp, rules); err != nil {
			t.Fatalf("Scan: %v", err)
		}

		if len(sink.got) != 2 {
			t.Fatalf("expected 2 RuleChecked updates, got %d: %+v", len(sink.got), sink.got)
		}
		want := []struct {
			ruleID string
			index  int
			ok     bool
		}{
			{"r-pass", 1, true},
			{"r-fail", 2, false},
		}
		for i, w := range want {
			u := sink.got[i]
			if u.Kind != progress.RuleChecked {
				t.Errorf("update[%d] Kind = %d, want RuleChecked", i, u.Kind)
			}
			if u.RuleID != w.ruleID {
				t.Errorf("update[%d] RuleID = %q, want %q", i, u.RuleID, w.ruleID)
			}
			if u.Index != w.index {
				t.Errorf("update[%d] Index = %d, want %d", i, u.Index, w.index)
			}
			if u.Total != 2 {
				t.Errorf("update[%d] Total = %d, want 2", i, u.Total)
			}
			if u.OK != w.ok {
				t.Errorf("update[%d] OK = %v, want %v", i, u.OK, w.ok)
			}
		}
	})
}

// TestScan_PanicSinkDoesNotBreak verifies a sink that panics on every Update
// does not break the scan — the result is still produced.
//
// @spec progress-emission
// @ac AC-05
func TestScan_PanicSinkDoesNotBreak(t *testing.T) {
	t.Run("progress-emission/AC-05", func(t *testing.T) {
		tp := &fakeTransport{results: map[string]api.CommandResult{
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
		}}
		runner := scan.New(nil, scan.WithProgress(panicSink{}))
		result, err := runner.Scan(context.Background(), tp,
			[]*api.Rule{minimalRule("r1"), minimalRule("r2")})
		if err != nil {
			t.Fatalf("Scan returned err despite panicking sink: %v", err)
		}
		if len(result.Transactions) != 2 {
			t.Fatalf("expected 2 results despite panicking sink, got %d",
				len(result.Transactions))
		}
	})
}
