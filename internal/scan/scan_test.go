package scan_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
	"github.com/Hanalyx/kensa/internal/rule"
	"github.com/Hanalyx/kensa/internal/scan"
)

// osReleaseResult fakes `cat /etc/os-release` output for a given ID/VERSION_ID.
func osReleaseResult(id, versionID string) api.CommandResult {
	return api.CommandResult{ExitCode: 0, Stdout: fmt.Sprintf("ID=%s\nVERSION_ID=%q\n", id, versionID)}
}

// rhelMinRule is a passing sysctl rule scoped to rhel >= minVersion.
func rhelMinRule(id string, minVersion int) *api.Rule {
	r := sysctlRule(id, "medium", "net.ipv4.ip_forward", "0")
	r.Platforms = []api.Platform{{Family: "rhel", MinVersion: minVersion}}
	return r
}

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
	runs   int // number of Run invocations, for never-ran assertions
}

func (e *fakeEngine) Run(_ context.Context, _ api.Transport, txn *api.Transaction, _ bool) (*api.TransactionResult, error) {
	e.runs++
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

// ruleForKey is minimalRule with a caller-chosen sysctl key so two rules in
// one test can have independent check outcomes via the fakeTransport.
func ruleForKey(id, key string) *api.Rule {
	r := minimalRule(id)
	r.Implementations[0].Check.Params = api.Params{"key": key, "expected": "0"}
	r.Implementations[0].Remediation.Params = api.Params{"key": key, "value": "0"}
	return r
}

// TestRemediateWithProgress_EmitsPerRule verifies RemediateWithOverrides emits
// one RuleChecked Update per rule with outcome flags a renderer maps to rows:
// already-compliant => OK && !Fixed (PASS), remediated => OK && Fixed (FIXED).
// (FAIL/ERROR follow from OK=false / Errored on the same seam.) This is the
// remediate counterpart to the scan emission in progress-emission.
//
// @spec progress-emission
// @ac AC-06
func TestRemediateWithProgress_EmitsPerRule(t *testing.T) {
	t.Run("progress-emission/AC-06", func(t *testing.T) {})

	okRule := ruleForKey("rule-ok", "net.a")   // check passes -> already compliant
	fixRule := ruleForKey("rule-fix", "net.b") // check fails -> remediated (fakeEngine commits)
	tp := &fakeTransport{results: map[string]api.CommandResult{
		"sysctl -n 'net.a'": {Stdout: "0", ExitCode: 0},
		"sysctl -n 'net.b'": {Stdout: "1", ExitCode: 0},
	}}
	sink := &recordingSink{}
	runner := scan.New(&fakeEngine{}, scan.WithProgress(sink))

	if _, err := runner.Remediate(context.Background(), tp, []*api.Rule{okRule, fixRule}); err != nil {
		t.Fatalf("Remediate: %v", err)
	}
	if len(sink.got) != 2 {
		t.Fatalf("expected 2 progress updates, got %d: %+v", len(sink.got), sink.got)
	}
	if u := sink.got[0]; u.RuleID != "rule-ok" || u.Kind != progress.RuleChecked || !u.OK || u.Fixed {
		t.Errorf("already-compliant rule: want RuleChecked OK && !Fixed for rule-ok, got %+v", u)
	}
	if u := sink.got[1]; u.RuleID != "rule-fix" || u.Kind != progress.RuleChecked || !u.OK || !u.Fixed {
		t.Errorf("remediated rule: want RuleChecked OK && Fixed for rule-fix, got %+v", u)
	}
}

// sysctlRule returns a rule with a single default sysctl_value check on key,
// expecting expected. The probe command is `sysctl -n '<key>'`.
func sysctlRule(id, severity, key, expected string) *api.Rule {
	return &api.Rule{
		ID:       id,
		Severity: severity,
		Implementations: []api.Implementation{{
			Default: true,
			Check: api.Check{
				Method: "sysctl_value",
				Params: api.Params{"key": key, "expected": expected},
			},
		}},
	}
}

// notApplicableRule returns a rule whose only implementation is gated on a
// capability the host lacks and has no default — so rule.Select wraps
// ErrNoImplementation and the rule is skipped (not-applicable), not errored.
func notApplicableRule(id string) *api.Rule {
	return &api.Rule{
		ID:       id,
		Severity: "low",
		Implementations: []api.Implementation{{
			When:  "a_capability_this_host_does_not_have",
			Check: api.Check{Method: "sysctl_value", Params: api.Params{"key": "x", "expected": "0"}},
		}},
	}
}

// uncheckableRule returns a rule whose default check uses an unknown method,
// so check.Run returns an error and the verdict is error.
func uncheckableRule(id string) *api.Rule {
	return &api.Rule{
		ID:       id,
		Severity: "high",
		Implementations: []api.Implementation{{
			Default: true,
			Check:   api.Check{Method: "no_such_check_method"},
		}},
	}
}

// malformedWhenRule returns a rule whose only implementation has a
// structurally invalid `when` (an int, neither string nor map) and no default,
// so rule.Select returns a real error that does NOT wrap ErrNoImplementation —
// the error branch of the skip/error split, distinct from notApplicableRule.
func malformedWhenRule(id string) *api.Rule {
	return &api.Rule{
		ID:       id,
		Severity: "high",
		Implementations: []api.Implementation{{
			When:  12345,
			Check: api.Check{Method: "sysctl_value", Params: api.Params{"key": "x", "expected": "0"}},
		}},
	}
}

// TestScan_Outcomes verifies the canonical compliance-verdict surface:
// ScanResult.Outcomes carries one api.RuleOutcome per rule, in order, with the
// pass/fail/skipped/error mapping — and Transactions stays populated.
//
// @spec scan-compliance-outcome
func TestScan_Outcomes(t *testing.T) {
	// AC-01/02/05 share one pass+fail scan: a passing then a failing rule, each
	// on a distinct sysctl key so one transport drives both. Each AC is its own
	// named subtest so the coverage gate credits a passing case per AC.
	pfTransport := &fakeTransport{results: map[string]api.CommandResult{
		"sysctl -n 'net.ipv4.ip_forward'":       {Stdout: "0", ExitCode: 0},
		"sysctl -n 'kernel.randomize_va_space'": {Stdout: "1", ExitCode: 0},
	}}
	pf, err := scan.New(nil).Scan(context.Background(), pfTransport, []*api.Rule{
		sysctlRule("rule-pass", "medium", "net.ipv4.ip_forward", "0"),
		sysctlRule("rule-fail", "high", "kernel.randomize_va_space", "0"),
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(pf.Outcomes) != 2 {
		t.Fatalf("want 2 outcomes, got %d", len(pf.Outcomes))
	}

	// AC-01: one outcome per rule, in input order, with RuleID + Severity.
	t.Run("scan-compliance-outcome/AC-01", func(t *testing.T) {
		// @spec scan-compliance-outcome
		// @ac AC-01
		if o := pf.Outcomes[0]; o.RuleID != "rule-pass" || o.Severity != "medium" {
			t.Errorf("outcome[0]: want rule-pass/medium, got %s/%s", o.RuleID, o.Severity)
		}
		if o := pf.Outcomes[1]; o.RuleID != "rule-fail" || o.Severity != "high" {
			t.Errorf("outcome[1]: want rule-fail/high, got %s/%s", o.RuleID, o.Severity)
		}
	})

	// AC-02: passing check => pass; failing check => fail.
	t.Run("scan-compliance-outcome/AC-02", func(t *testing.T) {
		// @spec scan-compliance-outcome
		// @ac AC-02
		if o := pf.Outcomes[0]; o.Status != api.CompliancePass {
			t.Errorf("outcome[0]: want pass, got %q", o.Status)
		}
		if o := pf.Outcomes[1]; o.Status != api.ComplianceFail {
			t.Errorf("outcome[1]: want fail, got %q", o.Status)
		}
	})

	// AC-05: Transactions still populated (committed for pass, rolled_back for fail).
	t.Run("scan-compliance-outcome/AC-05", func(t *testing.T) {
		// @spec scan-compliance-outcome
		// @ac AC-05
		if len(pf.Transactions) != 2 {
			t.Fatalf("want 2 transactions, got %d", len(pf.Transactions))
		}
		if pf.Transactions[0].Status != api.StatusCommitted {
			t.Errorf("txn[0]: want committed, got %s", pf.Transactions[0].Status)
		}
		if pf.Transactions[1].Status != api.StatusRolledBack {
			t.Errorf("txn[1]: want rolled_back, got %s", pf.Transactions[1].Status)
		}
	})

	// AC-03: a not-applicable rule (no impl, no default) is skipped, not
	// errored, with nil Err — and Transactions stays length-aligned (C-05).
	t.Run("scan-compliance-outcome/AC-03", func(t *testing.T) {
		// @spec scan-compliance-outcome
		// @ac AC-03
		result, err := scan.New(nil).Scan(context.Background(), &fakeTransport{}, []*api.Rule{notApplicableRule("rule-skip")})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if len(result.Outcomes) != 1 {
			t.Fatalf("want 1 outcome, got %d", len(result.Outcomes))
		}
		o := result.Outcomes[0]
		if o.Status != api.ComplianceSkipped {
			t.Errorf("want skipped, got %q (detail=%q)", o.Status, o.Detail)
		}
		if o.Err != nil {
			t.Errorf("skipped outcome must have nil Err, got %v", o.Err)
		}
		// C-05: Transactions stays one-per-rule, errored for a skip.
		if len(result.Transactions) != 1 || result.Transactions[0].Status != api.StatusErrored {
			t.Errorf("want 1 errored transaction for skip, got %d %+v", len(result.Transactions), result.Transactions)
		}
	})

	// AC-04: a rule whose check cannot run is error with a non-nil Err. Two
	// distinct sources: an unknown check method (check.Run errors) and a
	// structurally invalid `when` (rule.Select errors but NOT with
	// ErrNoImplementation — proving the skip/error split). Transactions stays
	// length-aligned (C-05).
	t.Run("scan-compliance-outcome/AC-04", func(t *testing.T) {
		// @spec scan-compliance-outcome
		// @ac AC-04
		cases := []struct {
			name       string
			rule       *api.Rule
			fromSelect bool // error originates in rule.Select (malformed when)
		}{
			{"check-error", uncheckableRule("rule-checkerr"), false},
			{"malformed-when", malformedWhenRule("rule-whenerr"), true},
		}
		for _, tc := range cases {
			result, err := scan.New(nil).Scan(context.Background(), &fakeTransport{}, []*api.Rule{tc.rule})
			if err != nil {
				t.Fatalf("%s: Scan: %v", tc.name, err)
			}
			if len(result.Outcomes) != 1 {
				t.Fatalf("%s: want 1 outcome, got %d", tc.name, len(result.Outcomes))
			}
			o := result.Outcomes[0]
			if o.Status != api.ComplianceError {
				t.Errorf("%s: want error, got %q", tc.name, o.Status)
			}
			if o.Err == nil {
				t.Errorf("%s: error outcome must carry a non-nil Err", tc.name)
			}
			// A malformed `when` must NOT be mistaken for the skip sentinel.
			if tc.fromSelect && errors.Is(o.Err, rule.ErrNoImplementation) {
				t.Errorf("%s: malformed when wrongly classified as ErrNoImplementation (would skip)", tc.name)
			}
			if len(result.Transactions) != 1 || result.Transactions[0].Status != api.StatusErrored {
				t.Errorf("%s: want 1 errored transaction, got %d %+v", tc.name, len(result.Transactions), result.Transactions)
			}
		}
	})

	// AC-06: every outcome carries the rule's FrameworkRefs, normalised from
	// References, so a consumer attributes a verdict to a framework without a
	// corpus re-join.
	t.Run("scan-compliance-outcome/AC-06", func(t *testing.T) {
		// @spec scan-compliance-outcome
		// @ac AC-06
		r := sysctlRule("rule-fw", "medium", "net.ipv4.ip_forward", "0")
		r.References = map[string]interface{}{"nist_800_53": []interface{}{"AC-6", "AC-17"}}
		tp := &fakeTransport{results: map[string]api.CommandResult{
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
		}}
		result, err := scan.New(nil).Scan(context.Background(), tp, []*api.Rule{r})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		refs := result.Outcomes[0].FrameworkRefs
		if len(refs) != 2 {
			t.Fatalf("want 2 framework refs, got %d: %+v", len(refs), refs)
		}
		for _, fr := range refs {
			if fr.FrameworkID != "nist_800_53" || (fr.ControlID != "AC-6" && fr.ControlID != "AC-17") {
				t.Errorf("unexpected framework ref: %+v", fr)
			}
		}
	})

	// AC-07: platform applicability. A rule scoped to an OS the host is not is
	// skipped (not evaluated); an in-scope or unconstrained rule is evaluated;
	// an undetectable host is never gated.
	t.Run("scan-compliance-outcome/AC-07", func(t *testing.T) {
		// @spec scan-compliance-outcome
		// @ac AC-07
		// (a) rhel>=9 rule on a rhel 8 host: skipped (would PASS if evaluated).
		tp8 := &fakeTransport{results: map[string]api.CommandResult{
			"cat /etc/os-release 2>/dev/null": osReleaseResult("rhel", "8.10"),
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
		}}
		r8, err := scan.New(nil).Scan(context.Background(), tp8, []*api.Rule{rhelMinRule("rule-rhel9", 9)})
		if err != nil {
			t.Fatalf("rhel8 scan: %v", err)
		}
		if o := r8.Outcomes[0]; o.Status != api.ComplianceSkipped || o.Err != nil {
			t.Errorf("rhel>=9 on rhel8: want skipped/nil-Err, got %q/%v (detail=%q)", o.Status, o.Err, o.Detail)
		}

		// (b) same rule on a rhel 9 host: evaluated -> pass.
		tp9 := &fakeTransport{results: map[string]api.CommandResult{
			"cat /etc/os-release 2>/dev/null": osReleaseResult("rhel", "9.6"),
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
		}}
		r9, err := scan.New(nil).Scan(context.Background(), tp9, []*api.Rule{rhelMinRule("rule-rhel9b", 9)})
		if err != nil {
			t.Fatalf("rhel9 scan: %v", err)
		}
		if o := r9.Outcomes[0]; o.Status != api.CompliancePass {
			t.Errorf("rhel>=9 on rhel9: want pass, got %q", o.Status)
		}

		// (c) a rule with no platforms is evaluated regardless of OS.
		noPlat := sysctlRule("rule-noplat", "low", "net.ipv4.ip_forward", "0")
		rNo, err := scan.New(nil).Scan(context.Background(), tp8, []*api.Rule{noPlat})
		if err != nil {
			t.Fatalf("noplat scan: %v", err)
		}
		if o := rNo.Outcomes[0]; o.Status != api.CompliancePass {
			t.Errorf("no-platform rule on rhel8: want pass, got %q", o.Status)
		}

		// (d) undetectable OS must NOT gate (no os-release -> zero OSInfo).
		tpUnknown := &fakeTransport{results: map[string]api.CommandResult{
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
		}}
		rUnk, err := scan.New(nil).Scan(context.Background(), tpUnknown, []*api.Rule{rhelMinRule("rule-unk", 9)})
		if err != nil {
			t.Fatalf("unknown-OS scan: %v", err)
		}
		if o := rUnk.Outcomes[0]; o.Status == api.ComplianceSkipped {
			t.Errorf("undetectable OS must not gate: want evaluated, got skipped")
		}
	})
}

// TestScan_PopulatesOutcomeEvidence verifies the scan path surfaces the
// check's structured observation evidence on RuleOutcome.Evidence — the
// command and method that produced the verdict.
//
// @spec check-observation-evidence
func TestScan_PopulatesOutcomeEvidence(t *testing.T) {
	t.Run("check-observation-evidence/AC-04", func(t *testing.T) {
		// @spec check-observation-evidence
		// @ac AC-04
		tp := &fakeTransport{results: map[string]api.CommandResult{
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "1", ExitCode: 0}, // != expected 0 -> fail
		}}
		rule := sysctlRule("rule-ev", "medium", "net.ipv4.ip_forward", "0")
		res, err := scan.New(nil).Scan(context.Background(), tp, []*api.Rule{rule})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		o := res.Outcomes[0]
		if o.Status != api.ComplianceFail {
			t.Fatalf("want fail, got %q", o.Status)
		}
		if len(o.Evidence) != 1 {
			t.Fatalf("want 1 evidence entry on the outcome, got %d", len(o.Evidence))
		}
		ev := o.Evidence[0]
		if ev.Method != "sysctl_value" {
			t.Errorf("evidence method: want sysctl_value, got %q", ev.Method)
		}
		if ev.Command != "sysctl -n 'net.ipv4.ip_forward'" {
			t.Errorf("evidence command: got %q", ev.Command)
		}
		if ev.Stdout != "1" || ev.Expected != "0" {
			t.Errorf("evidence stdout/expected: got stdout=%q expected=%q", ev.Stdout, ev.Expected)
		}
	})
}

// TestRemediate_PlatformGate verifies the apply path is platform-gated too:
// a failing rule whose platforms don't cover the host must NEVER reach the
// engine — gating only the scan would still let remediate mutate a host with
// a non-applicable change.
//
// @spec scan-compliance-outcome
func TestRemediate_PlatformGate(t *testing.T) {
	t.Run("scan-compliance-outcome/AC-08", func(t *testing.T) {
		// @spec scan-compliance-outcome
		// @ac AC-08
		// The check would FAIL (sysctl returns 1, rule wants 0), so an ungated
		// remediate would invoke the engine. The host is rhel 8.10; the rule
		// targets rhel >= 9.
		failing := minimalRule("rule-rhel9-remediate")
		failing.Platforms = []api.Platform{{Family: "rhel", MinVersion: 9}}
		tp := &fakeTransport{results: map[string]api.CommandResult{
			"cat /etc/os-release 2>/dev/null": osReleaseResult("rhel", "8.10"),
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "1", ExitCode: 0},
		}}
		eng := &fakeEngine{}
		sink := &recordingSink{}
		runner := scan.New(eng, scan.WithProgress(sink))

		result, err := runner.Remediate(context.Background(), tp, []*api.Rule{failing})
		if err != nil {
			t.Fatalf("Remediate: %v", err)
		}
		if eng.runs != 0 {
			t.Fatalf("engine ran %d time(s) for a platform-skipped rule; must never run", eng.runs)
		}
		if len(result.Transactions) != 1 || result.Transactions[0].Status != api.StatusErrored {
			t.Errorf("want 1 errored transaction (skip seam), got %+v", result.Transactions)
		}
		if len(sink.got) != 1 || !sink.got[0].Skipped || sink.got[0].Errored {
			t.Errorf("want one Skipped progress update, got %+v", sink.got)
		}

		// Control: same failing rule on rhel 9 — the engine MUST run.
		tp9 := &fakeTransport{results: map[string]api.CommandResult{
			"cat /etc/os-release 2>/dev/null": osReleaseResult("rhel", "9.6"),
			"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "1", ExitCode: 0},
		}}
		if _, err := runner.Remediate(context.Background(), tp9, []*api.Rule{failing}); err != nil {
			t.Fatalf("rhel9 Remediate: %v", err)
		}
		if eng.runs != 1 {
			t.Errorf("engine should run exactly once on the in-platform host, ran %d", eng.runs)
		}
	})
}
