package scan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/check"
	"github.com/Hanalyx/kensa/internal/scan"
)

// multiRule is the audit watch rule with its check composed from children.
func multiRule(chk api.Check) *api.Rule {
	r := auditWatchRule("audit-multi")
	r.Implementations[0].Check = chk
	return r
}

// The two children: an audit watch whose listing is ambiguous, and a check
// that fails with a plain error.
var (
	ambiguousChild = api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": "-w /etc/passwd -p wa -k identity"}}
	erroredChild   = api.Check{Method: "file_exists", Params: api.Params{}}
)

func multiTransport() *fakeTransport {
	return &fakeTransport{results: map[string]api.CommandResult{
		"auditctl -l": {Stdout: "-w /etc/passwd -p wa -k identity", ExitCode: 0}}}
}

// A multi check whose children include an ambiguous audit check never lets
// remediate run the engine, whichever child comes first and when it is
// nested one level down. A scan of the same check reports an error, not a
// skip: one not-assessable child must not hide another child's error.
//
// @spec scan-compliance-outcome
// @ac AC-11
func TestRemediate_AmbiguousChildAnyPosition(t *testing.T) {
	t.Run("scan-compliance-outcome/AC-11", func(t *testing.T) {
		for name, chk := range map[string]api.Check{
			"ambiguous first":  {Checks: []api.Check{ambiguousChild, erroredChild}},
			"ambiguous second": {Checks: []api.Check{erroredChild, ambiguousChild}},
			"nested second":    {Checks: []api.Check{erroredChild, {Checks: []api.Check{erroredChild, ambiguousChild}}}},
		} {
			eng := &fakeEngine{}
			res, err := scan.New(eng).Remediate(context.Background(), multiTransport(), []*api.Rule{multiRule(chk)})
			if err != nil {
				t.Fatal(err)
			}
			if eng.runs != 0 {
				t.Errorf("%s: engine.Run reached %d times", name, eng.runs)
			}
			if tr := res.Transactions[0]; !errors.Is(tr.Error, check.ErrAmbiguousEvidence) || !tr.HostUnchanged {
				t.Errorf("%s: record error=%v unchanged=%v", name, tr.Error, tr.HostUnchanged)
			}
			sres, err := scan.New(&fakeEngine{}).Scan(context.Background(), multiTransport(), []*api.Rule{multiRule(chk)})
			if err != nil {
				t.Fatal(err)
			}
			if got := sres.Outcomes[0].Status; got != api.ComplianceError {
				t.Errorf("%s: scan status %s, want error", name, got)
			}
		}
		// Ambiguity two levels down, behind an error at each level.
		deep := api.Check{Checks: []api.Check{erroredChild, {Checks: []api.Check{erroredChild, {Checks: []api.Check{ambiguousChild}}}}}}
		eng := &fakeEngine{}
		if _, err := scan.New(eng).Remediate(context.Background(), multiTransport(), []*api.Rule{multiRule(deep)}); err != nil {
			t.Fatal(err)
		}
		if eng.runs != 0 {
			t.Errorf("nested two levels: engine.Run reached %d times", eng.runs)
		}
		// A child that conclusively fails decides the AND: the rule is not
		// compliant, so remediate runs, and a scan reports fail.
		failing := api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": "-a always,exit -F arch=b64 -S chmod -k missing"}}
		withFail := api.Check{Checks: []api.Check{ambiguousChild, failing}}
		eng = &fakeEngine{}
		if _, err := scan.New(eng).Remediate(context.Background(), multiTransport(), []*api.Rule{multiRule(withFail)}); err != nil {
			t.Fatal(err)
		}
		if eng.runs != 1 {
			t.Errorf("an ambiguous child beside a failing one: engine.Run reached %d times, want 1", eng.runs)
		}
		fres, err := scan.New(&fakeEngine{}).Scan(context.Background(), multiTransport(), []*api.Rule{multiRule(withFail)})
		if err != nil {
			t.Fatal(err)
		}
		if got := fres.Outcomes[0].Status; got != api.ComplianceFail {
			t.Errorf("an ambiguous child beside a failing one: scan status %s, want fail", got)
		}
		// Every child undecided: the scan reports skipped.
		both := api.Check{Checks: []api.Check{ambiguousChild, {Checks: []api.Check{ambiguousChild}}}}
		sres, err := scan.New(&fakeEngine{}).Scan(context.Background(), multiTransport(), []*api.Rule{multiRule(both)})
		if err != nil {
			t.Fatal(err)
		}
		if got := sres.Outcomes[0].Status; got != api.ComplianceSkipped {
			t.Errorf("all children ambiguous: scan status %s, want skipped", got)
		}
	})
}
