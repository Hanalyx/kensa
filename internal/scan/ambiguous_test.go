package scan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/check"
	"github.com/Hanalyx/kensa/internal/scan"
)

// auditWatchRule is an audit watch rule with a drop-in remediation, the
// shape of the corpus identity watches.
func auditWatchRule(id string) *api.Rule {
	return &api.Rule{
		ID: id, Severity: "medium", Transactional: true,
		Implementations: []api.Implementation{{
			Default: true,
			Check: api.Check{Method: "audit_rule_exists",
				Params: api.Params{"rule": "-w /etc/passwd -p wa -k identity"}},
			Remediation: api.Remediation{Mechanism: "audit_rule_set", Params: api.Params{
				"rule": "-w /etc/passwd -p wa -k identity", "persist_file": "/etc/audit/rules.d/50-identity.rules"}},
		}},
	}
}

// A pre-check that cannot show whether the host is already compliant must
// not change the host: on a host that loads the watch under the rule's own
// key and on one that loads it under another key, remediate never runs the
// engine and records the platform gate's skip seam. An unreadable ruleset is
// a different case and still reaches the engine.
//
// @spec scan-compliance-outcome
// @ac AC-10
func TestRemediate_AmbiguousPreCheckNeverReachesEngine(t *testing.T) {
	t.Run("scan-compliance-outcome/AC-10", func(t *testing.T) {
		for name, listing := range map[string]string{
			"same key":    "-w /etc/passwd -p wa -k identity",
			"another key": "-w /etc/passwd -p wa -k audit_rules_usergroup_modification",
		} {
			t.Run(name, func(t *testing.T) {
				tp := &fakeTransport{results: map[string]api.CommandResult{
					"auditctl -l": {Stdout: listing, ExitCode: 0}}}
				eng := &fakeEngine{}
				sink := &recordingSink{}
				res, err := scan.New(eng, scan.WithProgress(sink)).Remediate(context.Background(), tp,
					[]*api.Rule{auditWatchRule("audit-file-passwd")})
				if err != nil {
					t.Fatal(err)
				}
				if eng.runs != 0 {
					t.Fatalf("engine.Run reached %d times on an ambiguous pre-check", eng.runs)
				}
				tr := res.Transactions[0]
				if tr.Status != api.StatusErrored || !tr.HostUnchanged || tr.CommittedAt != nil || tr.AlreadyCompliant {
					t.Errorf("record: status=%s unchanged=%v committed=%v already=%v",
						tr.Status, tr.HostUnchanged, tr.CommittedAt, tr.AlreadyCompliant)
				}
				if !errors.Is(tr.Error, check.ErrAmbiguousEvidence) {
					t.Errorf("error does not carry the sentinel: %v", tr.Error)
				}
				skipped := false
				for _, u := range sink.got {
					skipped = skipped || u.Skipped
				}
				if !skipped {
					t.Error("no Skipped progress update")
				}
			})
		}
		tp := &fakeTransport{results: map[string]api.CommandResult{
			"auditctl -l": {ExitCode: 127, Stderr: "sh: auditctl: command not found"}}}
		eng := &fakeEngine{}
		if _, err := scan.New(eng).Remediate(context.Background(), tp, []*api.Rule{auditWatchRule("audit-file-passwd")}); err != nil {
			t.Fatal(err)
		}
		if eng.runs != 1 {
			t.Errorf("an unreadable ruleset reached the engine %d times, want 1 (unchanged behavior)", eng.runs)
		}
	})
}
