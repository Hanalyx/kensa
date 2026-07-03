package rule

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/mechanism"
)

func ruleWith(id string, rem api.Remediation) *api.Rule {
	return &api.Rule{
		ID:              id,
		Transactional:   false,
		Implementations: []api.Implementation{{Default: true, Remediation: rem}},
	}
}

// @spec rule-param-contract
// @ac AC-01
func TestRemediationParamErrors_RejectsWrongParamName(t *testing.T) {
	t.Run("rule-param-contract/AC-01", func(t *testing.T) {})
	// config_set with the handler's name "file" instead of the contract's "path".
	r := ruleWith("synthetic-bad", api.Remediation{
		Mechanism: "config_set",
		Params:    api.Params{"file": "/etc/x.conf", "key": "K", "value": "V"},
	})
	errs := RemediationParamErrors(r)
	if len(errs) == 0 {
		t.Fatal("expected a param-contract violation for config_set missing 'path'")
	}
	found := false
	for _, e := range errs {
		if e.Field == "implementations[0].remediation" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected error on implementations[0].remediation; got %v", errs)
	}
}

// @spec rule-param-contract
// @ac AC-02
func TestRemediationParamErrors_AcceptsConforming(t *testing.T) {
	t.Run("rule-param-contract/AC-02", func(t *testing.T) {})
	r := ruleWith("synthetic-good", api.Remediation{
		Mechanism: "config_set",
		Params:    api.Params{"path": "/etc/x.conf", "key": "K", "value": "V", "separator": "="},
	})
	if errs := RemediationParamErrors(r); len(errs) != 0 {
		t.Errorf("expected conforming, got %v", errs)
	}
}

// @spec rule-param-contract
// @ac AC-03
func TestRemediationParamErrors_SkipsAllowlistedRule(t *testing.T) {
	t.Run("rule-param-contract/AC-03", func(t *testing.T) {})
	// An allowlisted rule with deliberately-wrong params must produce no error.
	// shell-timeout is still on the ratchet allowlist (the param-rename
	// entries were drained); the skip keys off the ID, not the params.
	r := ruleWith("shell-timeout", api.Remediation{
		Mechanism: "sysctl_set",
		Params:    api.Params{"key": "k", "value": "v", "file": "/etc/sysctl.d/x.conf"},
	})
	if errs := RemediationParamErrors(r); len(errs) != 0 {
		t.Errorf("allowlisted rule should be skipped, got %v", errs)
	}
}

// TestKnownNonConformingRulesStillViolate is the ratchet: every allowlisted
// rule must still actually violate the contract when checked directly. When a
// rule is fixed it stops violating, this test fails, and the engineer must
// remove its allowlist entry — so the debt ledger cannot go stale.
//
// @spec rule-param-contract
// @ac AC-05
func TestKnownNonConformingRulesStillViolate(t *testing.T) {
	t.Run("rule-param-contract/AC-05", func(t *testing.T) {})
	corpus := loadCorpus(t)
	for id := range KnownNonConforming() {
		r, ok := corpus[id]
		if !ok {
			t.Errorf("allowlisted rule %q not found in corpus; remove the entry", id)
			continue
		}
		stillBad := false
		for i := range r.Implementations {
			rem := &r.Implementations[i].Remediation
			if rem.Mechanism == "" || !mechanism.Known(rem.Mechanism) {
				continue
			}
			keys := make([]string, 0, len(rem.Params))
			for k := range rem.Params {
				keys = append(keys, k)
			}
			if len(mechanism.ValidateParams(rem.Mechanism, keys)) > 0 {
				stillBad = true
			}
		}
		if !stillBad {
			t.Errorf("allowlisted rule %q now conforms; remove it from knownNonConformingRules", id)
		}
	}
}
