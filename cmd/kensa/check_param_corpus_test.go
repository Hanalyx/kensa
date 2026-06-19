package main

import (
	"sort"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/check"
	"github.com/Hanalyx/kensa/internal/rule"
)

// rawCheckViolators returns the set of corpus rule IDs whose check params
// violate the check-method contract, computed WITHOUT the ratchet allowlist
// (so it detects both new violations and stale allowlist entries).
func rawCheckViolators(rules []*api.Rule) map[string]bool {
	out := map[string]bool{}
	var walk func(c *api.Check) bool
	walk = func(c *api.Check) bool {
		if len(c.Checks) > 0 {
			bad := false
			for j := range c.Checks {
				if walk(&c.Checks[j]) {
					bad = true
				}
			}
			return bad
		}
		if c.Method == "" {
			return false
		}
		keys := make([]string, 0, len(c.Params))
		for k := range c.Params {
			keys = append(keys, k)
		}
		return len(check.ValidateCheckParams(c.Method, keys)) > 0
	}
	for _, r := range rules {
		for i := range r.Implementations {
			if walk(&r.Implementations[i].Check) {
				out[r.ID] = true
			}
		}
	}
	return out
}

// TestCheckParamCorpusRatchet is the Layer-3 check-side ratchet: the set of
// rules that actually violate the check-method contract must equal the
// knownNonConformingCheckRules allowlist exactly. A NEW violation (unlisted)
// or a STALE entry (listed but now conforming) fails CI — forcing the
// allowlist to shrink monotonically as rules are fixed.
//
// @spec check-param-contract
// @ac AC-04
func TestCheckParamCorpusRatchet(t *testing.T) {
	t.Run("check-param-contract/AC-04", func(t *testing.T) {})
	rules := loadCorpusRules(t)
	violators := rawCheckViolators(rules)
	allow := rule.KnownNonConformingCheck()

	var newViol, stale []string
	for id := range violators {
		if _, ok := allow[id]; !ok {
			newViol = append(newViol, id)
		}
	}
	for id := range allow {
		if !violators[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(newViol)
	sort.Strings(stale)
	if len(newViol) > 0 {
		t.Errorf("NEW check-param violation(s) not in the ratchet allowlist (fix the rule or add a tracked entry): %v", newViol)
	}
	if len(stale) > 0 {
		t.Errorf("STALE ratchet entries (rule now conforms — remove from knownNonConformingCheckRules): %v", stale)
	}
}

// TestValidateCheckParams_Constraint10 confirms constraint (10) is wired into
// the rule validator: a non-allowlisted rule with an unknown check param fails
// validation; an allowlisted rule passes.
//
// @spec check-param-contract
// @ac AC-03
func TestValidateCheckParams_Constraint10(t *testing.T) {
	t.Run("check-param-contract/AC-03", func(t *testing.T) {})
	mk := func(id string) *api.Rule {
		return &api.Rule{
			ID: id,
			Implementations: []api.Implementation{{
				Check: api.Check{Method: "config_value", Params: api.Params{
					"path": "/etc/x", "key": "K", "expected": "1", "bogus_param": "x",
				}},
			}},
		}
	}
	// non-allowlisted: a genuinely-unknown check param must be flagged by (10).
	if errs := rule.CheckParamErrors(mk("not-an-allowlisted-rule")); len(errs) == 0 {
		t.Error("non-allowlisted rule with unknown 'bogus_param' must fail constraint (10)")
	}
	// allowlisted: skipped (tracked debt — ssh-private-key-permissions is still
	// ratcheted for its unread 'glob').
	if errs := rule.CheckParamErrors(mk("ssh-private-key-permissions")); len(errs) != 0 {
		t.Errorf("allowlisted rule must be skipped by constraint (10); got %v", errs)
	}
}
