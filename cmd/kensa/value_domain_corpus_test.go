package main

import (
	"sort"
	"testing"

	"github.com/Hanalyx/kensa/internal/rule"
)

// TestValueDomainCorpusRatchet is the value-domain ratchet: the set of corpus
// rules with out-of-domain param values must equal knownValueDomainViolators
// exactly. A NEW out-of-domain value (unlisted) or a STALE entry (now in
// domain) fails CI, forcing the allowlist to shrink as rules are fixed.
//
// @spec value-domains
// @ac AC-03
func TestValueDomainCorpusRatchet(t *testing.T) {
	t.Run("value-domains/AC-03", func(t *testing.T) {})
	rules := loadCorpusRules(t)
	allow := rule.KnownValueDomainViolators()

	violators := map[string]bool{}
	for _, r := range rules {
		// ValueDomainErrors respects the allowlist, so to find the true
		// violator set we temporarily treat every rule as non-allowlisted by
		// checking with a rule whose ID isn't in the allowlist would skip the
		// walk. Instead, reconstruct via the exported errors on a shallow copy
		// with a sentinel ID.
		probe := *r
		probe.ID = "__ratchet_probe__"
		if len(rule.ValueDomainErrors(&probe)) > 0 {
			violators[r.ID] = true
		}
	}

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
		t.Errorf("NEW value-domain violation(s) not in the ratchet (fix the rule or add a tracked entry): %v", newViol)
	}
	if len(stale) > 0 {
		t.Errorf("STALE value-domain ratchet entries (rule now in-domain — remove): %v", stale)
	}
}
