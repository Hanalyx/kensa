package rule

import (
	"fmt"
	"sort"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/check"
)

// knownNonConformingCheckRules is the ratcheting allowlist of corpus rules whose
// CHECK params do not satisfy the check-method contract (internal/check.
// CheckContracts). Each entry is a silently-broken rule found by the
// closed-world check-param gate (constraint 10): the engine reads none of the
// flagged param, so the rule's intent is silently dropped.
//
// This is the check-side analog of knownNonConformingRules. It ratchets: the
// corpus test fails if a listed rule no longer violates (entry is stale, remove
// it) or if a NON-listed rule starts violating (a regression). Fixing a rule
// (e.g. implementing 'comparator', or correcting 'state'->'active') removes its
// entry here.
var knownNonConformingCheckRules = map[string]string{
	// The 19 'comparator' rules left this allowlist when the comparator engine
	// landed (check.go compareValue + contract Optional + value-domain). They
	// now conform.
	//
	// 'glob' declared on a file_permission check that never reads it.
	"ssh-private-key-permissions": "file_permission declares unread 'glob'",
	"ssh-public-key-permissions":  "file_permission declares unread 'glob'",
	// typo / wrong-method params that the check silently ignores.
	"coredump-socket-disabled":    "command declares unread 'expected_enabled'",
	"usbguard-block-unauthorized": "service_state declares unread 'state' (should be active:true)",
}

// validateCheckParams is constraint (10): every check's params satisfy the
// check-method contract (internal/check.CheckContracts), closed-world. Rules in
// knownNonConformingCheckRules are skipped (tracked debt).
func validateCheckParams(r *api.Rule, add func(field, msg string)) {
	if _, skip := knownNonConformingCheckRules[r.ID]; skip {
		return
	}
	for i := range r.Implementations {
		walkCheck(fmt.Sprintf("implementations[%d].check", i), &r.Implementations[i].Check, add)
	}
}

// walkCheck validates one check node and recurses into composed sub-checks.
func walkCheck(field string, c *api.Check, add func(field, msg string)) {
	if len(c.Checks) > 0 {
		for j := range c.Checks {
			walkCheck(fmt.Sprintf("%s.checks[%d]", field, j), &c.Checks[j], add)
		}
		return
	}
	if c.Method == "" {
		return
	}
	keys := make([]string, 0, len(c.Params))
	for k := range c.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, problem := range check.ValidateCheckParams(c.Method, keys) {
		add(field, problem)
	}
}

// CheckParamErrors runs only constraint (10) and returns the violations,
// respecting knownNonConformingCheckRules. Exposed for the corpus integration
// test (the check-side ratchet).
func CheckParamErrors(r *api.Rule) []ValidationError {
	var errs []ValidationError
	validateCheckParams(r, func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Msg: msg})
	})
	return errs
}

// KnownNonConformingCheck returns a copy of the check-param ratchet allowlist.
func KnownNonConformingCheck() map[string]string {
	out := make(map[string]string, len(knownNonConformingCheckRules))
	for k, v := range knownNonConformingCheckRules {
		out[k] = v
	}
	return out
}
