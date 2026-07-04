package rule

import (
	"fmt"
	"sort"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/mechanism"
)

// knownNonConformingRules is the ratcheting allowlist of corpus rules whose
// remediation params do not yet satisfy the mechanism contract
// (internal/mechanism). Each entry is documented debt surfaced by the param
// contract gate; the validator skips these so CI stays green, and
// TestKnownNonConformingRulesStillViolate asserts every entry still violates —
// so a fixed rule forces removal of its entry.
//
// EMPTY: fully drained — every corpus rule's remediation params satisfy the
// mechanism contract. shell-timeout and sudo-timeout (the last two) were
// converted from content-form config_set_dropin to file_content. Add an entry
// only as a temporary, test-guarded escape hatch for a genuinely-blocked rule.
var knownNonConformingRules = map[string]string{}

// validateRemediationParams checks every remediation (single and multi-step)
// against the mechanism parameter contract. It is constraint (9) of Validate.
//
// Rules in knownNonConformingRules are skipped (documented debt). Mechanisms
// with no contract are skipped here — unknown-mechanism is already an atomicity
// concern handled elsewhere; this check is purely about parameter names.
func validateRemediationParams(r *api.Rule, add func(field, msg string)) {
	if _, skip := knownNonConformingRules[r.ID]; skip {
		return
	}
	for i := range r.Implementations {
		rem := &r.Implementations[i].Remediation
		if rem.Mechanism != "" && mechanism.Known(rem.Mechanism) {
			checkParams(fmt.Sprintf("implementations[%d].remediation", i), rem.Mechanism, rem.Params, add)
		}
		for j := range rem.Steps {
			st := &rem.Steps[j]
			if st.Mechanism != "" && mechanism.Known(st.Mechanism) {
				field := fmt.Sprintf("implementations[%d].remediation.steps[%d]", i, j)
				checkParams(field, st.Mechanism, st.Params, add)
			}
		}
	}
}

// RemediationParamErrors runs only constraint (9) — the mechanism parameter
// contract check — and returns the violations. It respects
// knownNonConformingRules. Exposed for the corpus↔handler integration test.
func RemediationParamErrors(r *api.Rule) []ValidationError {
	var errs []ValidationError
	validateRemediationParams(r, func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Msg: msg})
	})
	return errs
}

// KnownNonConforming returns a copy of the ratcheting allowlist of corpus rules
// whose remediation params do not yet satisfy the mechanism contract.
func KnownNonConforming() map[string]string {
	out := make(map[string]string, len(knownNonConformingRules))
	for k, v := range knownNonConformingRules {
		out[k] = v
	}
	return out
}

func checkParams(field, mech string, params api.Params, add func(field, msg string)) {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, problem := range mechanism.ValidateParams(mech, keys) {
		add(field, problem)
	}
}
