package rule

import (
	"fmt"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/handlers/configset"
)

// Value-domain validation (constraint 11) is the layer the param-KEY validators
// never had: it checks param VALUES against the closed sets the engine actually
// accepts. Before it, config_set separators like "\t"/"\t\t" passed validation
// (separator is an allowed KEY) and only errored at Capture on a live host; and
// package_state checks with state:"installed" silently never matched.
//
// Each domain is grounded in the engine source:
//   - config_set.separator: SSOT is configset.SeparatorValues() (the handler's
//     own accepted set — imported so the two cannot drift).
//   - the check-method state enums are the exact case/== values in check.go's
//     checkApparmorState / checkKernelModuleState / checkPackageState.

// checkValueDomains maps a check method + param to its allowed values.
var comparatorOps = []string{"==", "!=", "<", "<=", ">", ">="} // check.go compareValue

var checkValueDomains = map[string]map[string][]string{
	"apparmor_state":      {"state": {"enforcing", "loaded"}},     // check.go checkApparmorState
	"kernel_module_state": {"state": {"blacklisted", "disabled"}}, // check.go checkKernelModuleState
	"package_state":       {"state": {"absent", "present"}},       // check.go checkPackageState
	"config_value":        {"comparator": comparatorOps},          // check.go compareValue
	"sysctl_value":        {"comparator": comparatorOps},          // check.go compareValue
}

// mechanismValueDomains maps a remediation mechanism + param to its allowed
// values. config_set.separator is sourced from the handler's SSOT.
var mechanismValueDomains = map[string]map[string][]string{
	"config_set": {"separator": configset.SeparatorValues()},
}

// knownValueDomainViolators is the ratcheting allowlist of corpus rules whose
// param VALUES are outside the engine's accepted domain — tracked debt found by
// constraint (11). It ratchets exactly like the other allowlists.
var knownValueDomainViolators = map[string]string{
	// config_set separator '' (valueless flag) — the key alone enables the
	// setting (faillock.conf / pwquality.conf), which config_set's key<sep>value
	// shape can't express; convert to file_content.
	"pam-faillock-audit":     "config_set separator '' (valueless flag — convert to file_content)",
	"pwquality-root-enforce": "config_set separator '' (valueless flag — convert to file_content)",
}

// validateValueDomains is constraint (11): every check/remediation param value
// is within the engine's accepted domain. Rules in knownValueDomainViolators
// are skipped (tracked debt).
func validateValueDomains(r *api.Rule, add func(field, msg string)) {
	if _, skip := knownValueDomainViolators[r.ID]; skip {
		return
	}
	for i := range r.Implementations {
		walkCheckDomains(fmt.Sprintf("implementations[%d].check", i), &r.Implementations[i].Check, add)
		rem := &r.Implementations[i].Remediation
		if rem.Mechanism != "" {
			checkValueSet(fmt.Sprintf("implementations[%d].remediation", i), mechanismValueDomains[rem.Mechanism], rem.Params, add)
		}
		for j := range rem.Steps {
			st := &rem.Steps[j]
			checkValueSet(fmt.Sprintf("implementations[%d].remediation.steps[%d]", i, j), mechanismValueDomains[st.Mechanism], st.Params, add)
		}
	}
}

func walkCheckDomains(field string, c *api.Check, add func(field, msg string)) {
	if len(c.Checks) > 0 {
		for j := range c.Checks {
			walkCheckDomains(fmt.Sprintf("%s.checks[%d]", field, j), &c.Checks[j], add)
		}
		return
	}
	if c.Method == "" {
		return
	}
	checkValueSet(field, checkValueDomains[c.Method], c.Params, add)
}

// checkValueSet validates each param's value against its domain (if any).
func checkValueSet(field string, domains map[string][]string, params api.Params, add func(field, msg string)) {
	if domains == nil {
		return
	}
	for param, allowed := range domains {
		raw, ok := params[param]
		if !ok {
			continue
		}
		val := fmt.Sprintf("%v", raw)
		if !valueInSet(allowed, val) {
			add(field, fmt.Sprintf("param '%s' value %q is not in the allowed set %v", param, val, allowed))
		}
	}
}

func valueInSet(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// ValueDomainErrors runs only constraint (11), respecting the allowlist.
// Exposed for the corpus ratchet test.
func ValueDomainErrors(r *api.Rule) []ValidationError {
	var errs []ValidationError
	validateValueDomains(r, func(field, msg string) {
		errs = append(errs, ValidationError{Field: field, Msg: msg})
	})
	return errs
}

// KnownValueDomainViolators returns a copy of the value-domain ratchet allowlist.
func KnownValueDomainViolators() map[string]string {
	out := make(map[string]string, len(knownValueDomainViolators))
	for k, v := range knownValueDomainViolators {
		out[k] = v
	}
	return out
}
