package engine

import (
	"context"

	"github.com/Hanalyx/kensa-go/api"
)

// validate runs the post-apply validators during the VALIDATE phase.
//
// Three categories of validator run here:
//
//  1. Injected validators, registered via [WithValidators]. These run
//     for every transaction against this engine instance, regardless
//     of mechanism. Callers wire service-health and config-syntax
//     validators here when the rule's post-apply check is known at
//     engine construction time (e.g. via the CLI rule loader).
//
//  2. Built-in control-channel-reachability validator, activated
//     automatically when the transaction contains a control-channel-
//     sensitive mechanism (pam_module_configure, service_enabled, etc.).
//     It runs `true` on the transport to confirm the SSH session survived
//     the change.
//
//  3. kensa-fuzz forced failure (when [WithForceValidateFail] is set),
//     which always returns false so the harness can drive the
//     apply→validate-fail→rollback path without a real rule.
//
// TODO(week-21): wire api.Rule.Implementations[selected].Check through
// internal/checks and run the post-apply re-check.
func (e *Engine) validate(ctx context.Context, transport api.Transport, txn *api.Transaction) ([]api.ValidatorResult, bool) {
	if e.forceValidateFail {
		return []api.ValidatorResult{{
			Name:   "kensa-fuzz-injected",
			Passed: false,
			Detail: "kensa-fuzz: injected validate failure",
		}}, false
	}

	// Collect validators to run: injected first, then built-ins.
	vs := make([]Validator, 0, len(e.validators)+1)
	vs = append(vs, e.validators...)

	// Auto-activate control-channel-reachability for CC-sensitive transactions.
	if shouldArmDeadman(txn, e.registry) {
		vs = append(vs, ControlChannelValidator{})
	}

	if len(vs) == 0 {
		// No validators configured and not CC-sensitive: treat successful
		// apply as successful validate (pre-rule-parser behavior).
		return nil, true
	}

	results := make([]api.ValidatorResult, 0, len(vs))
	allPassed := true
	for _, v := range vs {
		r := v.Validate(ctx, transport, txn)
		results = append(results, r)
		if !r.Passed {
			allPassed = false
		}
	}
	return results, allPassed
}
