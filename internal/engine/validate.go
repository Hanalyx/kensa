package engine

import (
	"context"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/check"
)

// validate runs the post-apply checks during the VALIDATE phase and
// returns the per-check results plus an overall pass/fail. A false return
// drives the engine to roll the transaction back.
//
// Four categories run here:
//
//  1. The mandatory post-apply desired-state RE-CHECK: the rule's own
//     check (txn.Check) is re-run against the live
//     host to confirm the apply actually achieved the rule's intent. A
//     clean Passed==false drives rollback. Crucially ERROR != FAIL — a
//     transport/tool error on the re-read yields committed-but-unverified,
//     never an automatic rollback (a read we could not perform is not
//     evidence the change failed). Disabled by WithPostApplyRecheck(false).
//
//  2. Injected validators, registered via [WithValidators] — service-health
//     / config-syntax verifiers wired at engine-construction time.
//
//  3. Built-in control-channel-reachability validator, auto-activated for
//     control-channel-sensitive transactions; runs `true` on the transport
//     to confirm the SSH session survived the change.
//
//  4. kensa-fuzz forced failure ([WithForceValidateFail]), which always
//     fails so the harness can drive the apply→validate-fail→rollback path.
//
// Privilege symmetry: the re-check runs over the same transport the
// pre-check used to decide the rule was non-compliant, so it reads with the
// same privilege the pre-check had. Note this is NOT necessarily the
// privilege the APPLY had: in agent mode apply runs as root via the agent
// while the check reads over the SSH transport (e.g. owadmin). If an apply
// makes a file root-only-readable, the unprivileged re-read typically
// surfaces as a clean non-match (exit 1 -> Passed:false), NOT a transport
// error, so ERROR != FAIL does NOT rescue it — it drives a rollback of an
// otherwise-correct change. That reversal is byte-perfect (the host returns
// to its pre-apply state, never damaged), but it is a real correctness/
// convergence concern handled by the corpus check/remediation audit and the
// WithPostApplyRecheck kill-switch, not by ERROR != FAIL.
func (e *Engine) validate(ctx context.Context, transport api.Transport, txn *api.Transaction) ([]api.ValidatorResult, bool) {
	if e.forceValidateFail {
		return []api.ValidatorResult{{
			Name:   "kensa-fuzz-injected",
			Passed: false,
			Detail: "kensa-fuzz: injected validate failure",
		}}, false
	}

	results := make([]api.ValidatorResult, 0, len(e.validators)+2)
	allPassed := true

	// 1. Mandatory post-apply desired-state re-check.
	if e.postApplyRecheck && hasCheck(txn.Check) {
		vr := e.recheck(ctx, transport, txn.Check)
		results = append(results, vr)
		if !vr.Passed {
			allPassed = false
		}
	}

	// 2-3. Injected validators, then the built-in CC-reachability validator.
	vs := make([]Validator, 0, len(e.validators)+1)
	vs = append(vs, e.validators...)
	if shouldArmDeadman(txn, e.registry) {
		vs = append(vs, ControlChannelValidator{})
	}
	for _, v := range vs {
		r := v.Validate(ctx, transport, txn)
		results = append(results, r)
		if !r.Passed {
			allPassed = false
		}
	}

	if len(results) == 0 {
		// Nothing to verify (no check, no validators, not CC-sensitive):
		// treat a successful apply as a successful validate.
		return nil, true
	}
	return results, allPassed
}

// recheck re-runs the rule's own check against the live host and maps the
// outcome onto a ValidatorResult under the ERROR != FAIL rule:
//
//   - check errored (transport/tool failure) → Passed:true, committed-but-
//     unverified. A read we could not perform is NOT evidence the change
//     failed; never roll back a correct change over an unreadable re-check.
//   - check Passed                            → Passed:true, verified.
//   - check cleanly returned not-passing      → Passed:false, drives rollback.
func (e *Engine) recheck(ctx context.Context, transport api.Transport, chk api.Check) api.ValidatorResult {
	res, err := check.Run(ctx, transport, chk)
	vr := api.ValidatorResult{Name: "post-apply-recheck", Evidence: res.Detail}
	switch {
	case err != nil:
		vr.Passed = true
		vr.Detail = "unverified: post-apply re-check could not read host state (ERROR != FAIL, change left applied): " + err.Error()
	case res.Passed:
		vr.Passed = true
		vr.Detail = "verified: rule check passes after apply"
	default:
		vr.Passed = false
		vr.Detail = "rule check still fails after apply: " + res.Detail
	}
	return vr
}

// hasCheck reports whether a check is actually specified (a method or at
// least one sub-check). An empty check means no post-apply verification.
func hasCheck(chk api.Check) bool {
	return chk.Method != "" || len(chk.Checks) > 0
}
