// Package scan implements the read-only compliance scan and multi-rule
// remediation pipeline that back [api.Kensa.Scan] and
// [api.Kensa.Remediate].
//
// The pipeline for each rule is:
//
//  1. Select the best implementation from the rule using the host's
//     detected [api.CapabilitySet] (via [internal/rule.Select]).
//  2. Run the implementation's check via [internal/check.Run].
//  3. For [Remediate]: if the check fails, build an [api.Transaction]
//     from the selected implementation's remediation block and run it
//     through the engine.
package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/check"
	"github.com/Hanalyx/kensa/internal/detect"
	"github.com/Hanalyx/kensa/internal/mappings"
	"github.com/Hanalyx/kensa/internal/progress"
	"github.com/Hanalyx/kensa/internal/rule"
)

// Runner executes compliance scans and remediations over an SSH transport.
type Runner struct {
	// engine backs remediations. When nil, Remediate returns an error.
	engine api.Engine
	// progress is the optional display sink. When nil, no progress is
	// emitted and behavior is byte-identical to a Runner with no sink.
	progress progress.Sink
	// hostID stamps each remediation transaction (and its crash-recovery
	// journal entry) with the target host, so host-scoped recovery can find
	// it. Empty leaves Transaction.HostID empty (the prior behavior).
	hostID string
}

// Option configures a [Runner] at construction time.
type Option func(*Runner)

// WithProgress wires a progress [progress.Sink] into the Runner so that
// ScanWithOverrides emits a per-rule RuleChecked Update. Passing a nil sink
// (or omitting the option entirely) leaves the Runner's behavior
// byte-identical to today — the sink is the only added effect, and delivery
// is nil-safe via [progress.Emit].
func WithProgress(sink progress.Sink) Option {
	return func(r *Runner) { r.progress = sink }
}

// WithHostID stamps every remediation transaction (and thus its
// crash-recovery journal entry) with hostID, so `kensa recover -H host` finds
// the right entries. Omitting it leaves Transaction.HostID empty.
func WithHostID(hostID string) Option {
	return func(r *Runner) { r.hostID = hostID }
}

// New returns a Runner. Pass a non-nil engine to enable Remediate, and
// optionally one or more [Option]s (e.g. [WithProgress]). With no options the
// Runner emits no progress and behaves exactly as before this seam was added.
func New(eng api.Engine, opts ...Option) *Runner {
	r := &Runner{engine: eng}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Scan checks every rule against the host reachable via transport and
// returns per-rule check results. No mutation of the host occurs.
func (r *Runner) Scan(ctx context.Context, transport api.Transport, rules []*api.Rule) (*api.ScanResult, error) {
	return r.ScanWithOverrides(ctx, transport, rules, nil)
}

// ScanWithOverrides is the C-028 capability-override variant of
// [Scan]. After capability probes run, every key in `overrides`
// replaces the detected value before rule selection. Pass nil
// (or an empty map) for the legacy "use detected verbatim"
// behavior — Scan above does exactly that.
func (r *Runner) ScanWithOverrides(ctx context.Context, transport api.Transport, rules []*api.Rule, overrides api.CapabilitySet) (*api.ScanResult, error) {
	detected, err := detect.Detect(ctx, transport)
	if err != nil {
		return nil, fmt.Errorf("scan: detect capabilities: %w", err)
	}
	caps := detect.ApplyOverrides(detected, overrides)

	// Detect the host OS so we can platform-gate rules. A transport error here
	// must NOT abort the scan or silently skip everything: fall back to a zero
	// OSInfo, which detect.AppliesTo treats as "applies" (no gating). OpenWatch
	// may pre-filter by platform upstream; this is the standalone-CLI safety net.
	osInfo, osErr := detect.DetectOS(ctx, transport)
	if osErr != nil {
		osInfo = detect.OSInfo{}
	}

	hostID := "" // transport does not expose hostname; populated by caller
	result := &api.ScanResult{
		HostID:       hostID,
		Capabilities: caps,
		Platform:     api.DetectedPlatform{Family: osInfo.Family, Version: osInfo.Version},
	}

	total := len(rules)
	for i, rl := range rules {
		// FrameworkRefs is normalised from the rule's References block via the
		// internal mappings package (unreachable from external api consumers),
		// so every outcome carries its compliance-framework mapping and a
		// consumer never has to re-join the corpus to learn it.
		frameworkRefs := mappings.RefsFromReferences(rl.References)

		// Platform applicability: a rule scoped to an OS the host is not (e.g.
		// rhel >= 9 evaluated on rhel 8) is skipped, not evaluated — so a CLI
		// user gets a SKIP rather than a misleading pass/fail. Undetectable
		// hosts are never gated (AppliesTo returns true).
		if !detect.AppliesTo(rl.Platforms, osInfo) {
			detail := platformSkipDetail(rl, osInfo)
			result.Transactions = append(result.Transactions, erroredResult(rl, errors.New(detail)))
			result.Outcomes = append(result.Outcomes, api.RuleOutcome{
				RuleID:        rl.ID,
				Status:        api.ComplianceSkipped,
				Severity:      rl.Severity,
				Detail:        detail,
				FrameworkRefs: frameworkRefs,
			})
			r.emit(progress.Update{
				Kind: progress.RuleChecked, RuleID: rl.ID,
				Index: i + 1, Total: total, OK: false, Skipped: true, Detail: detail,
			})
			continue
		}

		impl, err := rule.Select(rl, caps)
		if err != nil {
			result.Transactions = append(result.Transactions, erroredResult(rl, err))
			// A rule with no applicable implementation (no gate matched AND no
			// default) is not-applicable to this host (skipped), not an error;
			// a structurally invalid `when` IS a genuine error. The Transactions
			// entry stays StatusErrored for backward compatibility, but Outcomes
			// carries the precise verdict so a consumer never records a
			// not-applicable rule as an error.
			skipped := errors.Is(err, rule.ErrNoImplementation)
			outcome := api.RuleOutcome{RuleID: rl.ID, Severity: rl.Severity, FrameworkRefs: frameworkRefs}
			if skipped {
				outcome.Status = api.ComplianceSkipped
				outcome.Detail = "no applicable implementation for this host"
			} else {
				outcome.Status = api.ComplianceError
				outcome.Detail = err.Error()
				outcome.Err = err
			}
			result.Outcomes = append(result.Outcomes, outcome)
			// Progress mirrors the verdict: a no-default rule is SKIP, a
			// structurally invalid `when` is ERROR.
			r.emit(progress.Update{
				Kind: progress.RuleChecked, RuleID: rl.ID,
				Index: i + 1, Total: total, OK: false, Skipped: skipped, Errored: !skipped, Detail: outcome.Detail,
			})
			continue
		}

		checkRes, checkErr := check.Run(ctx, transport, impl.Check)
		passed, detail := checkRes.Passed, checkRes.Detail
		if checkErr != nil {
			result.Transactions = append(result.Transactions, erroredResult(rl, checkErr))
			result.Outcomes = append(result.Outcomes, api.RuleOutcome{
				RuleID:        rl.ID,
				Status:        api.ComplianceError,
				Severity:      rl.Severity,
				Detail:        checkErr.Error(),
				Err:           checkErr,
				FrameworkRefs: frameworkRefs,
				Evidence:      checkRes.Evidence,
			})
			r.emit(progress.Update{
				Kind: progress.RuleChecked, RuleID: rl.ID,
				Index: i + 1, Total: total, OK: false, Errored: true, Detail: checkErr.Error(),
			})
			continue
		}

		r.emit(progress.Update{
			Kind: progress.RuleChecked, RuleID: rl.ID,
			Index: i + 1, Total: total, OK: passed, Detail: detail,
		})

		// committed/rolled_back overload kept on Transactions for back-compat;
		// Outcomes carries the canonical pass/fail verdict.
		status := api.StatusRolledBack // "not compliant"
		complianceStatus := api.ComplianceFail
		if passed {
			status = api.StatusCommitted // "compliant"
			complianceStatus = api.CompliancePass
		}
		result.Outcomes = append(result.Outcomes, api.RuleOutcome{
			RuleID:        rl.ID,
			Status:        complianceStatus,
			Severity:      rl.Severity,
			Detail:        detail,
			FrameworkRefs: frameworkRefs,
			Evidence:      checkRes.Evidence,
		})
		result.Transactions = append(result.Transactions, api.TransactionResult{
			TransactionID: uuid.New(),
			Status:        status,
			StartedAt:     time.Now().UTC(),
			FinishedAt:    time.Now().UTC(),
			Steps: []api.StepResult{{
				StepIndex:  0,
				Mechanism:  "check",
				Capturable: false,
				Success:    passed,
				Detail:     detail,
			}},
		})
	}
	return result, nil
}

// Remediate checks every rule and runs full transactions for each that
// fails the check. Rules that already pass are skipped. Returns the
// combined check+remediation results.
func (r *Runner) Remediate(ctx context.Context, transport api.Transport, rules []*api.Rule) (*api.RemediationResult, error) {
	return r.RemediateWithOverrides(ctx, transport, rules, nil)
}

// RemediateWithOverrides is the C-028 capability-override variant
// of [Remediate]. See [ScanWithOverrides] for semantics.
func (r *Runner) RemediateWithOverrides(ctx context.Context, transport api.Transport, rules []*api.Rule, overrides api.CapabilitySet) (*api.RemediationResult, error) {
	if r.engine == nil {
		return nil, fmt.Errorf("scan: engine not wired, cannot remediate")
	}

	detected, err := detect.Detect(ctx, transport)
	if err != nil {
		return nil, fmt.Errorf("scan: detect capabilities: %w", err)
	}
	caps := detect.ApplyOverrides(detected, overrides)

	// Platform-gate remediation exactly like Scan — and more importantly so:
	// an ungated remediate would APPLY a non-applicable rule's remediation to
	// the host (e.g. a rhel>=9 change on rhel 8), not just misreport a verdict.
	// Same leniency: undetectable OS gates nothing.
	osInfo, osErr := detect.DetectOS(ctx, transport)
	if osErr != nil {
		osInfo = detect.OSInfo{}
	}

	hostID := r.hostID
	result := &api.RemediationResult{HostID: hostID}

	total := len(rules)
	for i, rl := range rules {
		// A rule whose platforms don't cover this host is skipped BEFORE any
		// check or apply — the engine must never run a non-applicable rule's
		// remediation. Transactions records StatusErrored (the legacy seam,
		// same as Scan); progress reports SKIP.
		if !detect.AppliesTo(rl.Platforms, osInfo) {
			detail := platformSkipDetail(rl, osInfo)
			result.Transactions = append(result.Transactions, erroredResult(rl, errors.New(detail)))
			r.emit(progress.Update{
				Kind: progress.RuleChecked, RuleID: rl.ID,
				Index: i + 1, Total: total, OK: false, Skipped: true, Detail: detail,
			})
			continue
		}

		impl, err := rule.Select(rl, caps)
		if err != nil {
			result.Transactions = append(result.Transactions, erroredResult(rl, err))
			r.emit(progress.Update{
				Kind: progress.RuleChecked, RuleID: rl.ID,
				Index: i + 1, Total: total, OK: false, Errored: true, Detail: err.Error(),
			})
			continue
		}

		// Check first: skip rules already in desired state.
		checkRes, checkErr := check.Run(ctx, transport, impl.Check)
		passed := checkRes.Passed
		if checkErr == nil && passed {
			result.Transactions = append(result.Transactions, api.TransactionResult{
				TransactionID: uuid.New(),
				Status:        api.StatusCommitted,
				StartedAt:     time.Now().UTC(),
				FinishedAt:    time.Now().UTC(),
				Steps: []api.StepResult{{
					StepIndex: 0, Mechanism: "check", Success: true,
					Detail: "already in desired state — skipped",
				}},
			})
			r.emit(progress.Update{
				Kind: progress.RuleChecked, RuleID: rl.ID,
				Index: i + 1, Total: total, OK: true, Detail: "already in desired state",
			})
			continue
		}

		// Build and run transaction.
		txn := implToTransaction(rl, impl, caps, hostID)
		txr, runErr := r.engine.Run(ctx, transport, txn, false)
		if runErr != nil {
			result.Transactions = append(result.Transactions, erroredResult(rl, runErr))
			r.emit(progress.Update{
				Kind: progress.RuleChecked, RuleID: rl.ID,
				Index: i + 1, Total: total, OK: false, Errored: true, Detail: runErr.Error(),
			})
			continue
		}
		result.Transactions = append(result.Transactions, *txr)
		fixed := txr.Status == api.StatusCommitted
		detail := ""
		if !fixed {
			detail = string(txr.Status)
			if txr.Error != nil {
				detail = txr.Error.Error()
			}
		}
		r.emit(progress.Update{
			Kind: progress.RuleChecked, RuleID: rl.ID,
			Index: i + 1, Total: total, OK: fixed, Fixed: fixed, Detail: detail,
		})
	}
	return result, nil
}

// emit delivers a progress Update to the Runner's sink, treating a nil sink
// as a no-op and swallowing any panic the sink raises. Progress is cosmetic
// and strictly subordinate to the scan path: a misbehaving sink MUST NEVER
// break or abort a scan (spec progress-emission C-05), mirroring the engine's
// deliberate event-publish error-swallow.
func (r *Runner) emit(u progress.Update) {
	if r.progress == nil {
		return
	}
	defer func() { _ = recover() }()
	progress.Emit(r.progress, u)
}

// implToTransaction converts a selected rule implementation into an
// [api.Transaction] ready for the engine.
func implToTransaction(rl *api.Rule, impl *api.Implementation, _ api.CapabilitySet, hostID string) *api.Transaction {
	txn := &api.Transaction{
		ID:            uuid.New(),
		RuleID:        rl.ID,
		HostID:        hostID,
		Transactional: rl.Transactional,
		Severity:      rl.Severity,
		FrameworkRefs: mappings.RefsFromReferences(rl.References),
		// Carry the selected impl's check so the VALIDATE phase re-verifies
		// desired state post-apply.
		Check: impl.Check,
	}

	rem := impl.Remediation
	if len(rem.Steps) > 0 {
		for i, s := range rem.Steps {
			params := make(api.Params, len(s.Params))
			for k, v := range s.Params {
				params[k] = v
			}
			txn.Steps = append(txn.Steps, api.Step{
				Index:     i,
				Mechanism: s.Mechanism,
				Params:    params,
			})
		}
	} else {
		params := make(api.Params, len(rem.Params))
		for k, v := range rem.Params {
			params[k] = v
		}
		txn.Steps = []api.Step{{
			Index:     0,
			Mechanism: rem.Mechanism,
			Params:    params,
		}}
	}
	return txn
}

// platformSkipDetail explains why a rule was skipped as not-applicable to the
// host's detected OS, e.g. "not applicable: host RHEL 8.10, rule targets rhel >=9".
func platformSkipDetail(rl *api.Rule, os detect.OSInfo) string {
	host := os.Label()
	if host == "" {
		host = "unknown host OS"
	}
	return fmt.Sprintf("not applicable: host %s, rule targets %s", host, platformsSummary(rl.Platforms))
}

// platformsSummary renders a rule's platform constraints compactly, e.g.
// "rhel >=9", "rhel 8-9", "rhel <=8", or "rhel" when unversioned.
func platformsSummary(platforms []api.Platform) string {
	if len(platforms) == 0 {
		return "any platform"
	}
	parts := make([]string, 0, len(platforms))
	for _, p := range platforms {
		switch {
		case p.MinVersion != 0 && p.MaxVersion != 0:
			parts = append(parts, fmt.Sprintf("%s %d-%d", p.Family, p.MinVersion, p.MaxVersion))
		case p.MinVersion != 0:
			parts = append(parts, fmt.Sprintf("%s >=%d", p.Family, p.MinVersion))
		case p.MaxVersion != 0:
			parts = append(parts, fmt.Sprintf("%s <=%d", p.Family, p.MaxVersion))
		default:
			parts = append(parts, p.Family)
		}
	}
	return strings.Join(parts, ", ")
}

// erroredResult builds a synthetic errored [api.TransactionResult] for
// a rule that could not be checked or remediated.
func erroredResult(rl *api.Rule, err error) api.TransactionResult {
	return api.TransactionResult{
		TransactionID: uuid.New(),
		Status:        api.StatusErrored,
		StartedAt:     time.Now().UTC(),
		FinishedAt:    time.Now().UTC(),
		Error:         fmt.Errorf("%s: %w", rl.ID, err),
	}
}
