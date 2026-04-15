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
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/check"
	"github.com/Hanalyx/kensa-go/internal/detect"
	"github.com/Hanalyx/kensa-go/internal/mappings"
	"github.com/Hanalyx/kensa-go/internal/rule"
)

// CheckResult is the outcome of checking one rule against a host.
type CheckResult struct {
	// RuleID is the rule that was checked.
	RuleID string
	// Passed is true when the check confirmed desired state.
	Passed bool
	// Detail is a human-readable description of the check outcome.
	Detail string
	// Err is non-nil when the check could not run (transport error,
	// unsupported method, etc.).
	Err error
}

// Runner executes compliance scans and remediations over an SSH transport.
type Runner struct {
	// engine backs remediations. When nil, Remediate returns an error.
	engine api.Engine
}

// New returns a Runner. Pass a non-nil engine to enable Remediate.
func New(eng api.Engine) *Runner {
	return &Runner{engine: eng}
}

// Scan checks every rule against the host reachable via transport and
// returns per-rule check results. No mutation of the host occurs.
func (r *Runner) Scan(ctx context.Context, transport api.Transport, rules []*api.Rule) (*api.ScanResult, error) {
	caps, err := detect.Detect(ctx, transport)
	if err != nil {
		return nil, fmt.Errorf("scan: detect capabilities: %w", err)
	}

	hostID := "" // transport does not expose hostname; populated by caller
	result := &api.ScanResult{HostID: hostID}

	for _, rl := range rules {
		impl, err := rule.Select(rl, caps)
		if err != nil {
			result.Transactions = append(result.Transactions, erroredResult(rl, err))
			continue
		}

		passed, detail, checkErr := check.Run(ctx, transport, impl.Check)
		if checkErr != nil {
			result.Transactions = append(result.Transactions, erroredResult(rl, checkErr))
			continue
		}

		status := api.StatusRolledBack // "not compliant"
		if passed {
			status = api.StatusCommitted // "compliant"
		}
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
	if r.engine == nil {
		return nil, fmt.Errorf("scan: engine not wired, cannot remediate")
	}

	caps, err := detect.Detect(ctx, transport)
	if err != nil {
		return nil, fmt.Errorf("scan: detect capabilities: %w", err)
	}

	hostID := ""
	result := &api.RemediationResult{HostID: hostID}

	for _, rl := range rules {
		impl, err := rule.Select(rl, caps)
		if err != nil {
			result.Transactions = append(result.Transactions, erroredResult(rl, err))
			continue
		}

		// Check first: skip rules already in desired state.
		passed, _, checkErr := check.Run(ctx, transport, impl.Check)
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
			continue
		}

		// Build and run transaction.
		txn := implToTransaction(rl, impl, caps)
		txr, runErr := r.engine.Run(ctx, transport, txn, false)
		if runErr != nil {
			result.Transactions = append(result.Transactions, erroredResult(rl, runErr))
			continue
		}
		result.Transactions = append(result.Transactions, *txr)
	}
	return result, nil
}

// implToTransaction converts a selected rule implementation into an
// [api.Transaction] ready for the engine.
func implToTransaction(rl *api.Rule, impl *api.Implementation, _ api.CapabilitySet) *api.Transaction {
	txn := &api.Transaction{
		ID:            uuid.New(),
		RuleID:        rl.ID,
		Transactional: rl.Transactional,
		Severity:      rl.Severity,
		FrameworkRefs: mappings.RefsFromReferences(rl.References),
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
