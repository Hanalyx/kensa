package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// rollback reverses every successfully applied capturable step in
// reverse order, using the captured pre-state. Non-capturable steps
// that ran successfully are skipped (engine-transaction spec AC-05);
// for transactional:false rules they remain stranded and the
// transaction is recorded StatusPartiallyApplied.
//
// The source argument identifies which path drove rollback: "inline"
// (engine ran it during commit-or-rollback), "deadman" (the scheduled
// out-of-band script ran), or "manual" (kensa rollback --start). It
// surfaces via [api.RollbackResult.Source] for audit.
func (e *Engine) rollback(ctx context.Context, transport api.Transport, applyResults []api.StepResult, preStates []api.PreState, source string) []api.RollbackResult {
	results := make([]api.RollbackResult, 0, len(applyResults))

	// Iterate apply results in reverse. Only successfully-applied
	// capturable steps get reversed.
	for i := len(applyResults) - 1; i >= 0; i-- {
		ar := applyResults[i]
		if !ar.Success || !ar.Capturable {
			continue
		}

		h := e.mustLookupHandler(ar.Mechanism)
		rh, ok := h.(api.RollbackHandler)
		if !ok {
			results = append(results, api.RollbackResult{
				StepIndex: ar.StepIndex,
				Mechanism: ar.Mechanism,
				Success:   false,
				Detail:    "handler does not implement RollbackHandler despite Capturable() returning true",
				Source:    source,
			})
			continue
		}

		// Locate the matching PreState. Aligned by index.
		var pre *api.PreState
		for j := range preStates {
			if preStates[j].StepIndex == ar.StepIndex {
				p := preStates[j]
				pre = &p
				break
			}
		}
		if pre == nil {
			results = append(results, api.RollbackResult{
				StepIndex: ar.StepIndex,
				Mechanism: ar.Mechanism,
				Success:   false,
				Detail:    "no captured pre-state for this step",
				Source:    source,
			})
			continue
		}

		rr, err := rh.Rollback(ctx, transport, pre)
		if err != nil {
			results = append(results, api.RollbackResult{
				StepIndex: ar.StepIndex,
				Mechanism: ar.Mechanism,
				Success:   false,
				Detail:    err.Error(),
				Source:    source,
			})
			continue
		}
		if rr == nil {
			rr = &api.RollbackResult{
				StepIndex: ar.StepIndex,
				Mechanism: ar.Mechanism,
				Success:   true,
				Source:    source,
			}
		}
		// Stamp index/mechanism/source in case the handler omitted them.
		rr.StepIndex = ar.StepIndex
		rr.Mechanism = ar.Mechanism
		if rr.Source == "" {
			rr.Source = source
		}
		results = append(results, *rr)
	}
	return results
}

// RollbackTransaction implements manual rollback from a persisted
// [api.TransactionRecord]. It satisfies the RollbackTransaction method
// added to the [api.Engine] interface.
//
// The record must have its Steps field populated with the original
// apply results and its PreStates field populated with the captured
// pre-state bundle. Both are available from [api.LogQuery.Get] with
// the default options.
func (e *Engine) RollbackTransaction(ctx context.Context, transport api.Transport, record *api.TransactionRecord) (*api.RollbackResult, error) {
	// Build a slice of StepResult from the record's step outcomes.
	applyResults := make([]api.StepResult, len(record.Steps))
	copy(applyResults, record.Steps)

	preStates := record.PreStates

	rbResults := e.rollback(ctx, transport, applyResults, preStates, "manual")

	// Aggregate: return the first failure if any steps failed, otherwise
	// return a synthetic success result for the transaction. A partial
	// rollback is NOT persisted as rolled-back — the host is in a mixed
	// state and the transaction stays committed for the operator to inspect.
	for i := range rbResults {
		if !rbResults[i].Success {
			return &rbResults[i], nil
		}
	}

	rolledBackAt := time.Now().UTC()

	// Record the rollback outcome durably so the transaction log reflects
	// reality: the row is marked rolled-back, per-step events are written,
	// and the owning session stops showing as rollback-able. Without this
	// the host is reverted but the store still reports the transaction
	// committed (the pre-fix bug). Only stores that implement the optional
	// capability persist; the host reversal above already succeeded either
	// way.
	//
	// Recording is best-effort: the host is already reverted, and that is
	// the source of truth. A failure to write the audit record must NOT
	// report the rollback as failed — a downstream orchestrator would
	// otherwise mark a genuinely-reverted host as un-rolled-back and act on
	// a false negative. The gap is surfaced as a WARNING in the result
	// detail (which callers carry into their own evidence), not propagated
	// as an error.
	// A rollback that reverted nothing (no capturable steps — e.g. a
	// non-transactional transaction reached via the legacy `--txn` path,
	// which unlike --start applies no status/capturable filter) must NOT be
	// recorded as rolled-back: writing a rolled_back status with zero events
	// for a no-op would misrepresent the host. Leaving the transaction as-is
	// is the honest state.
	if len(rbResults) == 0 {
		return &api.RollbackResult{
			StepIndex:  -1,
			Success:    true,
			Detail:     "no capturable steps to roll back; host unchanged, transaction status left as-is",
			Source:     "manual",
			ExecutedAt: rolledBackAt,
		}, nil
	}

	detail := "all rollback steps succeeded"
	if rs, ok := e.store.(RollbackStore); ok {
		if err := rs.PersistRollback(ctx, record.ID, rbResults, rolledBackAt); err != nil {
			detail = fmt.Sprintf("all rollback steps succeeded; WARNING: host reverted but recording the rollback outcome to the transaction log failed: %v", err)
		}
	}

	return &api.RollbackResult{
		StepIndex:  -1, // transaction-level result, not step-level
		Mechanism:  "",
		Success:    true,
		Detail:     detail,
		Source:     "manual",
		ExecutedAt: rolledBackAt,
	}, nil
}
