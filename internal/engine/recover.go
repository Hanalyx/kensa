package engine

import (
	"context"
	"fmt"

	"github.com/Hanalyx/kensa/api"
)

// Recover compensates transactions that were interrupted before reaching a
// terminal status. It scans the store's open journal entries (a row written
// in PREPARE with no terminal transaction record — see the recovery-journal
// spec), rolls each one back from its captured pre-state, and records a
// terminal StatusRecovered result (StatusRollbackFailed if the compensation
// could not be machine-clean). The journal entry is cleared once the terminal
// record persists (via finalize), so Recover is idempotent: a second run
// finds nothing, and restore-from-pre-state is itself re-runnable.
//
// hostID scopes recovery to one host (empty = every open entry). The caller
// supplies the transport — recovery runs in a separate process (kensa
// recover) that reconnects to the host. Recover returns one result per
// recovered transaction.
//
// Concurrency: the recover CLI takes the recover.lock EXCLUSIVE, which fences
// concurrent recover runs. It does NOT currently fence against a LIVE engine —
// the live remediate/rollback path does not yet take the lock SHARED (see
// store.RecoverLock and docs/roadmap/STATUS.md). Until it does, the operator
// MUST NOT run recover against a host with a live engine on the same store.
func (e *Engine) Recover(ctx context.Context, transport api.Transport, hostID string) ([]*api.TransactionResult, error) {
	js, ok := e.store.(JournalStore)
	if !ok {
		// No journaling capability: nothing to recover.
		return nil, nil
	}
	entries, err := js.LoadOpenJournalEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("recover: load open journal entries: %w", err)
	}

	results := make([]*api.TransactionResult, 0, len(entries))
	for _, entry := range entries {
		if hostID != "" && entry.HostID != hostID {
			continue
		}
		preStates, err := e.store.LoadPreStates(ctx, entry.TxnID)
		if err != nil {
			// Can't load pre-state — we cannot safely compensate. Leave the
			// entry open for a later attempt rather than recording a bogus
			// terminal record.
			continue
		}

		txn := &api.Transaction{
			ID:            entry.TxnID,
			RuleID:        entry.RuleID,
			HostID:        entry.HostID,
			Transactional: entry.Transactional,
			Steps:         entry.Intent,
			StartedAt:     entry.CreatedAt,
		}

		rb := e.recoverRollback(ctx, transport, preStates)
		status := api.StatusRecovered
		if !rollbackClean(rb) {
			status = api.StatusRollbackFailed
		}

		// Reuse finalize: it recaptures the post-recovery state, signs the
		// envelope, persists the terminal record, and clears the journal
		// entry (clear-on-terminal). Pass nil apply steps/validators — there
		// is no live apply to record for a recovered transaction.
		result := e.finalize(ctx, transport, txn, entry.CreatedAt, status, nil, preStates, nil, rb)
		results = append(results, result)
	}
	return results, nil
}

// recoverRollback drives each capturable pre-state's RollbackHandler in
// reverse order, compensating an interrupted transaction from its captured
// state alone (there are no live apply results after a crash). Source is
// "recovery". Idempotent: restoring a step that may not have actually applied
// is safe, because rollback restores the recorded pre-state.
func (e *Engine) recoverRollback(ctx context.Context, transport api.Transport, preStates []api.PreState) []api.RollbackResult {
	results := make([]api.RollbackResult, 0, len(preStates))
	for i := len(preStates) - 1; i >= 0; i-- {
		pre := preStates[i]
		if !pre.Capturable {
			continue
		}
		h := e.mustLookupHandler(pre.Mechanism)
		rh, ok := h.(api.RollbackHandler)
		if !ok {
			results = append(results, api.RollbackResult{
				StepIndex: pre.StepIndex,
				Mechanism: pre.Mechanism,
				Success:   false,
				Detail:    "handler does not implement RollbackHandler",
				Source:    "recovery",
			})
			continue
		}
		p := pre
		rr, err := rh.Rollback(ctx, transport, &p)
		if err != nil {
			results = append(results, api.RollbackResult{
				StepIndex: pre.StepIndex,
				Mechanism: pre.Mechanism,
				Success:   false,
				Detail:    err.Error(),
				Source:    "recovery",
			})
			continue
		}
		if rr == nil {
			rr = &api.RollbackResult{Success: true}
		}
		rr.StepIndex = pre.StepIndex
		rr.Mechanism = pre.Mechanism
		if rr.Source == "" {
			rr.Source = "recovery"
		}
		results = append(results, *rr)
	}
	return results
}
