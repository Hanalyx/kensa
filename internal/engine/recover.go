package engine

import (
	"context"
	"fmt"
	"sort"

	"github.com/Hanalyx/kensa/api"
)

// Recover compensates transactions that were interrupted before reaching a
// terminal status. It scans the store's open journal entries (a row written
// in PREPARE with no terminal transaction record — see the recovery-journal
// spec), rolls each one back from its captured pre-state, and records a
// terminal StatusRecovered result (StatusRollbackFailed if the compensation
// could not be machine-clean). An entry whose step identity cannot be
// established is refused instead; see RecoverReport. Recover returns the
// compensated results and, when any entry was refused, a
// *RecoveryRefusedError. The journal entry is cleared once the terminal
// record persists (via finalize), so Recover is idempotent: a second run
// finds nothing, and restore-from-pre-state is itself re-runnable.
//
// hostID scopes recovery to one host (empty = every open entry). The caller
// supplies the transport — recovery runs in a separate process (kensa
// recover) that reconnects to the host. Recover returns one result per
// recovered transaction.
//
// Concurrency: the recover CLI takes the recover.lock EXCLUSIVE, which fences
// concurrent recover runs AND a live engine on the same store — the live
// remediate/rollback path holds the lock SHARED (via engine.WithRecoverLock,
// wired by the Default* constructors), so an exclusive recover fails fast with
// ErrRecoverLocked rather than racing an in-flight transaction. Recover
// itself never calls Run/RollbackTransaction (it drives each
// handler's Rollback directly), so it does not self-fence against its own
// exclusive lock.
func (e *Engine) Recover(ctx context.Context, transport api.Transport, hostID string) ([]*api.TransactionResult, error) {
	report, err := e.RecoverReport(ctx, transport, hostID)
	if err != nil {
		return nil, err
	}
	if len(report.Refusals) > 0 {
		return report.Results, &RecoveryRefusedError{Refusals: report.Refusals}
	}
	return report.Results, nil
}

// RecoveryRefusedError reports that Recover declined one or more entries.
// Recover returns it alongside the results of the entries it did
// compensate, so a caller that only checks the error still learns that
// the run was incomplete. RecoverReport returns the same information as
// data instead.
type RecoveryRefusedError struct {
	Refusals []RecoveryRefusal
}

func (e *RecoveryRefusedError) Error() string {
	return fmt.Sprintf("recover: refused %d interrupted transaction(s) whose step identity could not be established", len(e.Refusals))
}

// RecoverReport compensates open journal entries like Recover, and returns
// both the compensated results and the refused entries.
//
// Before anything is dispatched for an entry, recovery checks that the
// journal's intent and the loaded pre-states agree one to one: every step
// index appears once on each side, mechanisms match, each mechanism is
// registered, and each pre-state's capturable flag matches its handler.
// An entry that fails any check is refused whole. No handler runs for it,
// no terminal record is written, and its journal entry and pre-states stay
// intact, so a later run can recover it once the cause is fixed. Keeping
// that evidence preserves the opportunity to recover; it does not
// guarantee it, since a missing or ambiguous pre-state cannot be rebuilt.
//
// Refusing the whole entry, rather than restoring the steps that do check
// out, is deliberate. Steps can depend on each other, so restoring some
// and not others can leave a combination the host was never in.
func (e *Engine) RecoverReport(ctx context.Context, transport api.Transport, hostID string) (*RecoveryReport, error) {
	report := &RecoveryReport{}
	js, ok := e.store.(JournalStore)
	if !ok {
		// No journaling capability: nothing to recover.
		return report, nil
	}
	entries, err := js.LoadOpenJournalEntries(ctx)
	if err != nil {
		return nil, fmt.Errorf("recover: load open journal entries: %w", err)
	}

	report.Results = make([]*api.TransactionResult, 0, len(entries))
	for _, entry := range entries {
		if hostID != "" && entry.HostID != hostID {
			continue
		}
		refuse := func(findings []RecoveryFinding) {
			report.Refusals = append(report.Refusals, RecoveryRefusal{
				TransactionID: entry.TxnID, HostID: entry.HostID, RuleID: entry.RuleID, Findings: findings,
			})
		}
		preStates, err := e.store.LoadPreStates(ctx, entry.TxnID)
		if err != nil {
			// The bundle cannot be read, so nothing can be compensated
			// safely. Leave the entry open for a later attempt.
			refuse([]RecoveryFinding{{Code: FindingPreStatesUnloadable, StepIndex: -1, Detail: err.Error()}})
			continue
		}
		if findings := e.validateRecoveryIdentity(entry.Intent, preStates); len(findings) > 0 {
			refuse(findings)
			continue
		}
		// The bundle matches the intent one to one, so ordering by step
		// index gives the reverse-step-order compensation C-01 requires
		// whatever order the store returned them in.
		sort.SliceStable(preStates, func(i, j int) bool { return preStates[i].StepIndex < preStates[j].StepIndex })

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
		report.Results = append(report.Results, result)
	}
	return report, nil
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
