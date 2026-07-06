package engine

import (
	"context"

	"github.com/Hanalyx/kensa/api"
)

// apply executes each step in order, halting on the first failure
// (engine-transaction spec: APPLY phase). Returns the per-step
// results and a boolean reporting whether every step succeeded.
//
// The preStates slice is positionally aligned with txn.Steps so step
// N's PreState is preStates[N]. Non-capturable steps receive nil per
// handler-interface spec AC-06.
func (e *Engine) apply(ctx context.Context, transport api.Transport, txn *api.Transaction, preStates []api.PreState) (results []api.StepResult, allOK bool) {
	results = make([]api.StepResult, 0, len(txn.Steps))
	// When the store supports crash-recovery journaling, advance the durable
	// cursor write-ahead of each step's mutation (recovery-journal spec C-03):
	// the cursor records the highest step index whose mutation may have begun.
	//
	// The cursor is forensic, not load-bearing for recovery correctness:
	// recoverRollback compensates EVERY captured pre-state in reverse order
	// regardless of the cursor, and the PREPARE barrier already made the full
	// intent + pre-state durable before this phase. So the advance is
	// best-effort — a failed cursor write cannot cause recovery to skip a step,
	// and aborting a would-be-successful apply on a forensic-write error would
	// add an availability failure mode with no atomicity benefit. (If recovery
	// is ever made cursor-bounded, this failure handling MUST be revisited: a
	// dropped advance could then let recovery skip the in-flight step.) On the
	// plan path (PersistPreStates, no journal entry) the UPDATE matches no row
	// and is a harmless no-op.
	js, journaling := e.store.(JournalStore)
	for i, step := range txn.Steps {
		h := e.mustLookupHandler(step.Mechanism)

		var pre *api.PreState
		if h.Capturable() && i < len(preStates) {
			p := preStates[i]
			pre = &p
		}

		if journaling {
			_ = js.AdvanceJournalCursor(ctx, txn.ID, step.Index)
		}

		sr, err := h.Apply(ctx, transport, step.Params, pre)
		if err != nil {
			results = append(results, api.StepResult{
				StepIndex:  step.Index,
				Mechanism:  step.Mechanism,
				Capturable: h.Capturable(),
				Success:    false,
				Detail:     err.Error(),
			})
			return results, false
		}
		// Defensive: a successful Apply that returns a nil result is a
		// handler bug. Treat it as a successful step with empty detail
		// rather than panicking; the missing detail is logged.
		if sr == nil {
			sr = &api.StepResult{
				StepIndex: step.Index,
				Mechanism: step.Mechanism,
				Success:   true,
			}
		}
		// Stamp index/mechanism/capturable in case the handler omitted them.
		sr.StepIndex = step.Index
		sr.Mechanism = step.Mechanism
		sr.Capturable = h.Capturable()
		results = append(results, *sr)

		if !sr.Success {
			return results, false
		}
	}
	return results, true
}
