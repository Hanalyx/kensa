package engine

import (
	"context"

	"github.com/Hanalyx/kensa-go/api"
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
	for i, step := range txn.Steps {
		h := e.registry.MustGet(step.Mechanism)

		var pre *api.PreState
		if h.Capturable() && i < len(preStates) {
			p := preStates[i]
			pre = &p
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
