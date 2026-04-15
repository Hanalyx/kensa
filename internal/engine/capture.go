package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// capture invokes the CaptureHandler for every capturable step and
// records a marker PreState for non-capturable steps. The returned
// bundle is what the engine persists before any apply runs
// (engine-transaction spec C-02) and what rollback consumes.
//
// A capture-phase failure aborts the transaction before apply
// (engine-transaction spec AC-10). Returning an error here causes
// [Engine.Run] to return Status=Errored with no host mutation.
func (e *Engine) capture(ctx context.Context, transport api.Transport, txn *api.Transaction) ([]api.PreState, error) {
	preStates := make([]api.PreState, 0, len(txn.Steps))
	for _, step := range txn.Steps {
		h := e.registry.MustGet(step.Mechanism)
		now := time.Now().UTC()

		if !h.Capturable() {
			// Non-capturable step: record a marker so the index lines
			// up with the apply step and the rollback path can skip it.
			preStates = append(preStates, api.PreState{
				StepIndex:  step.Index,
				Mechanism:  step.Mechanism,
				Capturable: false,
				CapturedAt: now,
			})
			continue
		}

		ch, ok := h.(api.CaptureHandler)
		if !ok {
			return nil, fmt.Errorf("capture: handler %q reports Capturable() but does not implement CaptureHandler", step.Mechanism)
		}

		pre, err := ch.Capture(ctx, transport, step.Params)
		if err != nil {
			return nil, fmt.Errorf("capture: step %d (%s): %w", step.Index, step.Mechanism, err)
		}
		// Defensive: every capturable handler must return a non-nil
		// PreState. A nil PreState here indicates a handler bug;
		// rather than letting it propagate to the apply phase as a
		// nil-pointer panic, we surface it as ErrCaptureIncomplete.
		if pre == nil {
			return nil, fmt.Errorf("capture: step %d (%s): %w", step.Index, step.Mechanism, api.ErrCaptureIncomplete)
		}
		// Stamp the index/mechanism in case the handler did not.
		pre.StepIndex = step.Index
		pre.Mechanism = step.Mechanism
		pre.Capturable = true
		if pre.CapturedAt.IsZero() {
			pre.CapturedAt = now
		}
		preStates = append(preStates, *pre)
	}
	return preStates, nil
}

// rollbackPlanFromPreStates derives the rollback plan from the
// pre-state bundle. Used by the deadman armer to generate the
// out-of-band rollback script before any apply runs.
func rollbackPlanFromPreStates(preStates []api.PreState) []api.RollbackStepPreview {
	plan := make([]api.RollbackStepPreview, 0, len(preStates))
	for _, p := range preStates {
		if !p.Capturable {
			continue
		}
		plan = append(plan, api.RollbackStepPreview{
			Index:     p.StepIndex,
			Mechanism: p.Mechanism,
			Summary:   "restore captured pre-state",
		})
	}
	return plan
}
