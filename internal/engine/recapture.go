package engine

import (
	"context"
	"reflect"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// recaptureTimeout bounds the post-state recapture independently of the
// transaction deadline.
const recaptureTimeout = 30 * time.Second

// postStateUnobservedKey marks a PostStateBundle entry whose post-state could
// not be re-read (the recapture errored). A consumer keys on it to tell
// "host is in this state" from "we could not observe the state".
const postStateUnobservedKey = "__post_state__"

// recapture re-reads the post-transaction state of every capturable step by
// re-invoking its CaptureHandler. The result populates the evidence
// envelope's PostStateBundle so the signed record proves a RE-MEASURED end
// state rather than only the attempted apply steps.
//
// Unlike [Engine.capture], recapture NEVER fails the transaction: the host
// mutation (apply or rollback) has already happened, so a failed re-read is
// recorded as an "unobserved" post-state, not an abort. It runs on a context
// DETACHED from the transaction's cancellation/deadline — the post-state is
// worth recording even if the caller gave up — but bounded by its own
// timeout so a dead transport cannot hang commit.
func (e *Engine) recapture(ctx context.Context, transport api.Transport, txn *api.Transaction) []api.PreState {
	rcCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recaptureTimeout)
	defer cancel()

	post := make([]api.PreState, 0, len(txn.Steps))
	for _, step := range txn.Steps {
		h := e.mustLookupHandler(step.Mechanism)
		now := time.Now().UTC()

		if !h.Capturable() {
			// Non-capturable step: marker, index-aligned with capture().
			post = append(post, api.PreState{
				StepIndex:  step.Index,
				Mechanism:  step.Mechanism,
				Capturable: false,
				CapturedAt: now,
			})
			continue
		}

		ch, ok := h.(api.CaptureHandler)
		if !ok {
			post = append(post, unobservedPost(step, now, "handler reports Capturable() but does not implement CaptureHandler"))
			continue
		}

		pre, err := ch.Capture(rcCtx, transport, step.Params)
		if err != nil || pre == nil {
			detail := "recapture returned nil pre-state"
			if err != nil {
				detail = err.Error()
			}
			post = append(post, unobservedPost(step, now, detail))
			continue
		}
		pre.StepIndex = step.Index
		pre.Mechanism = step.Mechanism
		pre.Capturable = true
		if pre.CapturedAt.IsZero() {
			pre.CapturedAt = now
		}
		post = append(post, *pre)
	}
	return post
}

// unobservedPost builds a PostStateBundle entry for a step whose post-state
// could not be re-read.
func unobservedPost(step api.Step, now time.Time, detail string) api.PreState {
	return api.PreState{
		StepIndex:  step.Index,
		Mechanism:  step.Mechanism,
		Capturable: true,
		CapturedAt: now,
		Data: map[string]interface{}{
			postStateUnobservedKey: "unobserved",
			"detail":               detail,
		},
	}
}

// postMatchesPre reports whether the recaptured post-state for stepIndex is
// byte-equal to its captured pre-state — independent proof that a rollback
// restored the step, beyond the handler's self-reported Success. observed is
// false when the post-state could not be recaptured (an unobserved entry, or
// no entry at all), in which case matched is meaningless.
//
// Both bundles are produced over the same transport and encoding, so a
// genuine match is byte-symmetric; a divergence is real (or a concurrent
// external mutation, which a caller may treat as lower-confidence).
func postMatchesPre(pre, post []api.PreState, stepIndex int) (matched, observed bool) {
	prState := findState(pre, stepIndex)
	poState := findState(post, stepIndex)
	if prState == nil || poState == nil {
		return false, false
	}
	if v, ok := poState.Data[postStateUnobservedKey]; ok && v == "unobserved" {
		return false, false
	}
	return reflect.DeepEqual(prState.Data, poState.Data), true
}

func findState(states []api.PreState, stepIndex int) *api.PreState {
	for i := range states {
		if states[i].StepIndex == stepIndex {
			return &states[i]
		}
	}
	return nil
}
