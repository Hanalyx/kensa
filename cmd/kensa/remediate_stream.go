package main

import (
	"context"
	"fmt"
	"io"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
)

// remediateEventFilter is the subscription filter the remediate streaming
// path uses: only the four transaction-scoped kinds the engine emits during a
// remediation. The OpenWatch-owned heartbeat/drift kinds and the deadman kinds
// are never part of the per-rule progress stream, so they are filtered at the
// bus rather than skipped per-event. progress.FromEvent skips them too, but
// filtering here keeps the (bounded) bus buffer free for the events we render.
func remediateEventFilter() api.EventFilter {
	return api.EventFilter{Kinds: []api.EventKind{
		api.TransactionStarted,
		api.PhaseCompleted,
		api.RolledBack,
		api.Committed,
	}}
}

// streamRemediate runs an engine-backed remediation while draining its
// api.Event stream into sink as live progress. It implements the PR5
// drain-then-cancel ordering that the streaming-plan mandates (spec
// cli-remediate-stream C-04):
//
//  1. Subscribe with a CANCELABLE child of ctx (subCtx). The subscription
//     outlives the drain only until we explicitly cancel it.
//  2. Run remediate in a goroutine, capturing its result and error.
//  3. Drain the api.Event channel ON THIS goroutine, translating each event
//     via progress.FromEvent and feeding sink, until remediate signals done.
//  4. Cancel subCtx AFTER remediate returns, which closes the bus channel; the
//     drain loop then ranges to completion and we return.
//
// It deliberately does NOT inline subscribe-then-call on one goroutine: the
// engine's in-memory bus buffers a bounded 64 events per subscriber and DROPS
// past that, while a multi-rule remediation emits ~4 events per rule. A
// synchronous subscribe-then-call would let the engine fill and drop before
// the CLI ever read. Concurrent drain keeps the buffer draining.
//
// The canonical *api.RemediationResult and its error come from remediate's
// return value, NEVER reconstructed from the rendered stream (spec
// cli-remediate-stream C-05). A nil sink renders nothing but still drains the
// channel (so the engine never blocks) and returns the same result/err.
//
// subscribe and remediate are injected (rather than closing over a concrete
// *kensa.Service) so the ordering contract is unit-testable with fakes that
// emit more than the buffer's worth of events.
func streamRemediate(
	ctx context.Context,
	subscribe func(context.Context, api.EventFilter) (<-chan api.Event, error),
	remediate func(context.Context) (*api.RemediationResult, error),
	sink progress.Sink,
) (*api.RemediationResult, error) {
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch, err := subscribe(subCtx, remediateEventFilter())
	if err != nil {
		// Subscription failure is non-fatal to the remediation itself:
		// progress is cosmetic. Run remediate without a stream.
		return remediate(ctx)
	}

	type outcome struct {
		result *api.RemediationResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, e := remediate(ctx)
		done <- outcome{result: r, err: e}
	}()

	var out outcome
	got := false
	for !got {
		select {
		case ev, ok := <-ch:
			if !ok {
				// Bus channel closed (ctx cancellation elsewhere). Stop
				// draining; still wait for remediate below.
				ch = nil
				continue
			}
			if u, render := progress.FromEvent(ev); render {
				progress.Emit(sink, u)
			}
		case o := <-done:
			out = o
			got = true
		}
	}

	// Remediate has returned. Cancel the subscription so the bus closes our
	// channel, then drain any events the engine published before the close
	// became visible. This is best-effort tail rendering; the result is
	// already canonical. A nil ch means the channel already closed during the
	// main loop — nothing to tail-drain (ranging a nil channel would block
	// forever).
	cancel()
	if ch != nil {
		for ev := range ch {
			if u, render := progress.FromEvent(ev); render {
				progress.Emit(sink, u)
			}
		}
	}

	return out.result, out.err
}

// renderRollbackProgress writes one plain-text progress line for a single
// rolled-back transaction to w (the CLI points it at stderr). It is the
// rollback counterpart to the bus-streamed remediate progress: the engine's
// RollbackTransaction path emits NO events (it has zero publish() calls), so
// rollback CANNOT and MUST NOT subscribe to the event bus for progress. The
// CLI already iterates committed transactions one at a time (rule id known per
// step), so it renders this plain line itself as each rollback completes.
//
// ruleID names the transaction's rule. ok is the rollback outcome; when ok is
// false, detail carries a short reason. The write error is swallowed: progress
// is cosmetic and must never break the rollback run.
func renderRollbackProgress(w io.Writer, ruleID string, ok bool, detail string) {
	mark := "ok"
	if !ok {
		mark = "FAIL"
	}
	line := fmt.Sprintf("rollback %s: %s", ruleID, mark)
	if !ok && detail != "" {
		line += " (" + detail + ")"
	}
	_, _ = io.WriteString(w, line+"\n")
}
