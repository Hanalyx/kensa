// Tests for the PR5 engine-backed remediate streaming drain helper and the
// rollback plain-progress path (spec cli-remediate-stream).
//
// The drain-then-cancel ordering (C-04) and the result-passthrough (C-05) are
// exercised against in-package fakes that subscribe/emit more than the bus
// buffer's worth of events, with NO live engine. The rollback path (C-06) is
// asserted structurally: rollback renders plain text and the engine rollback
// path emits no events.
package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
)

// recordingSink captures every Update the drain helper renders, in order.
type recordingSink struct {
	updates []progress.Update
}

func (s *recordingSink) Update(u progress.Update) { s.updates = append(s.updates, u) }

// TestStreamRemediate_DrainsBeyondBuffer proves the drain helper runs
// Remediate concurrently and delivers EVERY emitted event to the sink even
// when the engine emits far more than the 64-slot bus buffer would hold. An
// inline subscribe-then-call would drop past slot 64; the concurrent drain
// does not. Order is preserved.
// @spec cli-remediate-stream
// @ac AC-05
func TestStreamRemediate_DrainsBeyondBuffer(t *testing.T) {
	t.Run("cli-remediate-stream/AC-05", func(t *testing.T) {
		ctx := context.Background()

		const nRules = 50 // ~4 events each => 200 events, well past the 64 buffer

		// emit is the unbuffered channel the fake "engine" publishes onto.
		// Unbuffered means the producer cannot get ahead of the drainer — if
		// the helper were NOT draining concurrently, the producer (inside
		// remediate) would block forever and the test would deadlock/timeout.
		emit := make(chan api.Event)

		subscribe := func(c context.Context, _ api.EventFilter) (<-chan api.Event, error) {
			out := make(chan api.Event)
			go func() {
				defer close(out)
				for {
					select {
					case <-c.Done():
						return
					case ev, ok := <-emit:
						if !ok {
							// producer finished; keep open until cancel
							<-c.Done()
							return
						}
						// Forward UNCONDITIONALLY (no Done race here): the helper
						// keeps reading the channel in its main loop and its
						// post-cancel tail-drain until we close(out), so this
						// send always has a reader and is never dropped.
						// Selecting on c.Done() here was the flake source — it
						// could drop the last in-flight event when remediate's
						// done outcome won the main-loop select before this
						// forward completed.
						out <- ev
					}
				}
			}()
			return out, nil
		}

		remediate := func(_ context.Context) (*api.RemediationResult, error) {
			txnID := uuid.New()
			for i := 0; i < nRules; i++ {
				rid := "rule-" + string(rune('a'+i%26))
				emit <- api.Event{Kind: api.TransactionStarted, TxnID: &txnID,
					Data: api.TransactionStartedData{RuleID: rid}}
				emit <- api.Event{Kind: api.PhaseCompleted, TxnID: &txnID,
					Data: api.PhaseCompletedData{Phase: api.PhaseApply, Success: true, RuleID: rid}}
				emit <- api.Event{Kind: api.PhaseCompleted, TxnID: &txnID,
					Data: api.PhaseCompletedData{Phase: api.PhaseValidate, Success: true, RuleID: rid}}
				emit <- api.Event{Kind: api.Committed, TxnID: &txnID}
			}
			close(emit)
			return &api.RemediationResult{}, nil
		}

		sink := &recordingSink{}
		if _, err := streamRemediate(ctx, subscribe, remediate, sink); err != nil {
			t.Fatalf("streamRemediate err = %v, want nil", err)
		}

		wantTotal := nRules * 4
		if len(sink.updates) != wantTotal {
			t.Fatalf("rendered %d updates, want %d (events were dropped — drain not concurrent?)",
				len(sink.updates), wantTotal)
		}
		// Order preserved: each rule's 4 updates appear as Started, Phase,
		// Phase, Done in sequence.
		for i := 0; i < nRules; i++ {
			base := i * 4
			if sink.updates[base].Kind != progress.TxnStarted {
				t.Errorf("update[%d].Kind = %v, want TxnStarted", base, sink.updates[base].Kind)
			}
			if sink.updates[base+3].Kind != progress.TxnDone {
				t.Errorf("update[%d].Kind = %v, want TxnDone", base+3, sink.updates[base+3].Kind)
			}
		}
	})
}

// TestStreamRemediate_ResultFromRemediate proves the helper returns exactly
// Remediate's result and error (the canonical struct), independent of the
// stream. Drained with a recording sink and with a nil sink yields the same
// result/err.
// @spec cli-remediate-stream
// @ac AC-06
func TestStreamRemediate_ResultFromRemediate(t *testing.T) {
	t.Run("cli-remediate-stream/AC-06", func(t *testing.T) {
		ctx := context.Background()
		wantResult := &api.RemediationResult{}
		wantErr := errors.New("boom")

		subscribe := func(c context.Context, _ api.EventFilter) (<-chan api.Event, error) {
			out := make(chan api.Event)
			go func() { <-c.Done(); close(out) }() // no events, closes on cancel
			return out, nil
		}
		remediate := func(_ context.Context) (*api.RemediationResult, error) {
			return wantResult, wantErr
		}

		// With a recording sink.
		gotResult, gotErr := streamRemediate(ctx, subscribe, remediate, &recordingSink{})
		if gotResult != wantResult || !errors.Is(gotErr, wantErr) {
			t.Errorf("with sink: result=%v err=%v, want result=%v err=%v",
				gotResult, gotErr, wantResult, wantErr)
		}

		// With a nil sink — same canonical result/err.
		gotResult2, gotErr2 := streamRemediate(ctx, subscribe, remediate, nil)
		if gotResult2 != wantResult || !errors.Is(gotErr2, wantErr) {
			t.Errorf("nil sink: result=%v err=%v, want result=%v err=%v",
				gotResult2, gotErr2, wantResult, wantErr)
		}
	})
}

// TestStreamRemediate_SubscribeFailureStillRemediates proves a subscription
// error is non-fatal: the remediation still runs and its result/err is
// returned (progress is cosmetic).
// @spec cli-remediate-stream
// @ac AC-06
func TestStreamRemediate_SubscribeFailureStillRemediates(t *testing.T) {
	t.Run("cli-remediate-stream/AC-06", func(t *testing.T) {
		ctx := context.Background()
		want := &api.RemediationResult{}
		ran := false
		subscribe := func(context.Context, api.EventFilter) (<-chan api.Event, error) {
			return nil, errors.New("bus unavailable")
		}
		remediate := func(_ context.Context) (*api.RemediationResult, error) {
			ran = true
			return want, nil
		}
		got, err := streamRemediate(ctx, subscribe, remediate, &recordingSink{})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if !ran {
			t.Error("remediate did not run after subscribe failure")
		}
		if got != want {
			t.Errorf("result = %v, want %v", got, want)
		}
	})
}

// TestRollback_PlainProgress_NotBus proves the rollback progress path renders
// plain per-transaction text (rule id + outcome) to a non-stdout writer
// WITHOUT any event-bus subscription. renderRollbackProgress is the plain-text
// helper; it takes a writer the CLI points at stderr.
// @spec cli-remediate-stream
// @ac AC-07
func TestRollback_PlainProgress_NotBus(t *testing.T) {
	t.Run("cli-remediate-stream/AC-07", func(t *testing.T) {
		var buf bytes.Buffer
		renderRollbackProgress(&buf, "cis-rhel9-1.2.3", true, "")
		renderRollbackProgress(&buf, "cis-rhel9-4.5.6", false, "transport closed")
		out := buf.String()
		if !strings.Contains(out, "cis-rhel9-1.2.3") {
			t.Errorf("plain rollback progress missing rule id; got: %q", out)
		}
		if !strings.Contains(out, "cis-rhel9-4.5.6") || !strings.Contains(out, "transport closed") {
			t.Errorf("plain rollback progress missing failed rule/detail; got: %q", out)
		}
	})
}

// TestReportDroppedEvents proves the lossy-bus dropped-event accounting: it
// reports the non-negative difference (result transactions minus rendered
// TxnDone) to a non-stdout writer, is silent when the tally is complete or
// ahead, and returns the count for assertion. The result is derived from the
// canonical RemediationResult (resultTxns) and the renderer tally — it never
// touches stdout, the exit code, or any -o FILE serialization.
// @spec cli-remediate-stream
// @ac AC-08
func TestReportDroppedEvents(t *testing.T) {
	t.Run("cli-remediate-stream/AC-08", func(t *testing.T) {
		// Fewer rendered than the result reports → some were dropped.
		var dropped bytes.Buffer
		n := reportDroppedEvents(&dropped, 3, 10)
		if n != 7 {
			t.Errorf("dropped count = %d, want 7 (10 result - 3 rendered)", n)
		}
		if !strings.Contains(dropped.String(), "7") {
			t.Errorf("dropped summary missing the count; got: %q", dropped.String())
		}
		if !strings.Contains(dropped.String(), "authoritative") {
			t.Errorf("dropped summary should reassure the result is authoritative; got: %q", dropped.String())
		}

		// Complete tally → silent, returns 0.
		var complete bytes.Buffer
		if n := reportDroppedEvents(&complete, 10, 10); n != 0 {
			t.Errorf("complete tally count = %d, want 0", n)
		}
		if complete.Len() != 0 {
			t.Errorf("complete tally must be silent; got: %q", complete.String())
		}

		// Renderer ahead of the result (lossy/edge over-count) → silent, no
		// negative line.
		var ahead bytes.Buffer
		if n := reportDroppedEvents(&ahead, 12, 10); n != 0 {
			t.Errorf("over-count tally = %d, want 0 (never negative)", n)
		}
		if ahead.Len() != 0 {
			t.Errorf("over-count must be silent; got: %q", ahead.String())
		}
	})
}
