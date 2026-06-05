package engine_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// drainEvents collects every event delivered on ch until it is closed (the
// bus closes the subscription channel when ctx is canceled).
func drainEvents(ch <-chan api.Event) []api.Event {
	var out []api.Event
	for ev := range ch {
		out = append(out, ev)
	}
	return out
}

// TestEngine_StreamingPayloadsCarryRuleID verifies the engine stamps
// txn.RuleID onto the Data payloads of the streaming events it emits:
// TransactionStarted (TransactionStartedData), PhaseCompleted
// (PhaseCompletedData), and RolledBack (RolledBackData).
//
// @spec progress-emission
// @ac AC-04
func TestEngine_StreamingPayloadsCarryRuleID(t *testing.T) {
	t.Run("progress-emission/AC-04", func(t *testing.T) {
		const wantRuleID = "rule-emit-ac04"

		// A handler whose Apply fails forces the rollback path, so the
		// same run exercises TransactionStarted, PhaseCompleted, AND
		// RolledBack — all three RuleID-bearing payloads.
		h := &engine.FakeHandler{
			HandlerName:  "fake_apply_fails",
			IsCapturable: true,
			ApplyErr:     errors.New("induced apply failure"),
		}
		r := handler.NewRegistry()
		r.Register(h)

		bus := engine.NewInMemoryEventBus()
		e := engine.New(engine.WithRegistry(r), engine.WithEvents(bus))

		// Long-lived subscription drained after the run; cancel closes
		// the channel so drainEvents terminates.
		subCtx, cancel := context.WithCancel(context.Background())
		ch, err := bus.Subscribe(subCtx, api.EventFilter{})
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}

		txn := &api.Transaction{
			ID:            uuid.New(),
			RuleID:        wantRuleID,
			HostID:        "test-host",
			Severity:      "high",
			Steps:         []api.Step{{Index: 0, Mechanism: "fake_apply_fails"}},
			StartedAt:     time.Now().UTC(),
			Deadline:      time.Now().Add(time.Minute),
			Transactional: true,
		}

		res, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Status != api.StatusRolledBack {
			t.Fatalf("expected RolledBack, got %s", res.Status)
		}

		cancel()
		events := drainEvents(ch)

		var sawStarted, sawPhase, sawRolledBack bool
		for _, ev := range events {
			switch d := ev.Data.(type) {
			case api.TransactionStartedData:
				sawStarted = true
				if d.RuleID != wantRuleID {
					t.Errorf("TransactionStartedData.RuleID = %q, want %q", d.RuleID, wantRuleID)
				}
			case api.PhaseCompletedData:
				sawPhase = true
				if d.RuleID != wantRuleID {
					t.Errorf("PhaseCompletedData.RuleID = %q, want %q", d.RuleID, wantRuleID)
				}
			case api.RolledBackData:
				sawRolledBack = true
				if d.RuleID != wantRuleID {
					t.Errorf("RolledBackData.RuleID = %q, want %q", d.RuleID, wantRuleID)
				}
			}
		}

		if !sawStarted {
			t.Error("no TransactionStarted event with TransactionStartedData observed")
		}
		if !sawPhase {
			t.Error("no PhaseCompleted event with PhaseCompletedData observed")
		}
		if !sawRolledBack {
			t.Error("no RolledBack event with RolledBackData observed")
		}
	})
}
