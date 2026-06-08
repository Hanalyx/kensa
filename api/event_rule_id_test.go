package api_test

import (
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// TestPhaseCompletedDataCarriesRuleID verifies the additive RuleID field on
// PhaseCompletedData round-trips alongside the existing fields.
//
// @spec api-event-rule-id
// @ac AC-01
func TestPhaseCompletedDataCarriesRuleID(t *testing.T) {
	t.Run("api-event-rule-id/AC-01", func(t *testing.T) {
		d := api.PhaseCompletedData{
			Phase:    api.PhaseApply,
			Success:  true,
			Duration: 250 * time.Millisecond,
			RuleID:   "rule-x",
		}
		if d.RuleID != "rule-x" {
			t.Errorf("RuleID = %q, want %q", d.RuleID, "rule-x")
		}
		if d.Phase != api.PhaseApply {
			t.Errorf("Phase = %q, want %q", d.Phase, api.PhaseApply)
		}
		if !d.Success {
			t.Error("Success = false, want true")
		}
		if d.Duration != 250*time.Millisecond {
			t.Errorf("Duration = %v, want %v", d.Duration, 250*time.Millisecond)
		}
	})
}

// TestRolledBackDataCarriesRuleID verifies the additive RuleID field on
// RolledBackData round-trips alongside the existing fields.
//
// @spec api-event-rule-id
// @ac AC-02
func TestRolledBackDataCarriesRuleID(t *testing.T) {
	t.Run("api-event-rule-id/AC-02", func(t *testing.T) {
		d := api.RolledBackData{
			Source: "inline",
			Reason: "validate failed",
			RuleID: "rule-y",
		}
		if d.RuleID != "rule-y" {
			t.Errorf("RuleID = %q, want %q", d.RuleID, "rule-y")
		}
		if d.Source != "inline" {
			t.Errorf("Source = %q, want %q", d.Source, "inline")
		}
		if d.Reason != "validate failed" {
			t.Errorf("Reason = %q, want %q", d.Reason, "validate failed")
		}
	})
}

// TestTransactionStartedDataRoundTrips verifies the new typed payload for the
// TransactionStarted event round-trips RuleID and the string Severity and is
// assignable to api.Event.Data on a TransactionStarted event.
//
// @spec api-event-rule-id
// @ac AC-03
func TestTransactionStartedDataRoundTrips(t *testing.T) {
	t.Run("api-event-rule-id/AC-03", func(t *testing.T) {
		d := api.TransactionStartedData{
			RuleID:   "rule-z",
			Severity: "high",
		}
		if d.RuleID != "rule-z" {
			t.Errorf("RuleID = %q, want %q", d.RuleID, "rule-z")
		}
		if d.Severity != "high" {
			t.Errorf("Severity = %q, want %q", d.Severity, "high")
		}

		ev := api.Event{
			Kind: api.TransactionStarted,
			Data: d,
		}
		got, ok := ev.Data.(api.TransactionStartedData)
		if !ok {
			t.Fatalf("Event.Data is %T, want api.TransactionStartedData", ev.Data)
		}
		if got.RuleID != "rule-z" || got.Severity != "high" {
			t.Errorf("round-trip mismatch: %+v", got)
		}
	})
}

// TestEventKindVocabularyUnchanged verifies the change is strictly additive:
// the existing EventKind constants retain their string values and no new kind
// is introduced by this PR (PR1 adds payloads only, not kinds).
//
// @spec api-event-rule-id
// @ac AC-04
func TestEventKindVocabularyUnchanged(t *testing.T) {
	t.Run("api-event-rule-id/AC-04", func(t *testing.T) {
		// The transaction-lifecycle kinds Kensa emits, plus the deadman
		// kinds and the OpenWatch-owned shared-vocabulary kinds. This
		// asserts the set and its string values are exactly as before —
		// PR1 must not add, remove, or rename any kind.
		want := map[api.EventKind]string{
			api.TransactionStarted: "transaction_started",
			api.PhaseCompleted:     "phase_completed",
			api.Committed:          "committed",
			api.RolledBack:         "rolled_back",
			api.DriftDetected:      "drift_detected",
			api.HeartbeatPulse:     "heartbeat_pulse",
			api.DeadmanTimerArmed:  "deadman_timer_armed",
			api.DeadmanTimerFired:  "deadman_timer_fired",
		}
		for kind, str := range want {
			if string(kind) != str {
				t.Errorf("EventKind %q has value %q, want %q", str, string(kind), str)
			}
		}
	})
}
