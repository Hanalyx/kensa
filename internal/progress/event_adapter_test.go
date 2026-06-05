package progress

import (
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// TestFromEvent_TransactionStarted pins the TransactionStarted -> TxnStarted
// mapping, including copying RuleID off the additive TransactionStartedData
// payload (PR1).
// @spec cli-remediate-stream
// @ac AC-01
func TestFromEvent_TransactionStarted(t *testing.T) {
	t.Run("cli-remediate-stream/AC-01", func(t *testing.T) {
		txnID := uuid.New()
		ev := api.Event{
			Kind:   api.TransactionStarted,
			TxnID:  &txnID,
			HostID: "web-01",
			Data:   api.TransactionStartedData{RuleID: "rule-a", Severity: "high"},
		}
		u, ok := FromEvent(ev)
		if !ok {
			t.Fatal("FromEvent(TransactionStarted) ok=false, want true")
		}
		if u.Kind != TxnStarted {
			t.Errorf("Kind = %v, want TxnStarted", u.Kind)
		}
		if u.RuleID != "rule-a" {
			t.Errorf("RuleID = %q, want %q", u.RuleID, "rule-a")
		}
		if u.Host != "web-01" {
			t.Errorf("Host = %q, want %q", u.Host, "web-01")
		}
	})
}

// TestFromEvent_PhaseCompleted pins PhaseCompleted -> TxnPhase, copying
// RuleID, Phase, and Success->OK off PhaseCompletedData.
// @spec cli-remediate-stream
// @ac AC-02
func TestFromEvent_PhaseCompleted(t *testing.T) {
	t.Run("cli-remediate-stream/AC-02", func(t *testing.T) {
		txnID := uuid.New()
		ev := api.Event{
			Kind:   api.PhaseCompleted,
			TxnID:  &txnID,
			HostID: "web-01",
			Data: api.PhaseCompletedData{
				Phase:   api.PhaseValidate,
				Success: true,
				RuleID:  "rule-b",
			},
		}
		u, ok := FromEvent(ev)
		if !ok {
			t.Fatal("FromEvent(PhaseCompleted) ok=false, want true")
		}
		if u.Kind != TxnPhase {
			t.Errorf("Kind = %v, want TxnPhase", u.Kind)
		}
		if u.RuleID != "rule-b" {
			t.Errorf("RuleID = %q, want %q", u.RuleID, "rule-b")
		}
		if u.Phase != api.PhaseValidate {
			t.Errorf("Phase = %q, want %q", u.Phase, api.PhaseValidate)
		}
		if !u.OK {
			t.Error("OK = false, want true (Success->OK)")
		}

		// A failed phase must carry OK=false.
		ev.Data = api.PhaseCompletedData{Phase: api.PhaseApply, Success: false, RuleID: "rule-b"}
		u, ok = FromEvent(ev)
		if !ok || u.OK {
			t.Errorf("failed PhaseCompleted: ok=%v OK=%v, want ok=true OK=false", ok, u.OK)
		}
	})
}

// TestFromEvent_TerminalKinds pins RolledBack -> TxnDone(OK=false) with RuleID
// and Committed -> TxnDone(OK=true) with an acceptable empty RuleID.
// @spec cli-remediate-stream
// @ac AC-03
func TestFromEvent_TerminalKinds(t *testing.T) {
	t.Run("cli-remediate-stream/AC-03", func(t *testing.T) {
		txnID := uuid.New()

		rb := api.Event{
			Kind:  api.RolledBack,
			TxnID: &txnID,
			Data:  api.RolledBackData{Source: "inline", RuleID: "rule-c"},
		}
		u, ok := FromEvent(rb)
		if !ok {
			t.Fatal("FromEvent(RolledBack) ok=false, want true")
		}
		if u.Kind != TxnDone {
			t.Errorf("RolledBack Kind = %v, want TxnDone", u.Kind)
		}
		if u.OK {
			t.Error("RolledBack OK = true, want false")
		}
		if u.RuleID != "rule-c" {
			t.Errorf("RolledBack RuleID = %q, want %q", u.RuleID, "rule-c")
		}

		// Committed has no Data payload; TxnDone OK=true with empty RuleID
		// is acceptable (preceding lines already named the rule).
		cm := api.Event{Kind: api.Committed, TxnID: &txnID}
		u, ok = FromEvent(cm)
		if !ok {
			t.Fatal("FromEvent(Committed) ok=false, want true")
		}
		if u.Kind != TxnDone {
			t.Errorf("Committed Kind = %v, want TxnDone", u.Kind)
		}
		if !u.OK {
			t.Error("Committed OK = false, want true")
		}
	})
}

// TestFromEvent_NonTransactionKinds pins that the OpenWatch-owned and deadman
// kinds are not rendered (ok=false) and that a nil or mismatched Data never
// panics.
// @spec cli-remediate-stream
// @ac AC-04
func TestFromEvent_NonTransactionKinds(t *testing.T) {
	t.Run("cli-remediate-stream/AC-04", func(t *testing.T) {
		for _, kind := range []api.EventKind{
			api.HeartbeatPulse,
			api.DriftDetected,
			api.DeadmanTimerArmed,
			api.DeadmanTimerFired,
		} {
			if _, ok := FromEvent(api.Event{Kind: kind}); ok {
				t.Errorf("FromEvent(%q) ok=true, want false (not a render-able kind)", kind)
			}
		}

		// Defensive: a transaction kind whose Data is nil or a wrong type
		// must not panic; the Update simply carries no RuleID.
		txnID := uuid.New()
		mismatched := []api.Event{
			{Kind: api.TransactionStarted, TxnID: &txnID, Data: nil},
			{Kind: api.PhaseCompleted, TxnID: &txnID, Data: "not-a-payload"},
			{Kind: api.RolledBack, TxnID: &txnID, Data: 42},
		}
		for _, ev := range mismatched {
			u, ok := FromEvent(ev) // must not panic
			if !ok {
				t.Errorf("FromEvent(%q, bad Data) ok=false, want true (kind still maps)", ev.Kind)
			}
			if u.RuleID != "" {
				t.Errorf("FromEvent(%q, bad Data) RuleID=%q, want empty", ev.Kind, u.RuleID)
			}
		}
	})
}
