package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
)

// prepareCrashedTxn writes a journal entry + pre-state for a transaction that
// was prepared but never finalized — i.e. the engine crashed mid-flight.
func prepareCrashedTxn(t *testing.T, js *journalRecorderStore, mechanism, hostID string) uuid.UUID {
	t.Helper()
	txnID := uuid.New()
	entry := api.JournalEntry{
		TxnID:         txnID,
		HostID:        hostID,
		RuleID:        "crashed-rule",
		Transactional: true,
		Phase:         "prepared",
		Cursor:        -1,
		Intent:        []api.Step{{Index: 0, Mechanism: mechanism}},
		CreatedAt:     time.Now().UTC(),
	}
	pre := []api.PreState{
		{StepIndex: 0, Mechanism: mechanism, Capturable: true, Data: map[string]interface{}{"v": "pre"}},
	}
	if err := js.PrepareTransaction(context.Background(), entry, pre); err != nil {
		t.Fatalf("PrepareTransaction: %v", err)
	}
	return txnID
}

// @spec recovery-replay
// @ac AC-01
func TestEngine_Recover_AC01_CompensatesOpenEntry(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-01")
	js := newJournalRecorderStore()
	h := &engine.FakeHandler{
		HandlerName:    "rec_mech",
		IsCapturable:   true,
		RollbackResult: &api.RollbackResult{Success: true, Detail: "restored"},
	}
	e := durabilityEngine(t, js, nil, h)

	txnID := prepareCrashedTxn(t, js, "rec_mech", "host-x")

	results, err := e.Recover(context.Background(), engine.NewFakeTransport(), "host-x")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 recovered transaction, got %d", len(results))
	}
	if results[0].Status != api.StatusRecovered {
		t.Errorf("recovered transaction status = %s, want recovered", results[0].Status)
	}
	if h.RollbackCalls != 1 {
		t.Errorf("recovery should drive exactly one rollback; got %d", h.RollbackCalls)
	}
	// Journal cleared (no open entry remains) and terminal record persisted.
	if !js.wasCleared(txnID) {
		t.Error("recovered transaction's journal entry was not cleared")
	}
	open, _ := js.LoadOpenJournalEntries(context.Background())
	for _, en := range open {
		if en.TxnID == txnID {
			t.Error("recovered transaction must leave no open journal entry")
		}
	}
}

// @spec recovery-replay
// @ac AC-02
func TestEngine_Recover_AC02_Idempotent(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-02")
	js := newJournalRecorderStore()
	h := &engine.FakeHandler{HandlerName: "rec_mech", IsCapturable: true, RollbackResult: &api.RollbackResult{Success: true}}
	e := durabilityEngine(t, js, nil, h)
	prepareCrashedTxn(t, js, "rec_mech", "host-y")

	if r, _ := e.Recover(context.Background(), engine.NewFakeTransport(), "host-y"); len(r) != 1 {
		t.Fatalf("first Recover should compensate 1, got %d", len(r))
	}
	// Second run finds nothing — the terminal record removed it from the open set.
	r2, err := e.Recover(context.Background(), engine.NewFakeTransport(), "host-y")
	if err != nil {
		t.Fatalf("second Recover: %v", err)
	}
	if len(r2) != 0 {
		t.Errorf("second Recover should be a no-op (idempotent); got %d results", len(r2))
	}
}

// @spec recovery-replay
// @ac AC-03
func TestEngine_Recover_AC03_HostScoped(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-03")
	js := newJournalRecorderStore()
	h := &engine.FakeHandler{HandlerName: "rec_mech", IsCapturable: true, RollbackResult: &api.RollbackResult{Success: true}}
	e := durabilityEngine(t, js, nil, h)

	mine := prepareCrashedTxn(t, js, "rec_mech", "host-mine")
	other := prepareCrashedTxn(t, js, "rec_mech", "host-other")

	results, err := e.Recover(context.Background(), engine.NewFakeTransport(), "host-mine")
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(results) != 1 || results[0].TransactionID != mine {
		t.Fatalf("expected only host-mine recovered; got %+v", results)
	}
	// host-other's entry is untouched (still open).
	open, _ := js.LoadOpenJournalEntries(context.Background())
	if findOpen(open, other) == nil {
		t.Error("an entry for a different host must be left open")
	}
	if findOpen(open, mine) != nil {
		t.Error("the recovered host's entry must be cleared")
	}
}

func findOpen(entries []api.JournalEntry, id uuid.UUID) *api.JournalEntry {
	for i := range entries {
		if entries[i].TxnID == id {
			return &entries[i]
		}
	}
	return nil
}
