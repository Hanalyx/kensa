package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

func sampleJournalEntry(txnID uuid.UUID, hostID string) api.JournalEntry {
	return api.JournalEntry{
		TxnID:         txnID,
		HostID:        hostID,
		RuleID:        "test-rule",
		Transactional: true,
		Phase:         "prepared",
		Cursor:        -1,
		Intent: []api.Step{
			{Index: 0, Mechanism: "file_permissions", Params: api.Params{"path": "/etc/x"}},
		},
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
}

func findEntry(entries []api.JournalEntry, txnID uuid.UUID) *api.JournalEntry {
	for i := range entries {
		if entries[i].TxnID == txnID {
			return &entries[i]
		}
	}
	return nil
}

// @spec recovery-journal
// @ac AC-01
func TestJournal_AC01_PrepareWritesAtomicAndOpen(t *testing.T) {
	t.Log("// @spec recovery-journal")
	t.Log("// @ac AC-01")
	s := newTestStore(t)
	ctx := context.Background()
	txnID := uuid.New()
	entry := sampleJournalEntry(txnID, "host-a")
	pre := []api.PreState{
		{StepIndex: 0, Mechanism: "file_permissions", Capturable: true, Data: map[string]interface{}{"mode": "0644"}, CapturedAt: time.Now().UTC()},
	}

	if err := s.PrepareTransaction(ctx, entry, pre); err != nil {
		t.Fatalf("PrepareTransaction: %v", err)
	}
	// Pre-states written in the same commit.
	got, err := s.LoadPreStates(ctx, txnID)
	if err != nil {
		t.Fatalf("LoadPreStates: %v", err)
	}
	if len(got) != 1 || got[0].Mechanism != "file_permissions" {
		t.Errorf("pre-states not persisted atomically with the journal: %+v", got)
	}
	// The entry is open (no terminal record yet) and round-trips.
	open, err := s.LoadOpenJournalEntries(ctx)
	if err != nil {
		t.Fatalf("LoadOpenJournalEntries: %v", err)
	}
	e := findEntry(open, txnID)
	if e == nil {
		t.Fatal("prepared transaction is not an open journal entry")
	}
	if e.RuleID != "test-rule" || len(e.Intent) != 1 || e.Intent[0].Mechanism != "file_permissions" {
		t.Errorf("journal entry did not round-trip: %+v", e)
	}
}

// @spec recovery-journal
// @ac AC-02
func TestJournal_AC02_TerminalResultClosesOpenEntry(t *testing.T) {
	t.Log("// @spec recovery-journal")
	t.Log("// @ac AC-02")
	s := newTestStore(t)
	ctx := context.Background()

	res := sampleTransaction(t, api.StatusCommitted, "r1", "host-b")
	txnID := res.TransactionID
	if err := s.PrepareTransaction(ctx, sampleJournalEntry(txnID, "host-b"), nil); err != nil {
		t.Fatalf("PrepareTransaction: %v", err)
	}
	if open, _ := s.LoadOpenJournalEntries(ctx); findEntry(open, txnID) == nil {
		t.Fatal("entry should be open before a terminal result")
	}

	// Persist the terminal record (the commit marker).
	if err := s.PersistResult(ctx, res); err != nil {
		t.Fatalf("PersistResult: %v", err)
	}
	open, err := s.LoadOpenJournalEntries(ctx)
	if err != nil {
		t.Fatalf("LoadOpenJournalEntries: %v", err)
	}
	if findEntry(open, txnID) != nil {
		t.Error("a transaction with a terminal record must NOT be an open journal entry")
	}
}

// @spec recovery-journal
// @ac AC-04
func TestJournal_AC04_AdvanceCursorAndClear(t *testing.T) {
	t.Log("// @spec recovery-journal")
	t.Log("// @ac AC-04")
	s := newTestStore(t)
	ctx := context.Background()
	txnID := uuid.New()
	if err := s.PrepareTransaction(ctx, sampleJournalEntry(txnID, "host-c"), nil); err != nil {
		t.Fatalf("PrepareTransaction: %v", err)
	}

	if err := s.AdvanceJournalCursor(ctx, txnID, 2); err != nil {
		t.Fatalf("AdvanceJournalCursor: %v", err)
	}
	open, _ := s.LoadOpenJournalEntries(ctx)
	if e := findEntry(open, txnID); e == nil || e.Cursor != 2 {
		t.Errorf("cursor not advanced; got %+v", e)
	}

	if err := s.ClearJournalEntry(ctx, txnID); err != nil {
		t.Fatalf("ClearJournalEntry: %v", err)
	}
	if open, _ := s.LoadOpenJournalEntries(ctx); findEntry(open, txnID) != nil {
		t.Error("cleared entry must not be returned")
	}
	// Clearing a non-existent entry is not an error.
	if err := s.ClearJournalEntry(ctx, uuid.New()); err != nil {
		t.Errorf("clearing a non-existent entry should be a no-op, got %v", err)
	}
}
