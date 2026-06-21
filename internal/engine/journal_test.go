package engine_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
)

// journalRecorderStore implements Store + the optional JournalStore and
// records the journal lifecycle so a test can assert the engine writes the
// entry in PREPARE and clears it at terminal.
type journalRecorderStore struct {
	mu       sync.Mutex
	prepared map[uuid.UUID]api.JournalEntry
	pre      map[uuid.UUID][]api.PreState
	results  map[uuid.UUID]bool
	cleared  map[uuid.UUID]bool
}

func newJournalRecorderStore() *journalRecorderStore {
	return &journalRecorderStore{
		prepared: map[uuid.UUID]api.JournalEntry{},
		pre:      map[uuid.UUID][]api.PreState{},
		results:  map[uuid.UUID]bool{},
		cleared:  map[uuid.UUID]bool{},
	}
}

func (s *journalRecorderStore) PersistPreStates(_ context.Context, txnID uuid.UUID, pre []api.PreState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pre[txnID] = pre
	return nil
}

func (s *journalRecorderStore) PersistResult(_ context.Context, r *api.TransactionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[r.TransactionID] = true
	return nil
}

func (s *journalRecorderStore) LoadPreStates(_ context.Context, txnID uuid.UUID) ([]api.PreState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pre[txnID], nil
}

func (s *journalRecorderStore) PrepareTransaction(_ context.Context, e api.JournalEntry, pre []api.PreState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prepared[e.TxnID] = e
	s.pre[e.TxnID] = pre
	return nil
}

func (s *journalRecorderStore) AdvanceJournalCursor(context.Context, uuid.UUID, int) error {
	return nil
}

func (s *journalRecorderStore) LoadOpenJournalEntries(context.Context) ([]api.JournalEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.JournalEntry
	for id, e := range s.prepared {
		if !s.results[id] && !s.cleared[id] {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *journalRecorderStore) ClearJournalEntry(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleared[id] = true
	return nil
}

func (s *journalRecorderStore) wasPrepared(id uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.prepared[id]
	return ok
}

func (s *journalRecorderStore) wasCleared(id uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleared[id]
}

// @spec recovery-journal
// @ac AC-03
func TestEngine_RecoveryJournal_AC03_RunWritesAndClears(t *testing.T) {
	t.Log("// @spec recovery-journal")
	t.Log("// @ac AC-03")
	js := newJournalRecorderStore()
	h := &engine.FakeHandler{HandlerName: "j_ok", IsCapturable: true}
	e := durabilityEngine(t, js, nil, h)

	txn := basicTxn("j_ok")
	txnID := txn.ID
	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Fatalf("got Status=%s, want Committed", res.Status)
	}
	if !js.wasPrepared(txnID) {
		t.Error("engine did not write the journal entry in PREPARE")
	}
	if !js.wasCleared(txnID) {
		t.Error("engine did not clear the journal entry at terminal")
	}
	open, err := js.LoadOpenJournalEntries(context.Background())
	if err != nil {
		t.Fatalf("LoadOpenJournalEntries: %v", err)
	}
	for _, en := range open {
		if en.TxnID == txnID {
			t.Error("a committed transaction must leave no open journal entry")
		}
	}
}
