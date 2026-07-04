package engine_test

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

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
	// events is a shared, ordered trace of "cursor:<n>" (a cursor advance) and
	// "apply:<n>" (a step Apply) markers, used to assert the cursor is advanced
	// WRITE-AHEAD of the mutation it guards.
	events *[]string
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

func (s *journalRecorderStore) AdvanceJournalCursor(_ context.Context, txnID uuid.UUID, cursor int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.prepared[txnID]; ok {
		e.Cursor = cursor
		s.prepared[txnID] = e
	}
	if s.events != nil {
		*s.events = append(*s.events, "cursor:"+strconv.Itoa(cursor))
	}
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

// orderingHandler records "apply:<idx>" into a shared event trace when its
// step is applied, so a test can prove the engine advanced the journal cursor
// ("cursor:<idx>", recorded by journalRecorderStore.AdvanceJournalCursor)
// BEFORE the mutation it guards.
type orderingHandler struct {
	name   string
	idx    int
	events *[]string
	mu     *sync.Mutex
}

func (h *orderingHandler) Name() string     { return h.name }
func (h *orderingHandler) Capturable() bool { return true }

func (h *orderingHandler) Apply(_ context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	h.mu.Lock()
	*h.events = append(*h.events, "apply:"+strconv.Itoa(h.idx))
	h.mu.Unlock()
	return &api.StepResult{Success: true}, nil
}

func (h *orderingHandler) Capture(_ context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	return &api.PreState{StepIndex: h.idx, Mechanism: h.name, Capturable: true}, nil
}

func (h *orderingHandler) Rollback(_ context.Context, _ api.Transport, _ *api.PreState) (*api.RollbackResult, error) {
	return &api.RollbackResult{Success: true}, nil
}

// @spec recovery-journal
// @ac AC-05
func TestEngine_RecoveryJournal_AC05_CursorAdvancesWriteAhead(t *testing.T) {
	t.Log("// @spec recovery-journal")
	t.Log("// @ac AC-05")
	var (
		events []string
		mu     sync.Mutex
	)
	js := newJournalRecorderStore()
	js.events = &events

	handlers := make([]api.Handler, 3)
	steps := make([]api.Step, 3)
	for i := 0; i < 3; i++ {
		name := "wa_step" + strconv.Itoa(i)
		handlers[i] = &orderingHandler{name: name, idx: i, events: &events, mu: &mu}
		steps[i] = api.Step{Index: i, Mechanism: name}
	}
	e := durabilityEngine(t, js, nil, handlers...)

	txn := &api.Transaction{
		ID:            uuid.New(),
		RuleID:        "wa-rule",
		HostID:        "wa-host",
		Steps:         steps,
		StartedAt:     time.Now().UTC(),
		Deadline:      time.Now().Add(time.Minute),
		Transactional: true,
	}
	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Fatalf("got Status=%s, want Committed", res.Status)
	}

	// The cursor for step N MUST be recorded before step N's Apply runs, for
	// every step, in order (recovery-journal C-03 write-ahead).
	want := []string{"cursor:0", "apply:0", "cursor:1", "apply:1", "cursor:2", "apply:2"}
	if len(events) != len(want) {
		t.Fatalf("event trace = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("event[%d] = %q, want %q (full trace %v)", i, events[i], want[i], events)
		}
	}
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
