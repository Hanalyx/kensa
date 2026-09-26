package engine_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
	"github.com/Hanalyx/kensa/internal/store"
)

// These tests exercise recovery's identity checks through the existing
// Recover surface only: which handlers run, in what order, with which
// pre-state, and what the store holds afterwards. Assertions about the
// refusal report itself live in recover_refusal_report_test.go.

// rollbackLog records every Rollback call a recordingHandler receives, in
// order, as "mechanism=value" where value is the pre-state's Data["v"].
type rollbackLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *rollbackLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, s)
}

func (l *rollbackLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

// recordingHandler is a capturable (or not) handler whose Rollback records
// which pre-state it was handed. Recording the data, not just the call,
// is what lets a test detect a restoration dispatched with the wrong
// pre-state.
type recordingHandler struct {
	name       string
	capturable bool
	log        *rollbackLog
}

func (h *recordingHandler) Name() string     { return h.name }
func (h *recordingHandler) Capturable() bool { return h.capturable }

func (h *recordingHandler) Apply(_ context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	return &api.StepResult{Success: true}, nil
}

func (h *recordingHandler) Capture(_ context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	return &api.PreState{Data: map[string]any{"v": h.name}}, nil
}

func (h *recordingHandler) Rollback(_ context.Context, _ api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	h.log.add(fmt.Sprintf("%s=%v", h.name, pre.Data["v"]))
	return &api.RollbackResult{Success: true}, nil
}

// captureOnlyHandler claims capturability but cannot roll back. It keeps
// today's handler-level failure path covered: that is a reversal failure,
// not an identity failure.
type captureOnlyHandler struct{ name string }

func (h *captureOnlyHandler) Name() string     { return h.name }
func (h *captureOnlyHandler) Capturable() bool { return true }
func (h *captureOnlyHandler) Apply(_ context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	return &api.StepResult{Success: true}, nil
}
func (h *captureOnlyHandler) Capture(_ context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	return &api.PreState{Data: map[string]any{"v": h.name}}, nil
}

// identityRig is one isolated store plus a registry of recording handlers.
type identityRig struct {
	t   *testing.T
	st  *store.SQLite
	log *rollbackLog
	reg *handler.Registry
}

func newIdentityRig(t *testing.T) *identityRig {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "recover.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rig := &identityRig{t: t, st: st, log: &rollbackLog{}, reg: handler.NewRegistry()}
	for _, name := range []string{"cap_a", "cap_b", "cap_c", "cap_z"} {
		rig.reg.Register(&recordingHandler{name: name, capturable: true, log: rig.log})
	}
	rig.reg.Register(&recordingHandler{name: "noncap_n", capturable: false, log: rig.log})
	rig.reg.Register(&captureOnlyHandler{name: "cap_norollback"})
	return rig
}

func (r *identityRig) engine() *engine.Engine {
	return engine.New(engine.WithRegistry(r.reg), engine.WithStore(r.st))
}

// crash journals a transaction that was prepared and never finalized.
func (r *identityRig) crash(host string, intent []api.Step, pre []api.PreState) uuid.UUID {
	r.t.Helper()
	id := uuid.New()
	entry := api.JournalEntry{
		TxnID: id, HostID: host, RuleID: "crashed-rule", Transactional: true,
		Phase: "applying", Cursor: len(intent) - 1, Intent: intent, CreatedAt: time.Now().UTC(),
	}
	if err := r.st.PrepareTransaction(context.Background(), entry, pre); err != nil {
		r.t.Fatalf("PrepareTransaction: %v", err)
	}
	return id
}

func (r *identityRig) isOpen(id uuid.UUID) bool {
	r.t.Helper()
	open, err := r.st.LoadOpenJournalEntries(context.Background())
	if err != nil {
		r.t.Fatalf("LoadOpenJournalEntries: %v", err)
	}
	for _, e := range open {
		if e.TxnID == id {
			return true
		}
	}
	return false
}

func (r *identityRig) hasTerminal(id uuid.UUID) bool {
	_, err := r.st.Get(context.Background(), id, api.WithoutEnvelope(), api.WithoutPreStates())
	return err == nil
}

// recoverSafely runs Recover and turns a panic into a returned value, so a
// test can assert "no panic" rather than dying.
func recoverSafely(e *engine.Engine, host string) (res []*api.TransactionResult, panicked any, err error) {
	defer func() { panicked = recover() }()
	res, err = e.Recover(context.Background(), engine.NewFakeTransport(), host)
	return
}

func step(i int, m string) api.Step { return api.Step{Index: i, Mechanism: m} }

func pre(i int, m string, capturable bool) api.PreState {
	return api.PreState{StepIndex: i, Mechanism: m, Capturable: capturable,
		CapturedAt: time.Now().UTC(), Data: map[string]any{"v": m}}
}

// assertRefused checks the baseline-observable half of a refusal: no panic,
// no handler call, no terminal record, the journal entry still open, and no
// result claiming the transaction was recovered.
func assertRefused(t *testing.T, rig *identityRig, id uuid.UUID, res []*api.TransactionResult, panicked any) {
	t.Helper()
	if panicked != nil {
		t.Fatalf("recovery panicked: %v", panicked)
	}
	if calls := rig.log.snapshot(); len(calls) != 0 {
		t.Errorf("a refused entry dispatched restorations: %v", calls)
	}
	if rig.hasTerminal(id) {
		t.Error("a refused entry received a terminal record")
	}
	if !rig.isOpen(id) {
		t.Error("a refused entry's journal entry was cleared")
	}
	for _, r := range res {
		if r.TransactionID == id {
			t.Errorf("a refused entry produced a result with status %s", r.Status)
		}
	}
}

// @spec recovery-replay
// @ac AC-06
func TestRecoverIdentity_CleanBundleUnchanged(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-06")
	rig := newIdentityRig(t)
	id := rig.crash("h", []api.Step{step(0, "cap_a"), step(1, "cap_b"), step(2, "cap_c")},
		[]api.PreState{pre(0, "cap_a", true), pre(1, "cap_b", true), pre(2, "cap_c", true)})

	res, panicked, err := recoverSafely(rig.engine(), "h")
	if panicked != nil || err != nil {
		t.Fatalf("recover: panic=%v err=%v", panicked, err)
	}
	// Reverse step order, each handler exactly once, each with its own
	// pre-state. A swapped pre-state or a changed order fails here.
	want := []string{"cap_c=cap_c", "cap_b=cap_b", "cap_a=cap_a"}
	if got := rig.log.snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("dispatch = %v, want %v", got, want)
	}
	if len(res) != 1 || res[0].Status != api.StatusRecovered {
		t.Fatalf("got %d results, want one recovered", len(res))
	}
	if rig.isOpen(id) {
		t.Error("a recovered entry's journal entry was left open")
	}
}

// @spec recovery-replay
// @ac AC-07
func TestRecoverIdentity_RefusedConditions(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-07")
	cases := []struct {
		name   string
		intent []api.Step
		pre    []api.PreState
	}{
		{"zero eligible: capturability disagreement on every step",
			[]api.Step{step(0, "noncap_n"), step(1, "noncap_n")},
			[]api.PreState{pre(0, "noncap_n", true), pre(1, "noncap_n", true)}},
		{"mixed valid and mismatched",
			[]api.Step{step(0, "cap_a"), step(1, "cap_b")},
			[]api.PreState{pre(0, "cap_a", true), pre(1, "cap_z", true)}},
		{"duplicate intent index",
			[]api.Step{step(0, "cap_a"), step(0, "cap_b")},
			[]api.PreState{pre(0, "cap_a", true)}},
		{"pre-state with no matching intent",
			[]api.Step{step(0, "cap_a")},
			[]api.PreState{pre(0, "cap_a", true), pre(5, "cap_b", true)}},
		{"missing pre-state",
			[]api.Step{step(0, "cap_a"), step(1, "cap_b")},
			[]api.PreState{pre(0, "cap_a", true)}},
		{"empty bundle behind a non-empty intent",
			[]api.Step{step(0, "cap_a")},
			nil},
		{"mechanism mismatch",
			[]api.Step{step(0, "cap_a")},
			[]api.PreState{pre(0, "cap_z", true)}},
		{"unknown capturable mechanism",
			[]api.Step{step(0, "ghost")},
			[]api.PreState{pre(0, "ghost", true)}},
		{"unknown non-capturable marker",
			[]api.Step{step(0, "ghost_marker")},
			[]api.PreState{pre(0, "ghost_marker", false)}},
		{"capturable claimed, handler not capturable",
			[]api.Step{step(0, "noncap_n")},
			[]api.PreState{pre(0, "noncap_n", true)}},
		{"not capturable claimed, handler capturable",
			[]api.Step{step(0, "cap_a")},
			[]api.PreState{pre(0, "cap_a", false)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newIdentityRig(t)
			id := rig.crash("h", tc.intent, tc.pre)
			res, panicked, _ := recoverSafely(rig.engine(), "h")
			assertRefused(t, rig, id, res, panicked)
		})
	}
}

// @spec recovery-replay
// @ac AC-07
func TestRecoverIdentity_DuplicatePreStateIndex(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-07")
	// SQLite keys pre_states on (transaction, step), so a duplicate index
	// cannot be stored there. Another JournalStore can return one, so it
	// is exercised through the in-memory journal store.
	js := newJournalRecorderStore()
	log := &rollbackLog{}
	r := handler.NewRegistry()
	r.Register(&recordingHandler{name: "cap_a", capturable: true, log: log})
	id := uuid.New()
	entry := api.JournalEntry{TxnID: id, HostID: "h", RuleID: "r", Transactional: true,
		Phase: "applying", Intent: []api.Step{step(0, "cap_a")}, CreatedAt: time.Now().UTC()}
	if err := js.PrepareTransaction(context.Background(), entry,
		[]api.PreState{pre(0, "cap_a", true), pre(0, "cap_a", true)}); err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.WithRegistry(r), engine.WithStore(js))
	res, panicked, _ := recoverSafely(e, "h")
	if panicked != nil {
		t.Fatalf("recovery panicked: %v", panicked)
	}
	if calls := log.snapshot(); len(calls) != 0 {
		t.Errorf("an ambiguous bundle dispatched restorations: %v", calls)
	}
	if len(res) != 0 {
		t.Errorf("an ambiguous bundle produced %d results", len(res))
	}
}

// @spec recovery-replay
// @ac AC-07
func TestRecoverIdentity_ValidNonCapturableMarkerNotDispatched(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-07")
	// A matching non-capturable marker is valid identity and stays
	// undispatched, as today. What recovery then reports for it is not
	// changed here.
	rig := newIdentityRig(t)
	rig.crash("h", []api.Step{step(0, "noncap_n")}, []api.PreState{pre(0, "noncap_n", false)})
	if _, panicked, _ := recoverSafely(rig.engine(), "h"); panicked != nil {
		t.Fatalf("recovery panicked: %v", panicked)
	}
	if calls := rig.log.snapshot(); len(calls) != 0 {
		t.Errorf("a non-capturable marker was dispatched: %v", calls)
	}
}

// @spec recovery-replay
// @ac AC-07
func TestRecoverIdentity_RefusalDoesNotBlockOtherEntries(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-07")
	rig := newIdentityRig(t)
	bad := rig.crash("h", []api.Step{step(0, "cap_a")}, []api.PreState{pre(0, "cap_z", true)})
	good := rig.crash("h", []api.Step{step(0, "cap_b")}, []api.PreState{pre(0, "cap_b", true)})

	res, panicked, _ := recoverSafely(rig.engine(), "h")
	if panicked != nil {
		t.Fatalf("recovery panicked: %v", panicked)
	}
	if calls := rig.log.snapshot(); fmt.Sprint(calls) != fmt.Sprint([]string{"cap_b=cap_b"}) {
		t.Errorf("dispatch = %v, want only the valid entry's step", calls)
	}
	if !rig.isOpen(bad) || rig.hasTerminal(bad) {
		t.Error("the refused entry was not left open without a terminal record")
	}
	if rig.isOpen(good) || !rig.hasTerminal(good) {
		t.Error("the valid entry was not recovered and cleared")
	}
	if len(res) != 1 || res[0].TransactionID != good {
		t.Errorf("results = %d, want exactly the valid entry", len(res))
	}
}

// @spec recovery-replay
// @ac AC-07
func TestRecoverIdentity_RerunRefusesAgain(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-07")
	rig := newIdentityRig(t)
	id := rig.crash("h", []api.Step{step(0, "cap_a")}, []api.PreState{pre(0, "cap_z", true)})
	for run := 1; run <= 2; run++ {
		res, panicked, _ := recoverSafely(rig.engine(), "h")
		assertRefused(t, rig, id, res, panicked)
	}
}

// @spec recovery-replay
// @ac AC-06
func TestRecoverIdentity_HandlerWithoutRollbackUnchanged(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-06")
	// Valid identity whose handler cannot roll back: today's handler-level
	// failure path, a rollback_failed verdict with a failure row. It is a
	// reversal failure, not an identity refusal, and must stay as it is.
	rig := newIdentityRig(t)
	id := rig.crash("h", []api.Step{step(0, "cap_norollback")},
		[]api.PreState{pre(0, "cap_norollback", true)})
	res, panicked, err := recoverSafely(rig.engine(), "h")
	if panicked != nil || err != nil {
		t.Fatalf("recover: panic=%v err=%v", panicked, err)
	}
	if len(res) != 1 || res[0].Status != api.StatusRollbackFailed {
		t.Fatalf("want one rollback_failed result, got %d", len(res))
	}
	if len(res[0].RollbackResults) != 1 || res[0].RollbackResults[0].Success {
		t.Error("the handler-level failure row is missing")
	}
	if rig.isOpen(id) {
		t.Error("a terminal rollback_failed entry was left open")
	}
}
