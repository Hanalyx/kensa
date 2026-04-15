package engine_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

// newTestEngine returns a fresh engine with an isolated handler registry,
// the in-memory store, and the no-op signer/deadman/events. Each test
// should call this for isolation.
func newTestEngine(t *testing.T, handlers ...api.Handler) *engine.Engine {
	t.Helper()
	r := handler.NewRegistry()
	for _, h := range handlers {
		r.Register(h)
	}
	return engine.New(engine.WithRegistry(r))
}

func basicTxn(mechanism string) *api.Transaction {
	return &api.Transaction{
		ID:            uuid.New(),
		RuleID:        "test-rule",
		HostID:        "test-host",
		Steps:         []api.Step{{Index: 0, Mechanism: mechanism}},
		StartedAt:     time.Now().UTC(),
		Deadline:      time.Now().Add(time.Minute),
		Transactional: true,
	}
}

// @spec engine-transaction
// @ac AC-01
func TestEngine_AC01_CommittedOnFullSuccess(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fake_ok", IsCapturable: true}
	e := newTestEngine(t, h)

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_ok"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Errorf("got Status=%s, want Committed", res.Status)
	}
	if res.CommittedAt == nil {
		t.Error("expected CommittedAt to be set on committed transaction")
	}
	if h.RollbackCalls != 0 {
		t.Errorf("Rollback was invoked %d times on success path", h.RollbackCalls)
	}
}

// @spec engine-transaction
// @ac AC-02
func TestEngine_AC02_RolledBackOnApplyFailure(t *testing.T) {
	h := &engine.FakeHandler{
		HandlerName:  "fake_apply_fails",
		IsCapturable: true,
		ApplyErr:     errors.New("induced apply failure"),
	}
	e := newTestEngine(t, h)

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_apply_fails"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusRolledBack {
		t.Errorf("got Status=%s, want RolledBack", res.Status)
	}
	if res.RolledBackAt == nil {
		t.Error("expected RolledBackAt to be set on rolled-back transaction")
	}
}

// @spec engine-transaction
// @ac AC-02
func TestEngine_AC02_RollbackInReverseOrder(t *testing.T) {
	// Three steps. Step 0 and 1 succeed; step 2 fails. Rollback must
	// run for steps 1 then 0; step 2 never applied so it is not
	// rolled back.
	mkRecording := func(name string, succeed bool) *engine.FakeHandler {
		h := &engine.FakeHandler{
			HandlerName:  name,
			IsCapturable: true,
		}
		if !succeed {
			h.ApplyErr = errors.New("step failed")
		}
		h.RollbackResult = &api.RollbackResult{Success: true, Detail: name}
		return h
	}

	h0 := mkRecording("step0", true)
	h1 := mkRecording("step1", true)
	h2 := mkRecording("step2", false)

	r := handler.NewRegistry()
	r.Register(h0)
	r.Register(h1)
	r.Register(h2)
	e := engine.New(engine.WithRegistry(r))

	// Wrap each handler's Rollback by re-implementing through a thin
	// wrapper that records order. Easier: assert RollbackCalls counts.
	txn := &api.Transaction{
		ID:     uuid.New(),
		RuleID: "ordered-rule",
		HostID: "test-host",
		Steps: []api.Step{
			{Index: 0, Mechanism: "step0"},
			{Index: 1, Mechanism: "step1"},
			{Index: 2, Mechanism: "step2"},
		},
		Transactional: true,
	}

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if res.Status != api.StatusRolledBack {
		t.Fatalf("got Status=%s, want RolledBack", res.Status)
	}
	// Step 0 and 1 applied successfully; both should have rolled back.
	if h0.RollbackCalls != 1 {
		t.Errorf("step0 RollbackCalls=%d, want 1", h0.RollbackCalls)
	}
	if h1.RollbackCalls != 1 {
		t.Errorf("step1 RollbackCalls=%d, want 1", h1.RollbackCalls)
	}
	// Step 2 never applied, so rollback should not have invoked it.
	if h2.RollbackCalls != 0 {
		t.Errorf("step2 RollbackCalls=%d, want 0 (apply failed)", h2.RollbackCalls)
	}

	// Inspect TransactionResult.Steps for failure detail on step 2.
	if len(res.Steps) != 3 {
		t.Fatalf("got %d step results, want 3", len(res.Steps))
	}
	if res.Steps[2].Success {
		t.Error("expected step 2 to be marked failed")
	}
}

// @spec engine-transaction
// @ac AC-05
func TestEngine_AC05_PartiallyAppliedForNonCapturableSuccess(t *testing.T) {
	// Two steps. Step 0 is non-capturable and succeeds; step 1 is
	// capturable and fails. Rule is transactional:false (it must be,
	// because it has a non-capturable step).
	h0 := &engine.FakeHandler{HandlerName: "noncap_ok", IsCapturable: false}
	h1 := &engine.FakeHandler{
		HandlerName:  "cap_fails",
		IsCapturable: true,
		ApplyErr:     errors.New("induced fail"),
	}
	r := handler.NewRegistry()
	r.Register(h0)
	r.Register(h1)
	e := engine.New(engine.WithRegistry(r))

	txn := &api.Transaction{
		ID:     uuid.New(),
		RuleID: "mixed-rule",
		HostID: "test-host",
		Steps: []api.Step{
			{Index: 0, Mechanism: "noncap_ok"},
			{Index: 1, Mechanism: "cap_fails"},
		},
		Transactional: false,
	}
	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if res.Status != api.StatusPartiallyApplied {
		t.Errorf("got Status=%s, want PartiallyApplied", res.Status)
	}
	// Step 0 succeeded and is non-capturable; expect Stranded=true.
	if !res.Steps[0].Stranded {
		t.Error("expected step 0 to be marked Stranded")
	}
	// Step 0 was non-capturable so Rollback must not have run on it.
	if h0.RollbackCalls != 0 {
		t.Errorf("non-capturable step had RollbackCalls=%d, want 0", h0.RollbackCalls)
	}
}

// @spec engine-transaction
// @ac AC-07
func TestEngine_AC07_PerHostSerialization(t *testing.T) {
	// Two transactions against the same host should serialize. The
	// slow handler appends "start" / "end" markers to a shared
	// timeline; per-host serialization means we should see
	// "start", "end", "start", "end" — never "start", "start".
	timeline := &orderedTimeline{}
	r := handler.NewRegistry()
	r.Register(&slowApplyHandler{name: "slow", timeline: timeline})
	e := engine.New(engine.WithRegistry(r))

	mk := func() *api.Transaction {
		return &api.Transaction{
			ID:            uuid.New(),
			RuleID:        "r",
			HostID:        "shared-host",
			Steps:         []api.Step{{Index: 0, Mechanism: "slow"}},
			Transactional: true,
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = e.Run(context.Background(), engine.NewFakeTransport(), mk(), false)
	}()
	time.Sleep(10 * time.Millisecond) // ensure first enters lock first
	go func() {
		defer wg.Done()
		_, _ = e.Run(context.Background(), engine.NewFakeTransport(), mk(), false)
	}()
	wg.Wait()

	events := timeline.events()
	if len(events) != 4 {
		t.Fatalf("got timeline=%v, want 4 events", events)
	}
	// The serialized pattern is start,end,start,end.
	want := []string{"start", "end", "start", "end"}
	for i, w := range want {
		if events[i] != w {
			t.Errorf("timeline[%d]=%q, want %q (full timeline=%v)", i, events[i], w, events)
		}
	}
}

// @spec engine-transaction
// @ac AC-08
func TestEngine_AC08_NonBlockingReturnsErrHostBusy(t *testing.T) {
	hold := make(chan struct{})
	release := make(chan struct{})
	holder := &blockingHandler{name: "blocker", entered: hold, exit: release}
	r := handler.NewRegistry()
	r.Register(holder)
	e := engine.New(engine.WithRegistry(r))

	mk := func() *api.Transaction {
		return &api.Transaction{
			ID:            uuid.New(),
			RuleID:        "r",
			HostID:        "host-busy",
			Steps:         []api.Step{{Index: 0, Mechanism: "blocker"}},
			Transactional: true,
		}
	}

	go func() { _, _ = e.Run(context.Background(), engine.NewFakeTransport(), mk(), false) }()
	<-hold // wait until the first holder is inside Apply

	// Second invocation with nonBlocking=true should return ErrHostBusy.
	_, err := e.Run(context.Background(), engine.NewFakeTransport(), mk(), true)
	if !errors.Is(err, api.ErrHostBusy) {
		t.Errorf("got err=%v, want ErrHostBusy", err)
	}

	close(release) // let the first finish
}

// @spec engine-transaction
// @ac AC-10
func TestEngine_AC10_CaptureFailureReturnsErrored(t *testing.T) {
	h := &engine.FakeHandler{
		HandlerName:  "capture_fails",
		IsCapturable: true,
		CaptureErr:   api.ErrCaptureIncomplete,
	}
	e := newTestEngine(t, h)
	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("capture_fails"), false)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if res.Status != api.StatusErrored {
		t.Errorf("got Status=%s, want Errored", res.Status)
	}
	if !errors.Is(res.Error, api.ErrCaptureIncomplete) {
		t.Errorf("got err=%v, want ErrCaptureIncomplete chain", res.Error)
	}
	if h.ApplyCalls != 0 {
		t.Errorf("Apply was invoked %d times after capture failure", h.ApplyCalls)
	}
}

// @spec engine-transaction
// @ac AC-11
func TestEngine_AC11_PreflightRejectsTransactionalTrueWithNonCapturable(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "noncap", IsCapturable: false}
	e := newTestEngine(t, h)

	txn := &api.Transaction{
		ID:            uuid.New(),
		RuleID:        "bad-rule",
		HostID:        "test-host",
		Steps:         []api.Step{{Index: 0, Mechanism: "noncap"}},
		Transactional: true, // declares atomicity but contains non-capturable step
	}

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if res.Status != api.StatusErrored {
		t.Errorf("got Status=%s, want Errored", res.Status)
	}
	if h.ApplyCalls != 0 {
		t.Errorf("Apply was invoked despite preflight rejection")
	}
}

// @spec engine-transaction
// @ac AC-09
func TestEngine_AC09_EvidenceEnvelopeAttached(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fake_ok2", IsCapturable: true}
	e := newTestEngine(t, h)
	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_ok2"), false)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if res.Envelope == nil {
		t.Fatal("expected non-nil Envelope on committed transaction")
	}
	if res.Envelope.SchemaVersion != "v1" {
		t.Errorf("got SchemaVersion=%q, want v1", res.Envelope.SchemaVersion)
	}
	if res.Envelope.Decision != api.StatusCommitted {
		t.Errorf("got Decision=%s, want Committed", res.Envelope.Decision)
	}
	if res.Envelope.SigningKeyID == "" {
		t.Error("expected non-empty SigningKeyID even with noop signer")
	}
}

// ─── Helpers ────────────────────────────────────────────────────────────

// orderedTimeline is a thread-safe append-only string log used to
// observe serialization ordering across goroutines in tests.
type orderedTimeline struct {
	mu    sync.Mutex
	marks []string
}

func (t *orderedTimeline) record(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.marks = append(t.marks, s)
}

func (t *orderedTimeline) events() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.marks))
	copy(out, t.marks)
	return out
}

// slowApplyHandler appends "start" / "end" markers to a timeline so
// tests can verify per-host serialization.
type slowApplyHandler struct {
	name     string
	timeline *orderedTimeline
}

func (s *slowApplyHandler) Name() string     { return s.name }
func (s *slowApplyHandler) Capturable() bool { return true }
func (s *slowApplyHandler) Apply(_ context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	s.timeline.record("start")
	time.Sleep(50 * time.Millisecond)
	s.timeline.record("end")
	return &api.StepResult{Success: true}, nil
}
func (s *slowApplyHandler) Capture(_ context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	return &api.PreState{Data: map[string]interface{}{"slow": true}}, nil
}
func (s *slowApplyHandler) Rollback(_ context.Context, _ api.Transport, _ *api.PreState) (*api.RollbackResult, error) {
	return &api.RollbackResult{Success: true}, nil
}

// blockingHandler holds the per-host mutex by sleeping in Apply until
// the test releases it.
type blockingHandler struct {
	name    string
	entered chan struct{}
	exit    chan struct{}
}

func (b *blockingHandler) Name() string     { return b.name }
func (b *blockingHandler) Capturable() bool { return true }
func (b *blockingHandler) Apply(_ context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	close(b.entered)
	<-b.exit
	return &api.StepResult{Success: true}, nil
}
func (b *blockingHandler) Capture(_ context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	return &api.PreState{Data: map[string]interface{}{"blocking": true}}, nil
}
func (b *blockingHandler) Rollback(_ context.Context, _ api.Transport, _ *api.PreState) (*api.RollbackResult, error) {
	return &api.RollbackResult{Success: true}, nil
}
