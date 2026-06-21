package engine_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// capturingStore records every PersistResult call so a test can assert the
// durable row an errored transaction leaves behind. PersistPreStates and
// LoadPreStates are inert.
type capturingStore struct {
	mu      sync.Mutex
	results []*api.TransactionResult
}

func (s *capturingStore) PersistPreStates(context.Context, uuid.UUID, []api.PreState) error {
	return nil
}

func (s *capturingStore) PersistResult(_ context.Context, r *api.TransactionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, r)
	return nil
}

func (s *capturingStore) LoadPreStates(context.Context, uuid.UUID) ([]api.PreState, error) {
	return nil, nil
}

func (s *capturingStore) last() *api.TransactionResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.results) == 0 {
		return nil
	}
	return s.results[len(s.results)-1]
}

// persistFailStore accepts the pre-state write (so the transaction reaches
// commit) but fails to persist the terminal result — modeling a store that
// goes unwritable at the worst moment.
type persistFailStore struct{}

func (persistFailStore) PersistPreStates(context.Context, uuid.UUID, []api.PreState) error {
	return nil
}

func (persistFailStore) PersistResult(context.Context, *api.TransactionResult) error {
	return errors.New("induced persist failure")
}

func (persistFailStore) LoadPreStates(context.Context, uuid.UUID) ([]api.PreState, error) {
	return nil, nil
}

// signFailSigner models a key/HSM outage at commit time.
type signFailSigner struct{}

func (signFailSigner) Sign(*api.EvidenceEnvelope) ([]byte, string, error) {
	return nil, "", errors.New("induced signer failure")
}

func (signFailSigner) Verify(*api.EvidenceEnvelope) (*api.VerifyResult, error) {
	return nil, errors.New("signFailSigner: verify not implemented")
}

// durabilityEngine builds an engine with an isolated registry plus optional
// store/signer doubles.
func durabilityEngine(t *testing.T, store engine.Store, signer engine.Signer, handlers ...api.Handler) *engine.Engine {
	t.Helper()
	r := handler.NewRegistry()
	for _, h := range handlers {
		r.Register(h)
	}
	opts := []engine.Option{engine.WithRegistry(r)}
	if store != nil {
		opts = append(opts, engine.WithStore(store))
	}
	if signer != nil {
		opts = append(opts, engine.WithSigner(signer))
	}
	return engine.New(opts...)
}

// @spec engine-transaction
// @ac AC-12
func TestEngine_AC12_ErroredPersistsDurableUnsignedRow(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-12")
	store := &capturingStore{}
	h := &engine.FakeHandler{
		HandlerName:  "fake_cap_fails",
		IsCapturable: true,
		CaptureErr:   errors.New("induced capture failure"),
	}
	e := durabilityEngine(t, store, nil, h)

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_cap_fails"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusErrored {
		t.Fatalf("got Status=%s, want Errored", res.Status)
	}
	rec := store.last()
	if rec == nil {
		t.Fatal("errored transaction left no durable row in the store")
	}
	if rec.Envelope == nil {
		t.Fatal("errored row has a nil envelope; the durable store would reject it")
	}
	if rec.Envelope.Decision != api.StatusErrored {
		t.Errorf("errored envelope Decision=%s, want errored", rec.Envelope.Decision)
	}
	// Unsigned: the empty signature + errored decision is the marker
	// verification tooling keys on (C-06).
	if len(rec.Envelope.Signature) != 0 {
		t.Errorf("errored row must be unsigned; got %d signature bytes", len(rec.Envelope.Signature))
	}
}

// @spec engine-transaction
// @ac AC-13
func TestEngine_AC13_PersistFailureDemotesCommitted(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-13")
	h := &engine.FakeHandler{HandlerName: "fake_ok", IsCapturable: true}
	e := durabilityEngine(t, persistFailStore{}, nil, h)

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_ok"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusErrored {
		t.Errorf("a committed result that could not be persisted must demote to Errored; got %s", res.Status)
	}
	if res.Error == nil {
		t.Error("expected the persistence error surfaced in TransactionResult.Error")
	}
	if res.CommittedAt != nil {
		t.Error("a demoted result must not retain CommittedAt")
	}
}

// @spec engine-transaction
// @ac AC-14
func TestEngine_AC14_HostUnchangedPredicate(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-14")

	// Pre-apply (capture) failure: the host was never touched.
	capFail := &engine.FakeHandler{
		HandlerName:  "cap_fail",
		IsCapturable: true,
		CaptureErr:   errors.New("induced capture failure"),
	}
	e1 := durabilityEngine(t, nil, nil, capFail)
	res1, err := e1.Run(context.Background(), engine.NewFakeTransport(), basicTxn("cap_fail"), false)
	if err != nil {
		t.Fatalf("Run (capture-fail) returned err: %v", err)
	}
	if res1.Status != api.StatusErrored {
		t.Fatalf("capture-fail Status=%s, want Errored", res1.Status)
	}
	if !res1.HostUnchanged {
		t.Error("a pre-apply (capture) failure must report HostUnchanged=true")
	}

	// Signer failure AFTER a successful apply: the host was mutated and the
	// signing failure did not reverse it.
	ok := &engine.FakeHandler{HandlerName: "fake_ok2", IsCapturable: true}
	e2 := durabilityEngine(t, nil, signFailSigner{}, ok)
	res2, err := e2.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_ok2"), false)
	if err != nil {
		t.Fatalf("Run (signer-fail) returned err: %v", err)
	}
	if res2.Status != api.StatusErrored {
		t.Fatalf("signer-fail Status=%s, want Errored", res2.Status)
	}
	if res2.HostUnchanged {
		t.Error("a signer failure after a successful apply must report HostUnchanged=false (host mutated)")
	}
}

// @spec engine-transaction
// @ac AC-15
func TestEngine_AC15_RollbackResultsOnResultAndEnvelope(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-15")
	// Two steps: step 0 applies, step 1 fails → step 0 is rolled back,
	// producing a RollbackResult that must reach both surfaces.
	h0 := &engine.FakeHandler{
		HandlerName:    "s0",
		IsCapturable:   true,
		RollbackResult: &api.RollbackResult{Success: true, Detail: "s0 restored"},
	}
	h1 := &engine.FakeHandler{
		HandlerName:  "s1",
		IsCapturable: true,
		ApplyErr:     errors.New("induced apply failure"),
	}
	e := durabilityEngine(t, nil, nil, h0, h1)

	txn := &api.Transaction{
		ID:            uuid.New(),
		RuleID:        "test-rule",
		HostID:        "test-host",
		Steps:         []api.Step{{Index: 0, Mechanism: "s0"}, {Index: 1, Mechanism: "s1"}},
		StartedAt:     time.Now().UTC(),
		Deadline:      time.Now().Add(time.Minute),
		Transactional: true,
	}
	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusRolledBack {
		t.Fatalf("got Status=%s, want RolledBack", res.Status)
	}
	if len(res.RollbackResults) == 0 {
		t.Error("RollbackResults missing on TransactionResult after a rollback")
	}
	if res.Envelope == nil || len(res.Envelope.RollbackResults) == 0 {
		t.Error("RollbackResults missing on the evidence envelope after a rollback")
	}
}
