package engine_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// recaptureFailHandler captures successfully on the FIRST call (the capture
// phase) and errors on every subsequent call (the post-state recapture), so a
// test can drive the recapture-failure path without failing the capture phase.
type recaptureFailHandler struct {
	mu           sync.Mutex
	captureCalls int
}

func (h *recaptureFailHandler) Name() string     { return "recapture_fail" }
func (h *recaptureFailHandler) Capturable() bool { return true }
func (h *recaptureFailHandler) Apply(context.Context, api.Transport, api.Params, *api.PreState) (*api.StepResult, error) {
	return &api.StepResult{Success: true}, nil
}

func (h *recaptureFailHandler) Capture(context.Context, api.Transport, api.Params) (*api.PreState, error) {
	h.mu.Lock()
	h.captureCalls++
	n := h.captureCalls
	h.mu.Unlock()
	if n == 1 {
		return &api.PreState{Data: map[string]interface{}{"v": "pre"}}, nil
	}
	return nil, errors.New("induced recapture failure")
}

func (h *recaptureFailHandler) Rollback(context.Context, api.Transport, *api.PreState) (*api.RollbackResult, error) {
	return &api.RollbackResult{Success: true}, nil
}

func postStateFor(env *api.EvidenceEnvelope, stepIndex int) *api.PreState {
	if env == nil {
		return nil
	}
	for i := range env.PostStateBundle {
		if env.PostStateBundle[i].StepIndex == stepIndex {
			return &env.PostStateBundle[i]
		}
	}
	return nil
}

// @spec engine-transaction
// @ac AC-22
func TestEngine_AC22_CommitRecapturesPostState(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-22")
	h := &engine.FakeHandler{HandlerName: "rc_commit", IsCapturable: true}
	e := durabilityEngine(t, nil, nil, h)

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("rc_commit"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Fatalf("got Status=%s, want Committed", res.Status)
	}
	ps := postStateFor(res.Envelope, 0)
	if ps == nil {
		t.Fatal("committed envelope has no PostStateBundle entry for step 0 (no re-measurement)")
	}
	if v, ok := ps.Data["__post_state__"]; ok && v == "unobserved" {
		t.Errorf("post-state should have been observed for a healthy capture handler; got %+v", ps.Data)
	}
}

// @spec engine-transaction
// @ac AC-23
func TestEngine_AC23_RollbackRecapturesAndMatches(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-23")
	// Two steps: step 0 applies (capturable), step 1 fails -> step 0 reversed.
	h0 := &engine.FakeHandler{
		HandlerName:    "rc_s0",
		IsCapturable:   true,
		RollbackResult: &api.RollbackResult{Success: true, Detail: "restored"},
	}
	h1 := &engine.FakeHandler{HandlerName: "rc_s1", IsCapturable: true, ApplyErr: errors.New("boom")}
	e := durabilityEngine(t, nil, nil, h0, h1)

	txn := &api.Transaction{
		ID:            uuid.New(),
		RuleID:        "test-rule",
		HostID:        "test-host",
		Steps:         []api.Step{{Index: 0, Mechanism: "rc_s0"}, {Index: 1, Mechanism: "rc_s1"}},
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
	if postStateFor(res.Envelope, 0) == nil {
		t.Error("rolled-back envelope has no PostStateBundle entry for the reversed step")
	}
	// The reversed step's RollbackResult records the pre/post comparison.
	var found bool
	for _, r := range res.RollbackResults {
		if r.StepIndex == 0 && strings.Contains(r.Detail, "post-state:") {
			found = true
		}
	}
	if !found {
		t.Errorf("reversed step's RollbackResult should record the post-state comparison; got %+v", res.RollbackResults)
	}
}

// @spec engine-transaction
// @ac AC-24
func TestEngine_AC24_RecaptureFailureIsUnobservedNotFatal(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-24")
	h := &recaptureFailHandler{}
	r := handler.NewRegistry()
	r.Register(h)
	e := engine.New(engine.WithRegistry(r))

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("recapture_fail"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	// Recapture errored, but the transaction still committed — recapture is
	// observational and must never fail the transaction.
	if res.Status != api.StatusCommitted {
		t.Fatalf("a recapture failure must NOT change the terminal status; got %s", res.Status)
	}
	ps := postStateFor(res.Envelope, 0)
	if ps == nil {
		t.Fatal("expected an (unobserved) PostStateBundle entry for the step")
	}
	if v := ps.Data["__post_state__"]; v != "unobserved" {
		t.Errorf("a failed recapture must be marked unobserved; got Data=%+v", ps.Data)
	}
}
