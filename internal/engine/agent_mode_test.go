package engine_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

// fakeAgentClient implements engine.AgentClient for tests.
// Records every Apply/Capture/Rollback call and returns
// canned StepResult / PreState / RollbackResult.
type fakeAgentClient struct {
	applyCount    atomic.Int32
	captureCount  atomic.Int32
	rollbackCount atomic.Int32

	applyResult    *api.StepResult
	captureResult  *api.PreState
	rollbackResult *api.RollbackResult
}

func (f *fakeAgentClient) Apply(_ context.Context, mechanism string, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	f.applyCount.Add(1)
	if f.applyResult != nil {
		return f.applyResult, nil
	}
	return &api.StepResult{Mechanism: mechanism, Capturable: true, Success: true, Detail: "fake agent apply"}, nil
}

func (f *fakeAgentClient) Capture(_ context.Context, mechanism string, _ api.Params) (*api.PreState, error) {
	f.captureCount.Add(1)
	if f.captureResult != nil {
		return f.captureResult, nil
	}
	return &api.PreState{Mechanism: mechanism, Capturable: true, Data: map[string]any{"via": "agent"}, CapturedAt: time.Now().UTC()}, nil
}

func (f *fakeAgentClient) Rollback(_ context.Context, pre api.PreState) (*api.RollbackResult, error) {
	f.rollbackCount.Add(1)
	if f.rollbackResult != nil {
		return f.rollbackResult, nil
	}
	return &api.RollbackResult{Mechanism: pre.Mechanism, Success: true, Source: "agent", ExecutedAt: time.Now().UTC()}, nil
}

// ArmDeadman / CancelDeadman: D-005 added these to the
// engine.AgentClient interface. The L-014 test scope
// doesn't exercise deadman dispatch — implement as no-ops
// returning sentinel values so the interface check passes.
func (f *fakeAgentClient) ArmDeadman(_ context.Context, _ string, _ int64, _ []string) (int64, error) {
	return time.Now().Add(120 * time.Second).Unix(), nil
}

func (f *fakeAgentClient) CancelDeadman(_ context.Context, _ string) (bool, error) {
	return true, nil
}

// TestEngine_WithAgentClient_RoutesApplyThroughClient locks
// the core L-014 contract: when WithAgentClient is set, an
// Apply call goes through the AgentClient instead of the
// registered local handler.
//
// @spec agent-handler-port-filepermissions
// @ac AC-06
func TestEngine_WithAgentClient_RoutesApplyThroughClient(t *testing.T) {
	fc := &fakeAgentClient{}
	// The local handler exists in the registry; we set up
	// a fake handler that should NEVER be invoked in agent
	// mode. Use FakeHandler from existing engine tests.
	h := &engine.FakeHandler{HandlerName: "fp_agent_test", IsCapturable: true}
	e := newTestEngineWithAgent(t, fc, h)

	txn := &api.Transaction{
		ID:        uuid.New(),
		RuleID:    "test-rule",
		HostID:    "test-host",
		Steps:     []api.Step{{Index: 0, Mechanism: "fp_agent_test"}},
		StartedAt: time.Now().UTC(),
	}
	_, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Agent path took the Apply call.
	if fc.applyCount.Load() == 0 {
		t.Error("expected Apply via agent client; count=0")
	}
	// Local handler's Apply MUST NOT have been called —
	// the FakeHandler tracks invocations.
	if h.ApplyCalls != 0 {
		t.Errorf("local handler Apply was called %d times in agent mode; should be 0", h.ApplyCalls)
	}
}

// TestEngine_WithoutAgentClient_RoutesApplyLocally locks
// the negative case: without WithAgentClient, the local
// handler runs (existing engine behavior unchanged).
func TestEngine_WithoutAgentClient_RoutesApplyLocally(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fp_local_test", IsCapturable: true}
	e := newTestEngine(t, h)

	txn := &api.Transaction{
		ID:        uuid.New(),
		RuleID:    "test-rule",
		HostID:    "test-host",
		Steps:     []api.Step{{Index: 0, Mechanism: "fp_local_test"}},
		StartedAt: time.Now().UTC(),
	}
	_, err := e.Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if h.ApplyCalls == 0 {
		t.Error("local handler Apply should have been called in non-agent mode")
	}
}

// newTestEngineWithAgent constructs an Engine with an
// isolated registry + agent-client wired in.
func newTestEngineWithAgent(t *testing.T, fc *fakeAgentClient, handlers ...api.Handler) *engine.Engine {
	t.Helper()
	r := handler.NewRegistry()
	for _, h := range handlers {
		r.Register(h)
	}
	return engine.New(engine.WithRegistry(r), engine.WithAgentClient(fc))
}
