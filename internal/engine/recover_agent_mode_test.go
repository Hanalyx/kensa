package engine_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// In agent mode the engine's handler lookup never reports a mechanism as
// unknown: an unregistered one is assumed present and capturable, because
// the agent might register it. Recovery's identity check must not inherit
// that assumption. These tests run recovery with an agent client so the
// difference is observable.

// recordingAgentClient counts every call and records each rollback's
// mechanism and pre-state value, in order.
type recordingAgentClient struct {
	mu        sync.Mutex
	rollbacks []string
	captures  int
	applies   int
}

func (c *recordingAgentClient) Apply(_ context.Context, m string, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applies++
	return &api.StepResult{Mechanism: m, Success: true}, nil
}

func (c *recordingAgentClient) Capture(_ context.Context, m string, _ api.Params) (*api.PreState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.captures++
	return &api.PreState{Mechanism: m, Capturable: true, Data: map[string]any{"v": m}, CapturedAt: time.Now().UTC()}, nil
}

func (c *recordingAgentClient) Rollback(_ context.Context, pre api.PreState) (*api.RollbackResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollbacks = append(c.rollbacks, fmt.Sprintf("%s=%v", pre.Mechanism, pre.Data["v"]))
	return &api.RollbackResult{Mechanism: pre.Mechanism, Success: true, Source: "agent"}, nil
}

func (c *recordingAgentClient) ArmDeadman(context.Context, string, int64, []string) (int64, error) {
	return 0, nil
}

func (c *recordingAgentClient) CancelDeadman(context.Context, string) (bool, error) {
	return false, nil
}

func (c *recordingAgentClient) calls() (rollbacks []string, captures, applies int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.rollbacks...), c.captures, c.applies
}

// agentEngine builds an agent-mode engine over the rig's store, with a
// local registry holding only the named handlers. The local handlers
// supply capturability metadata; in agent mode their Rollback never runs.
func agentEngine(rig *identityRig, client *recordingAgentClient, local ...api.Handler) *engine.Engine {
	r := handler.NewRegistry()
	for _, h := range local {
		r.Register(h)
	}
	return engine.New(engine.WithRegistry(r), engine.WithStore(rig.st), engine.WithAgentClient(client))
}

func assertAgentRefused(t *testing.T, client *recordingAgentClient, res []*api.TransactionResult, panicked any) {
	t.Helper()
	if panicked != nil {
		t.Fatalf("recovery panicked: %v", panicked)
	}
	rb, caps, apps := client.calls()
	if len(rb) != 0 || caps != 0 || apps != 0 {
		t.Errorf("a refused entry reached the agent: rollbacks=%v captures=%d applies=%d", rb, caps, apps)
	}
	if len(res) != 0 {
		t.Errorf("a refused entry produced %d results", len(res))
	}
}

// @spec recovery-replay
// @ac AC-07
func TestRecoverAgentMode_UnknownMechanismRefused(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-07")
	rig := newIdentityRig(t)
	client := &recordingAgentClient{}
	id := rig.crash("h", []api.Step{step(0, "ghost")}, []api.PreState{pre(0, "ghost", true)})
	// The local registry does not know "ghost". Agent-mode lookup would
	// accept it as capturable; the identity check must not.
	res, panicked, _ := recoverSafely(agentEngine(rig, client), "h")
	assertAgentRefused(t, client, res, panicked)
	if rig.hasTerminal(id) || !rig.isOpen(id) {
		t.Error("the refused entry was not left open without a terminal record")
	}
}

// @spec recovery-replay
// @ac AC-07
func TestRecoverAgentMode_CapturabilityMismatchRefused(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-07")
	rig := newIdentityRig(t)
	client := &recordingAgentClient{}
	id := rig.crash("h", []api.Step{step(0, "noncap_n")}, []api.PreState{pre(0, "noncap_n", true)})
	res, panicked, _ := recoverSafely(agentEngine(rig, client,
		&recordingHandler{name: "noncap_n", capturable: false, log: rig.log}), "h")
	assertAgentRefused(t, client, res, panicked)
	if rig.hasTerminal(id) || !rig.isOpen(id) {
		t.Error("the refused entry was not left open without a terminal record")
	}
	if calls := rig.log.snapshot(); len(calls) != 0 {
		t.Errorf("a local handler ran in agent mode: %v", calls)
	}
}

// @spec recovery-replay
// @ac AC-06
func TestRecoverAgentMode_ValidEntryRestoredThroughAgent(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-06")
	rig := newIdentityRig(t)
	client := &recordingAgentClient{}
	id := rig.crash("h", []api.Step{step(0, "cap_a"), step(1, "cap_b")},
		[]api.PreState{pre(0, "cap_a", true), pre(1, "cap_b", true)})
	res, panicked, err := recoverSafely(agentEngine(rig, client,
		&recordingHandler{name: "cap_a", capturable: true, log: rig.log},
		&recordingHandler{name: "cap_b", capturable: true, log: rig.log}), "h")
	if panicked != nil || err != nil {
		t.Fatalf("recover: panic=%v err=%v", panicked, err)
	}
	rb, _, _ := client.calls()
	want := []string{"cap_b=cap_b", "cap_a=cap_a"}
	if fmt.Sprint(rb) != fmt.Sprint(want) {
		t.Errorf("agent rollbacks = %v, want %v", rb, want)
	}
	if calls := rig.log.snapshot(); len(calls) != 0 {
		t.Errorf("restoration ran locally instead of through the agent: %v", calls)
	}
	if len(res) != 1 || res[0].Status != api.StatusRecovered {
		t.Fatalf("want one recovered result, got %d", len(res))
	}
	if rig.isOpen(id) {
		t.Error("a recovered entry was left open")
	}
}
