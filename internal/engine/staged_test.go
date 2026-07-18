package engine_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
)

// An apply step reporting Staged terminates the transaction StatusStaged: the
// engine skips the runtime re-check and does NOT roll back, sets neither
// CommittedAt nor RolledBackAt, reports HostUnchanged=false (the persist layer
// was written), and records a signed envelope with Decision=staged.
//
// @spec engine-transaction
// @ac AC-25
func TestEngine_AC25_StagedTerminatesWithoutRollback(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-25")
	h := &engine.FakeHandler{
		HandlerName:  "fake_staged",
		IsCapturable: true,
		ApplyResult: &api.StepResult{
			StepIndex: 0,
			Mechanism: "fake_staged",
			Success:   true,
			Staged:    true,
			Detail:    "audit config immutable; staged, reboot required",
		},
	}
	e := newTestEngine(t, h)

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_staged"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusStaged {
		t.Fatalf("got Status=%s, want staged", res.Status)
	}
	if h.RollbackCalls != 0 {
		t.Errorf("staged transaction must NOT roll back; RollbackCalls=%d", h.RollbackCalls)
	}
	if res.CommittedAt != nil || res.RolledBackAt != nil {
		t.Errorf("staged transaction sets neither CommittedAt nor RolledBackAt; got CommittedAt=%v RolledBackAt=%v",
			res.CommittedAt, res.RolledBackAt)
	}
	if res.HostUnchanged {
		t.Error("staged transaction wrote the persist layer; HostUnchanged must be false")
	}
	if res.Envelope == nil || res.Envelope.Decision != api.StatusStaged {
		t.Fatalf("envelope must record Decision=staged; got %v", res.Envelope)
	}
}
