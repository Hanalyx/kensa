package engine_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
	"github.com/Hanalyx/kensa/internal/redact"
)

// runToStatus drives one transaction with the supplied handler and options
// and returns the terminal result.
func runToStatus(t *testing.T, st engine.Store, signer engine.Signer, h api.Handler,
	transactional bool, extra ...engine.Option,
) *api.TransactionResult {
	t.Helper()
	r := handler.NewRegistry()
	r.Register(h)
	opts := append([]engine.Option{engine.WithRegistry(r)}, extra...)
	if st != nil {
		opts = append(opts, engine.WithStore(st))
	}
	if signer != nil {
		opts = append(opts, engine.WithSigner(signer))
	}
	txn := strandedTxn()
	txn.Transactional = transactional
	res, err := engine.New(opts...).Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	return res
}

// TestPersistFailure_DemotionMatrix walks the accepted error-path matrix.
// The demotion set is committed, rolled_back and staged; every other
// terminal status keeps its status, its valid signature, and a nil Error,
// because api.TransactionResult.Error is non-nil only for Errored.
func TestPersistFailure_DemotionMatrix(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-13")

	t.Run("rolled_back demotes and preserves HostUnchanged", func(t *testing.T) {
		s := realSigner(t)
		res := runToStatus(t, persistFailStore{}, s, capHandler(), true,
			engine.WithForceValidateFail())
		if res.Status != api.StatusErrored {
			t.Fatalf("got %s, want Errored", res.Status)
		}
		if !res.HostUnchanged {
			t.Error("a verified rollback demoted by a persistence failure lost HostUnchanged=true")
		}
		if res.RolledBackAt != nil {
			t.Error("demoted result kept RolledBackAt")
		}
		if res.Envelope.Decision != api.StatusErrored {
			t.Errorf("envelope decision %s, want errored", res.Envelope.Decision)
		}
		if len(res.Envelope.RollbackResults) == 0 {
			t.Error("replacement envelope dropped the rollback evidence")
		}
		mustVerify(t, s, res.Envelope, "replacement envelope after rolled_back demotion")
	})

	t.Run("staged demotes", func(t *testing.T) {
		s := realSigner(t)
		h := capHandler()
		h.ApplyResult = &api.StepResult{Success: true, Staged: true}
		res := runToStatus(t, persistFailStore{}, s, h, true)
		if res.Status != api.StatusErrored {
			t.Fatalf("got %s, want Errored", res.Status)
		}
		if res.HostUnchanged {
			t.Error("a staged apply reported HostUnchanged=true")
		}
		mustVerify(t, s, res.Envelope, "replacement envelope after staged demotion")
	})

	t.Run("partially_applied keeps its status and signature", func(t *testing.T) {
		s := realSigner(t)
		res := runToStatus(t, persistFailStore{}, s, noncapHandler(), false,
			engine.WithForceValidateFail())
		if res.Status != api.StatusPartiallyApplied {
			t.Fatalf("got %s, want PartiallyApplied", res.Status)
		}
		if res.Error != nil {
			t.Errorf("Error is non-nil for a non-Errored status: %v", res.Error)
		}
		if res.Envelope.Decision != api.StatusPartiallyApplied {
			t.Errorf("envelope decision %s, want partially_applied", res.Envelope.Decision)
		}
		mustVerify(t, s, res.Envelope, "retained envelope")
	})

	t.Run("rollback_failed keeps its status and signature", func(t *testing.T) {
		s := realSigner(t)
		h := capHandler()
		h.RollbackResult = &api.RollbackResult{Success: false, Detail: "induced rollback failure"}
		res := runToStatus(t, persistFailStore{}, s, h, true, engine.WithForceValidateFail())
		if res.Status != api.StatusRollbackFailed {
			t.Fatalf("got %s, want RollbackFailed", res.Status)
		}
		if res.Error != nil {
			t.Errorf("Error is non-nil for a non-Errored status: %v", res.Error)
		}
		mustVerify(t, s, res.Envelope, "retained envelope")
	})
}

// TestPersistFailure_TerminalEventIsFailure proves a demoted result never
// publishes the success event it did not earn.
func TestPersistFailure_TerminalEventIsFailure(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-13")
	r := handler.NewRegistry()
	r.Register(capHandler())
	bus := engine.NewInMemoryEventBus()
	subCtx, cancel := context.WithCancel(context.Background())
	ch, err := bus.Subscribe(subCtx, api.EventFilter{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	txn := strandedTxn()
	txn.Transactional = true
	res, err := engine.New(engine.WithRegistry(r), engine.WithEvents(bus),
		engine.WithStore(persistFailStore{}), engine.WithSigner(realSigner(t))).
		Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != api.StatusErrored {
		t.Fatalf("got %s, want Errored", res.Status)
	}
	cancel()

	var sawCommitted, sawCommitPhaseFailure bool
	for _, ev := range drainEvents(ch) {
		if ev.Kind == api.Committed {
			sawCommitted = true
		}
		if d, ok := ev.Data.(api.PhaseCompletedData); ok && d.Phase == api.PhaseCommit && !d.Success {
			sawCommitPhaseFailure = true
		}
	}
	if sawCommitted {
		t.Error("a demoted result published a Committed event")
	}
	if !sawCommitPhaseFailure {
		t.Error("no failed commit-phase event published for the demoted result")
	}
}

// TestResignFailure_EvidenceIsRedacted covers the fallback that returns
// evidence a signer never processed. Redaction must not depend on the
// signer having succeeded.
func TestResignFailure_EvidenceIsRedacted(t *testing.T) {
	t.Log("// @spec store-redaction")
	t.Log("// @ac AC-04")
	const secret = "fallback-credential" // pragma: allowlist secret
	captured := map[string]any{
		"path":   "/etc/thing",
		"nested": map[string]any{"user_password": secret},
	}
	h := capHandler()
	h.CapturePreState = &api.PreState{
		Mechanism:  strandedMechanism,
		Capturable: true,
		Data:       captured,
	}
	s := &resignFailSigner{inner: realSigner(t), failOn: 2}
	res := runToStatus(t, persistFailStore{}, s, h, true)

	if res.Status != api.StatusErrored {
		t.Fatalf("got %s, want Errored", res.Status)
	}
	if len(res.Envelope.Signature) != 0 {
		t.Fatal("fallback evidence is signed")
	}
	got := res.Envelope.PreStateBundle[0].Data["nested"].(map[string]any)["user_password"]
	if got != redact.Placeholder {
		t.Errorf("unsigned fallback returned a credential value: got %v", got)
	}
	if captured["nested"].(map[string]any)["user_password"] != secret { // pragma: allowlist secret
		t.Error("redaction reached the caller's captured state")
	}
}

// TestCopyFailure_PersistsUnsignedDiagnostic proves the unrepresentable
// state path reaches the durable log and reloads as an unsigned record
// naming what was lost, and that a persistence failure on top of it does
// not hide either failure.
func TestCopyFailure_PersistsUnsignedDiagnostic(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-12")
	badState := func() *api.PreState {
		return &api.PreState{
			Mechanism:  strandedMechanism,
			Capturable: true,
			Data:       map[string]any{"typed_map": map[string]string{"a": "b"}},
		}
	}

	t.Run("persisted and reloaded unsigned", func(t *testing.T) {
		st := openStore(t)
		h := capHandler()
		h.CapturePreState = badState()
		res := runToStatus(t, st, realSigner(t), h, true)
		if res.Status != api.StatusErrored {
			t.Fatalf("got %s, want Errored", res.Status)
		}
		rec, err := st.Get(context.Background(), res.TransactionID, api.WithEnvelope())
		if err != nil {
			t.Fatalf("store Get: %v", err)
		}
		if len(rec.Envelope.Signature) != 0 {
			t.Error("unrepresentable-state record persisted as signed")
		}
		if rec.Envelope.Decision != api.StatusErrored {
			t.Errorf("persisted decision %s, want errored", rec.Envelope.Decision)
		}
		if rec.Envelope.PreStateBundle[0].Data["kensa_state_unrepresentable"] != "true" {
			t.Errorf("diagnostic did not survive persistence: %v", rec.Envelope.PreStateBundle[0].Data)
		}
	})

	t.Run("copy failure then persistence failure reports both", func(t *testing.T) {
		h := capHandler()
		h.CapturePreState = badState()
		res := runToStatus(t, persistFailStore{}, realSigner(t), h, true)
		if res.Status != api.StatusErrored {
			t.Fatalf("got %s, want Errored", res.Status)
		}
		msg := ""
		if res.Error != nil {
			msg = res.Error.Error()
		}
		if !strings.Contains(msg, "unsupported type") {
			t.Errorf("copy failure not reported: %v", res.Error)
		}
		if !strings.Contains(msg, "induced persist failure") {
			t.Errorf("persistence failure hidden behind the copy failure: %v", res.Error)
		}
		if len(res.Envelope.Signature) != 0 {
			t.Error("evidence signed despite unrepresentable state")
		}
	})
}
