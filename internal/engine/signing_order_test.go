package engine_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/evidence"
	"github.com/Hanalyx/kensa/internal/handler"
	"github.com/Hanalyx/kensa/internal/redact"
	"github.com/Hanalyx/kensa/internal/store"
)

// The fixture is a transactional:false rule whose only step applies
// successfully and is non-capturable, followed by a forced validation
// failure. Rollback has nothing to reverse, so the transaction ends
// PartiallyApplied with the step marked Stranded — the one outcome that
// writes to a signed field at the end of finalize.

const strandedMechanism = "noncap_stranded"

// strandedTxn is the transactional:false transaction the fixture drives.
func strandedTxn() *api.Transaction {
	return &api.Transaction{
		ID:            uuid.New(),
		RuleID:        "stranded-rule",
		HostID:        "test-host",
		Severity:      "medium",
		Steps:         []api.Step{{Index: 0, Mechanism: strandedMechanism}},
		StartedAt:     time.Now().UTC(),
		Deadline:      time.Now().Add(time.Minute),
		Transactional: false,
		FrameworkRefs: []api.FrameworkRef{{FrameworkID: "cis", ControlID: "1.1.1"}},
	}
}

// runStranded drives the fixture and returns the terminal result.
func runStranded(t *testing.T, st engine.Store, signer engine.Signer, h api.Handler) *api.TransactionResult {
	t.Helper()
	r := handler.NewRegistry()
	r.Register(h)
	opts := []engine.Option{engine.WithRegistry(r), engine.WithForceValidateFail()}
	if st != nil {
		opts = append(opts, engine.WithStore(st))
	}
	if signer != nil {
		opts = append(opts, engine.WithSigner(signer))
	}
	txn := strandedTxn()
	res, err := engine.New(opts...).Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusPartiallyApplied {
		t.Fatalf("fixture did not reach PartiallyApplied: got %s", res.Status)
	}
	return res
}

// noncapHandler is the fixture's non-capturable handler.
func noncapHandler() *engine.FakeHandler {
	return &engine.FakeHandler{HandlerName: strandedMechanism, IsCapturable: false}
}

// realSigner returns a live Ed25519 signer. No signing test uses a double:
// a fake signer cannot show that a payload edit invalidates a signature.
func realSigner(t *testing.T) *evidence.Signer {
	t.Helper()
	s, err := evidence.Generate()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	return s
}

// openStore returns an isolated on-disk SQLite store under t.TempDir().
func openStore(t *testing.T) *store.SQLite {
	t.Helper()
	s, err := store.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "results.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustVerify(t *testing.T, s *evidence.Signer, env *api.EvidenceEnvelope, what string) {
	t.Helper()
	if env == nil {
		t.Fatalf("%s: envelope is nil", what)
	}
	r, err := s.Verify(env)
	if err != nil || r == nil || !r.Valid {
		t.Errorf("%s: signature does not verify (valid=%v err=%v)", what, r != nil && r.Valid, err)
	}
}

// TestFinalize_ReturnedEnvelopeVerifies is the primary regression. The
// stranded marking used to run after Sign, through the array the envelope
// shared with the result, so the returned envelope did not verify.
func TestFinalize_ReturnedEnvelopeVerifies(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	s := realSigner(t)
	res := runStranded(t, nil, s, noncapHandler())
	mustVerify(t, s, res.Envelope, "returned envelope")
}

// TestFinalize_PersistedEnvelopeVerifies reloads the envelope through the
// real store path (SQLite.Get with WithEnvelope) and verifies it there.
func TestFinalize_PersistedEnvelopeVerifies(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	s := realSigner(t)
	st := openStore(t)
	res := runStranded(t, st, s, noncapHandler())

	rec, err := st.Get(context.Background(), res.TransactionID, api.WithEnvelope())
	if err != nil {
		t.Fatalf("store Get: %v", err)
	}
	mustVerify(t, s, rec.Envelope, "reloaded envelope")
}

// TestFinalize_StrandedSurvivesSigning is the companion assertion. It
// passes with or without the fix, so it never stands in for the
// verification tests above; it exists so the fix cannot be "achieved" by
// dropping the flag.
func TestFinalize_StrandedSurvivesSigning(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-05")
	s := realSigner(t)
	st := openStore(t)
	res := runStranded(t, st, s, noncapHandler())

	if !res.Steps[0].Stranded {
		t.Error("returned result: step 0 is not marked Stranded")
	}
	if !res.Envelope.ApplySteps[0].Stranded {
		t.Error("returned envelope: apply step 0 is not marked Stranded")
	}
	rec, err := st.Get(context.Background(), res.TransactionID, api.WithEnvelope())
	if err != nil {
		t.Fatalf("store Get: %v", err)
	}
	if !rec.Envelope.ApplySteps[0].Stranded {
		t.Error("reloaded envelope: apply step 0 is not marked Stranded")
	}
}

// TestFinalize_ResultWritesDoNotReachEnvelope proves the envelope owns its
// payload: writing through the returned result, including into a nested
// captured-state map, must not change the signed record.
func TestFinalize_ResultWritesDoNotReachEnvelope(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	s := realSigner(t)
	h := &engine.FakeHandler{
		HandlerName:  strandedMechanism,
		IsCapturable: true,
		CapturePreState: &api.PreState{
			Mechanism:  strandedMechanism,
			Capturable: true,
			Data: map[string]any{
				"prior_content": "original",
				"nested":        map[string]any{"inner": "original"},
			},
		},
		// A failed apply keeps the step non-stranded but still exercises
		// capture, so the envelope carries a pre-state bundle.
		ApplyResult: &api.StepResult{Success: true},
	}
	r := handler.NewRegistry()
	r.Register(h)
	txn := strandedTxn()
	txn.Transactional = true
	res, err := engine.New(engine.WithRegistry(r), engine.WithSigner(s), engine.WithForceValidateFail()).
		Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.PreStates) == 0 {
		t.Fatal("fixture produced no pre-states")
	}

	res.Steps[0].Detail = "mutated after return"
	res.PreStates[0].Data["prior_content"] = "mutated after return"
	res.PreStates[0].Data["nested"].(map[string]any)["inner"] = "mutated after return"

	if got := res.Envelope.ApplySteps[0].Detail; got == "mutated after return" {
		t.Error("envelope apply step shares its array with the result")
	}
	env := res.Envelope.PreStateBundle[0].Data
	if env["prior_content"] == "mutated after return" {
		t.Error("envelope pre-state shares its map with the result")
	}
	if env["nested"].(map[string]any)["inner"] == "mutated after return" {
		t.Error("envelope pre-state shares a NESTED map with the result")
	}
	mustVerify(t, s, res.Envelope, "envelope after result mutation")
}

// TestFinalize_RedactionBoundaries proves the two surfaces redaction must
// not touch: the caller's own captured state, and the pre_states table
// that rollback restores from.
func TestFinalize_RedactionBoundaries(t *testing.T) {
	s := realSigner(t)
	st := openStore(t)
	// Test fixture only: a value the redactor must scrub from evidence and
	// must NOT scrub from the restoration source. pragma: allowlist secret
	secret := "correct-horse-battery-staple" // pragma: allowlist secret
	captured := map[string]any{"path": "/etc/thing", "password": secret}
	h := &engine.FakeHandler{
		HandlerName:  strandedMechanism,
		IsCapturable: true,
		CapturePreState: &api.PreState{
			Mechanism:  strandedMechanism,
			Capturable: true,
			Data:       captured,
		},
	}
	r := handler.NewRegistry()
	r.Register(h)
	txn := strandedTxn()
	txn.Transactional = true
	res, err := engine.New(engine.WithRegistry(r), engine.WithStore(st), engine.WithSigner(s),
		engine.WithForceValidateFail()).
		Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	t.Run("store-redaction/AC-04", func(t *testing.T) {
		if got := res.Envelope.PreStateBundle[0].Data["password"]; got != redact.Placeholder {
			t.Errorf("envelope pre-state was not redacted: got %v", got)
		}
		rec, err := st.Get(context.Background(), res.TransactionID, api.WithEnvelope())
		if err != nil {
			t.Fatalf("store Get: %v", err)
		}
		if got := rec.Envelope.PreStateBundle[0].Data["password"]; got != redact.Placeholder {
			t.Errorf("persisted envelope is not redacted: got %v", got)
		}
		mustVerify(t, s, rec.Envelope, "reloaded envelope after redaction round trip")
	})

	t.Run("store-redaction/AC-06", func(t *testing.T) {
		if captured["password"] != secret { // pragma: allowlist secret
			t.Errorf("signing redacted the caller's own captured state: got %v", captured["password"])
		}
		if res.PreStates[0].Data["password"] != secret { // pragma: allowlist secret
			t.Errorf("result pre-state was redacted in place: got %v", res.PreStates[0].Data["password"])
		}
		loaded, err := st.LoadPreStates(context.Background(), res.TransactionID)
		if err != nil {
			t.Fatalf("LoadPreStates: %v", err)
		}
		if len(loaded) == 0 {
			t.Fatal("no pre-states persisted")
		}
		if loaded[0].Data["password"] != secret { // pragma: allowlist secret
			t.Errorf("restoration source was redacted: got %v", loaded[0].Data["password"])
		}
	})
}
