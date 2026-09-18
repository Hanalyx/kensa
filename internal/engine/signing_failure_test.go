package engine_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// resignFailSigner signs normally until the nth call, then fails. It
// models a key or HSM outage that appears between the first signature and
// the replacement one, which is the only way to reach the unsigned
// fallback on the persistence-failure path.
type resignFailSigner struct {
	inner  engine.Signer
	failOn int

	mu    sync.Mutex
	calls int
}

func (s *resignFailSigner) Sign(env *api.EvidenceEnvelope) ([]byte, string, error) {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()
	if n >= s.failOn {
		return nil, "", errors.New("induced re-sign failure")
	}
	return s.inner.Sign(env)
}

func (s *resignFailSigner) Verify(env *api.EvidenceEnvelope) (*api.VerifyResult, error) {
	return s.inner.Verify(env)
}

// committedTxn drives a capturable step that applies and validates
// cleanly, so the transaction reaches Committed and the persistence
// failure has a status in the demotion set to act on.
func runCommitted(t *testing.T, st engine.Store, signer engine.Signer, h api.Handler) *api.TransactionResult {
	t.Helper()
	r := handler.NewRegistry()
	r.Register(h)
	opts := []engine.Option{engine.WithRegistry(r)}
	if st != nil {
		opts = append(opts, engine.WithStore(st))
	}
	if signer != nil {
		opts = append(opts, engine.WithSigner(signer))
	}
	txn := strandedTxn()
	txn.Transactional = true
	res, err := engine.New(opts...).Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	return res
}

func capHandler() *engine.FakeHandler {
	return &engine.FakeHandler{
		HandlerName:  strandedMechanism,
		IsCapturable: true,
		CapturePreState: &api.PreState{
			Mechanism:  strandedMechanism,
			Capturable: true,
			Data:       map[string]any{"prior_content": "original"},
		},
	}
}

// TestFinalize_PersistFailureSignsReplacementEvidence covers the second
// post-signing mutation: the decision used to be overwritten in place on a
// persistence failure, leaving a signature over bytes that no longer
// existed. The replacement must carry the errored decision, retain the
// evidence, and verify.
func TestFinalize_PersistFailureSignsReplacementEvidence(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-13")
	s := realSigner(t)
	res := runCommitted(t, persistFailStore{}, s, capHandler())

	if res.Status != api.StatusErrored {
		t.Fatalf("got Status=%s, want Errored", res.Status)
	}
	if res.Envelope.Decision != api.StatusErrored {
		t.Errorf("got envelope Decision=%s, want errored", res.Envelope.Decision)
	}
	if len(res.Envelope.ApplySteps) == 0 || len(res.Envelope.PreStateBundle) == 0 {
		t.Error("replacement envelope dropped the transaction evidence")
	}
	if res.CommittedAt != nil {
		t.Error("demoted result kept CommittedAt")
	}
	if res.Error == nil || !strings.Contains(res.Error.Error(), "induced persist failure") {
		t.Errorf("persistence failure not reported: %v", res.Error)
	}
	mustVerify(t, s, res.Envelope, "replacement envelope")
}

// TestFinalize_ResignFailureIsExplicitlyUnsigned proves the fallback never
// keeps a stale signature, and that the second failure is reported
// alongside the first rather than being dropped by first-failure-wins.
func TestFinalize_ResignFailureIsExplicitlyUnsigned(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-12")
	s := &resignFailSigner{inner: realSigner(t), failOn: 2}
	res := runCommitted(t, persistFailStore{}, s, capHandler())

	if res.Status != api.StatusErrored {
		t.Fatalf("got Status=%s, want Errored", res.Status)
	}
	if res.Envelope.Signature == nil {
		t.Error("signature is nil; the NOT NULL envelope_sig column needs the empty-slice sentinel")
	}
	if len(res.Envelope.Signature) != 0 {
		t.Error("unsigned fallback carries a signature over altered contents")
	}
	if res.Envelope.SigningKeyID != "" {
		t.Errorf("unsigned fallback kept a key id: %q", res.Envelope.SigningKeyID)
	}
	if len(res.Envelope.ApplySteps) == 0 {
		t.Error("unsigned fallback dropped the transaction evidence")
	}
	msg := ""
	if res.Error != nil {
		msg = res.Error.Error()
	}
	if !strings.Contains(msg, "induced persist failure") {
		t.Errorf("persistence failure hidden by the re-sign failure: %v", res.Error)
	}
	if !strings.Contains(msg, "induced re-sign failure") {
		t.Errorf("re-sign failure not reported: %v", res.Error)
	}
}

// TestFinalize_UnsupportedCapturedStateFailsClosed covers the copy-failure
// path. It must not route through the pre-apply errored helper, which
// asserts the host is untouched: apply already ran here.
func TestFinalize_UnsupportedCapturedStateFailsClosed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-14")
	s := realSigner(t)
	st := &capturingStore{}
	original := map[string]any{
		"path": "/etc/thing",
		// Marshals cleanly, so it reaches the envelope copy rather than
		// failing earlier in pre-state persistence.
		"typed_map": map[string]string{"a": "b"},
	}
	h := capHandler()
	h.CapturePreState = &api.PreState{
		Mechanism:  strandedMechanism,
		Capturable: true,
		Data:       original,
	}
	res := runCommitted(t, st, s, h)

	if res.Status != api.StatusErrored {
		t.Fatalf("got Status=%s, want Errored", res.Status)
	}
	if res.HostUnchanged {
		t.Error("HostUnchanged is true after a successful apply; the pre-apply errored path was used")
	}
	if res.Envelope.Signature == nil || len(res.Envelope.Signature) != 0 {
		t.Error("unrepresentable evidence must carry the unsigned sentinel")
	}
	data := res.Envelope.PreStateBundle[0].Data
	if data["kensa_state_unrepresentable"] != "true" {
		t.Errorf("no diagnostic recorded for the unrepresentable entry: %v", data)
	}
	if !strings.Contains(data["reason"].(string), "map[string]string") {
		t.Errorf("diagnostic does not name the offending type: %v", data["reason"])
	}
	original["typed_map"].(map[string]string)["a"] = "mutated"
	if strings.Contains(data["reason"].(string), "mutated") {
		t.Error("diagnostic aliases the original captured state")
	}
	if _, aliased := data["typed_map"]; aliased {
		t.Error("envelope retained the unsupported value instead of failing closed")
	}
	if st.last() == nil {
		t.Error("no persistence attempt was made for the errored outcome")
	}
	if res.Error == nil || !strings.Contains(res.Error.Error(), "unsupported type") {
		t.Errorf("copy failure not reported: %v", res.Error)
	}
}
