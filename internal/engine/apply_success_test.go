package engine_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/evidence"
	"github.com/Hanalyx/kensa/internal/handler"
	"github.com/Hanalyx/kensa/internal/store"
)

// errCaptureInduced is the shared induced failure for these fixtures.
var errCaptureInduced = errors.New("induced failure")

// Group B fixtures: Apply fully succeeds and validation then fails. These
// contracts are unchanged, and they are the regression risk of the
// failed-Apply work, so every assertion here passes before and after.

// TestApplySucceeded_CleanRollbackStillRolledBack is the case the change must
// not disturb: nothing failed to apply, the reversal was reported clean, so
// the host is provably back and HostUnchanged stays true.
// @spec engine-transaction
// @ac AC-26
func TestApplySucceeded_CleanRollbackStillRolledBack(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	h := capOK("clean_rollback")
	res := runTxn(t, applyFailTxn(true, "clean_rollback"),
		[]engine.Option{engine.WithForceValidateFail()}, h)

	if res.Status != api.StatusRolledBack {
		t.Errorf("got Status=%s, want RolledBack", res.Status)
	}
	if !res.HostUnchanged {
		t.Error("a verified rollback lost HostUnchanged=true")
	}
}

// TestApplySucceeded_StrandedStillPartiallyApplied keeps the ordinary
// stranded-step verdict intact when no Apply failed.
// @spec engine-transaction
// @ac AC-26
func TestApplySucceeded_StrandedStillPartiallyApplied(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	h := noncapOK("stranded_only")
	res := runTxn(t, applyFailTxn(false, "stranded_only"),
		[]engine.Option{engine.WithForceValidateFail()}, h)

	if res.Status != api.StatusPartiallyApplied {
		t.Errorf("got Status=%s, want PartiallyApplied", res.Status)
	}
	if !res.Steps[0].Stranded {
		t.Error("the successful non-capturable step is not marked Stranded")
	}
	if res.HostUnchanged {
		t.Error("a partially applied outcome reported HostUnchanged=true")
	}
}

// TestApplySucceeded_MixedCapturability covers a stranded step beside a
// cleanly reversed one.
// @spec engine-transaction
// @ac AC-26
func TestApplySucceeded_MixedCapturability(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	nc := noncapOK("mixed_nc")
	c := capOK("mixed_cap")
	res := runTxn(t, applyFailTxn(false, "mixed_nc", "mixed_cap"),
		[]engine.Option{engine.WithForceValidateFail()}, nc, c)

	if res.Status != api.StatusPartiallyApplied {
		t.Errorf("got Status=%s, want PartiallyApplied", res.Status)
	}
	if !res.Steps[0].Stranded {
		t.Error("the non-capturable step is not marked Stranded")
	}
	if res.Steps[1].Stranded {
		t.Error("a capturable step was marked Stranded")
	}
}

// TestApplySucceeded_RollbackFailureStillRollbackFailed keeps the original
// cause of RollbackFailed working.
// @spec engine-transaction
// @ac AC-26
func TestApplySucceeded_RollbackFailureStillRollbackFailed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	h := capOK("rb_fails")
	h.RollbackResult = &api.RollbackResult{Success: false, Detail: "induced rollback failure"}
	res := runTxn(t, applyFailTxn(true, "rb_fails"),
		[]engine.Option{engine.WithForceValidateFail()}, h)

	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed", res.Status)
	}
	if res.HostUnchanged {
		t.Error("an unconfirmed restoration reported HostUnchanged=true")
	}
}

// TestSuccessfulTransaction_NoStrandedFlag is the preservation test for the
// status-gated marking. A successful transactional:false transaction has no
// stranded steps: nothing failed, so nothing was left behind by a failure.
// A gate that tested only Transactional would mark every successful
// non-capturable step here.
// @spec engine-transaction
// @ac AC-26
func TestSuccessfulTransaction_NoStrandedFlag(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	signer, err := evidence.Generate()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	st, err := store.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "results.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	res := runTxn(t, applyFailTxn(false, "success_nc"),
		[]engine.Option{engine.WithStore(st), engine.WithSigner(signer)}, noncapOK("success_nc"))

	if res.Status != api.StatusCommitted {
		t.Fatalf("got Status=%s, want Committed", res.Status)
	}
	if res.Steps[0].Stranded {
		t.Error("a successful transaction marked its non-capturable step Stranded")
	}
	if res.Envelope.ApplySteps[0].Stranded {
		t.Error("the returned envelope carries a Stranded flag for a successful transaction")
	}
	rec, err := st.Get(context.Background(), res.TransactionID, api.WithEnvelope())
	if err != nil {
		t.Fatalf("store Get: %v", err)
	}
	if rec.Envelope.ApplySteps[0].Stranded {
		t.Error("the persisted envelope carries a Stranded flag for a successful transaction")
	}
}

// TestPreApplyFailure_HostUnchangedStaysTrue confirms the pre-apply boundary is
// untouched: a capture failure never invoked Apply, so the host is provably
// clean and the errored path still says so.
// @spec engine-transaction
// @ac AC-14
func TestPreApplyFailure_HostUnchangedStaysTrue(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-14")
	h := capOK("capture_fails")
	h.CaptureErr = errCaptureInduced
	res := runTxn(t, applyFailTxn(true, "capture_fails"), nil, h)

	if res.Status != api.StatusErrored {
		t.Fatalf("got Status=%s, want Errored", res.Status)
	}
	if !res.HostUnchanged {
		t.Error("a pre-apply failure lost HostUnchanged=true")
	}
	if h.ApplyCalls != 0 {
		t.Errorf("Apply ran %d times on a pre-apply failure", h.ApplyCalls)
	}
}

// TestFailedApply_EvidenceIsSignedAndStranded proves the reporting change
// rides inside the signature: the flags are settled before the envelope is
// built, and both the returned and the reloaded records verify.
// @spec evidence-envelope
// @ac AC-03
func TestFailedApply_EvidenceIsSignedAndStranded(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-03")
	signer, err := evidence.Generate()
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	st, err := store.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "results.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	strand := noncapOK("ev_strand")
	bad := capOK("ev_fails")
	bad.ApplyErr = errCaptureInduced
	res := runTxn(t, applyFailTxn(false, "ev_strand", "ev_fails"),
		[]engine.Option{engine.WithStore(st), engine.WithSigner(signer)}, strand, bad)

	if res.Status != api.StatusRollbackFailed {
		t.Fatalf("got Status=%s, want RollbackFailed", res.Status)
	}
	if r, err := signer.Verify(res.Envelope); err != nil || r == nil || !r.Valid {
		t.Errorf("returned envelope does not verify: %v", err)
	}
	if res.Envelope.Decision != api.StatusRollbackFailed {
		t.Errorf("envelope decision %s, want rollback_failed", res.Envelope.Decision)
	}
	if !res.Envelope.ApplySteps[0].Stranded {
		t.Error("the signed evidence lost the Stranded flag")
	}
	if res.Envelope.ApplySteps[1].Stranded {
		t.Error("the signed evidence marks the FAILED step Stranded")
	}
	rec, err := st.Get(context.Background(), res.TransactionID, api.WithEnvelope())
	if err != nil {
		t.Fatalf("store Get: %v", err)
	}
	if r, err := signer.Verify(rec.Envelope); err != nil || r == nil || !r.Valid {
		t.Errorf("reloaded envelope does not verify: %v", err)
	}
	if !rec.Envelope.ApplySteps[0].Stranded {
		t.Error("the reloaded evidence lost the Stranded flag")
	}
}

// TestFailedApply_PlanPathClassifiesTheSame exercises the second entry point.
// rollbackStatus is shared by Run and ExecutePlan, and a fix applied to one
// path only would leave the other reporting the old verdict.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_PlanPathClassifiesTheSame(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	strand := noncapOK("plan_strand")
	bad := capOK("plan_fails")
	bad.ApplyErr = errCaptureInduced

	r := handler.NewRegistry()
	r.Register(strand)
	r.Register(bad)
	e := engine.New(engine.WithRegistry(r))

	rule := &api.Rule{
		ID:            "plan-failed-apply",
		Title:         "plan path failed apply",
		Transactional: false,
		Implementations: []api.Implementation{
			{
				Default: true,
				Remediation: api.Remediation{
					Steps: []api.RemediationStep{
						{Mechanism: "plan_strand"},
						{Mechanism: "plan_fails"},
					},
				},
			},
		},
	}
	plan, err := e.PlanTransaction(context.Background(), engine.NewFakeTransport(), rule)
	if err != nil {
		t.Fatalf("PlanTransaction: %v", err)
	}
	res, err := e.ExecutePlan(context.Background(), engine.NewFakeTransport(), plan)
	if err != nil {
		t.Fatalf("ExecutePlan: %v", err)
	}
	if res.Status != api.StatusRollbackFailed {
		t.Errorf("plan path got Status=%s, want RollbackFailed", res.Status)
	}
	if res.HostUnchanged {
		t.Error("plan path reported HostUnchanged=true after a failed Apply")
	}
	if !res.Steps[0].Stranded {
		t.Error("plan path lost the Stranded flag")
	}
	if res.Steps[1].Stranded {
		t.Error("plan path marked the FAILED step Stranded")
	}
}

// TestApplySucceeded_StrandedWithFailedRollback combines successful
// non-capturable work with a capturable step whose reversal fails. The
// unclean reversal outranks the stranded-step verdict, and the stranded
// evidence survives the change of status. The status here was already
// RollbackFailed before the failed-apply work; what that work added is the
// retained flag, which the narrower gate used to drop.
//
// @spec engine-transaction
// @ac AC-26
func TestApplySucceeded_StrandedWithFailedRollback(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	nc := noncapOK("swfr_nc")
	c := capOK("swfr_cap")
	c.RollbackResult = &api.RollbackResult{Success: false, Detail: "induced rollback failure"}
	res := runTxn(t, applyFailTxn(false, "swfr_nc", "swfr_cap"),
		[]engine.Option{engine.WithForceValidateFail()}, nc, c)

	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed (unclean reversal outranks stranded)", res.Status)
	}
	if res.HostUnchanged {
		t.Error("an unconfirmed restoration reported HostUnchanged=true")
	}
	if !res.Steps[0].Stranded {
		t.Error("the successful non-capturable step lost its Stranded flag under RollbackFailed")
	}
	if res.Steps[1].Stranded {
		t.Error("a capturable step was marked Stranded")
	}
}
