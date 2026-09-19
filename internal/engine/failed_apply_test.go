package engine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// Group A fixtures: an invoked Apply that reports failure. Kept separate from
// the Group B fixtures, where Apply fully succeeds and validation then fails,
// because the two produce different contracts and share no expectations.

// applyFailTxn builds a transaction over the named mechanisms.
func applyFailTxn(transactional bool, mechanisms ...string) *api.Transaction {
	steps := make([]api.Step, len(mechanisms))
	for i, m := range mechanisms {
		steps[i] = api.Step{Index: i, Mechanism: m}
	}
	return &api.Transaction{
		ID:            uuid.New(),
		RuleID:        "failed-apply-rule",
		HostID:        "test-host",
		Severity:      "medium",
		Steps:         steps,
		StartedAt:     time.Now().UTC(),
		Deadline:      time.Now().Add(time.Minute),
		Transactional: transactional,
	}
}

// runTxn drives one transaction through Run.
func runTxn(t *testing.T, txn *api.Transaction, opts []engine.Option, handlers ...api.Handler) *api.TransactionResult {
	t.Helper()
	r := handler.NewRegistry()
	for _, h := range handlers {
		r.Register(h)
	}
	res, err := engine.New(append([]engine.Option{engine.WithRegistry(r)}, opts...)...).
		Run(context.Background(), engine.NewFakeTransport(), txn, false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	return res
}

// capOK is a capturable handler that applies cleanly.
func capOK(name string) *engine.FakeHandler {
	return &engine.FakeHandler{
		HandlerName:  name,
		IsCapturable: true,
		CapturePreState: &api.PreState{
			Mechanism:  name,
			Capturable: true,
			Data:       map[string]any{"prior": "original"},
		},
	}
}

// noncapOK is a non-capturable handler that applies cleanly.
func noncapOK(name string) *engine.FakeHandler {
	return &engine.FakeHandler{HandlerName: name, IsCapturable: false}
}

// TestFailedApply_ReturnedError is the first failure shape: the handler
// returns an error. The engine does not reverse a failed step, so its effects
// are unresolved and the host is unconfirmed.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_ReturnedError(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	h := capOK("err_shape")
	h.ApplyErr = errors.New("induced apply failure")
	res := runTxn(t, applyFailTxn(true, "err_shape"), nil, h)

	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed", res.Status)
	}
	if res.HostUnchanged {
		t.Error("HostUnchanged is true after an invoked Apply reported failure")
	}
}

// TestFailedApply_SuccessFalse is the second failure shape: the handler
// returns a result with Success false. Asserted independently, not by
// comparison with the first shape, because before the fix both shapes produced
// the same incorrect outcome and an equivalence check would have passed.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_SuccessFalse(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	h := capOK("false_shape")
	h.ApplyResult = &api.StepResult{Success: false, Detail: "handler reported failure"}
	res := runTxn(t, applyFailTxn(true, "false_shape"), nil, h)

	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed", res.Status)
	}
	if res.HostUnchanged {
		t.Error("HostUnchanged is true after an invoked Apply reported failure")
	}
}

// TestFailedApply_ShapesAgree is preservation coverage: the two failure shapes
// must not diverge. It passes before and after the fix, so it never stands in
// for the two tests above.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_ShapesAgree(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	hErr := capOK("agree_err")
	hErr.ApplyErr = errors.New("induced apply failure")
	hFalse := capOK("agree_false")
	hFalse.ApplyResult = &api.StepResult{Success: false}

	a := runTxn(t, applyFailTxn(true, "agree_err"), nil, hErr)
	b := runTxn(t, applyFailTxn(true, "agree_false"), nil, hFalse)

	if a.Status != b.Status {
		t.Errorf("failure shapes disagree on status: %s vs %s", a.Status, b.Status)
	}
	if a.HostUnchanged != b.HostUnchanged {
		t.Errorf("failure shapes disagree on HostUnchanged: %v vs %v", a.HostUnchanged, b.HostUnchanged)
	}
	// Rollback eligibility is unchanged by either shape: a failed step is
	// never reversed, so neither run produces a rollback result.
	if len(a.RollbackResults) != 0 || len(b.RollbackResults) != 0 {
		t.Errorf("a failed step was reversed: %d and %d rollback results",
			len(a.RollbackResults), len(b.RollbackResults))
	}
}

// TestFailedApply_EarlierStepStillReversed proves the verdict is about the
// transaction, not about the rollback rows: an earlier capturable step is
// still reversed and can report success while the transaction reports an
// unconfirmed host.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_EarlierStepStillReversed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	ok := capOK("earlier_ok")
	bad := capOK("later_fails")
	bad.ApplyErr = errors.New("induced apply failure")
	res := runTxn(t, applyFailTxn(true, "earlier_ok", "later_fails"), nil, ok, bad)

	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed", res.Status)
	}
	if res.HostUnchanged {
		t.Error("HostUnchanged is true after an invoked Apply reported failure")
	}
	if len(res.RollbackResults) != 1 {
		t.Fatalf("got %d rollback results, want 1 (step 0 only)", len(res.RollbackResults))
	}
	if res.RollbackResults[0].StepIndex != 0 {
		t.Errorf("reversed step %d, want step 0", res.RollbackResults[0].StepIndex)
	}
	if !res.RollbackResults[0].Success {
		t.Error("step 0 should have reversed cleanly")
	}
	if ok.RollbackCalls != 1 || bad.RollbackCalls != 0 {
		t.Errorf("rollback eligibility wrong: ok=%d bad=%d", ok.RollbackCalls, bad.RollbackCalls)
	}
}

// TestFailedApply_TakesPrecedenceOverStranded covers the precedence rule: an
// unresolved failed Apply outranks the stranded-step verdict, and the stranded
// evidence survives the change of status.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_TakesPrecedenceOverStranded(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	strand := noncapOK("strand_ok")
	bad := capOK("strand_fails")
	bad.ApplyErr = errors.New("induced apply failure")
	res := runTxn(t, applyFailTxn(false, "strand_ok", "strand_fails"), nil, strand, bad)

	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed (precedence over PartiallyApplied)", res.Status)
	}
	if !res.Steps[0].Stranded {
		t.Error("stranded evidence lost when the verdict became RollbackFailed")
	}
	if res.Steps[1].Stranded {
		t.Error("the FAILED step was marked Stranded")
	}
}

// TestFailedApply_FailedNonCapturableIsNotStranded is the condition OpenWatch
// depends on: their step note reads "it succeeded before a later step failed",
// so the flag must never appear on a step that failed. The failing step here is
// itself non-capturable, which is the shape a careless gate would mark.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_FailedNonCapturableIsNotStranded(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	ok := noncapOK("nc_ok")
	bad := noncapOK("nc_fails")
	bad.ApplyErr = errors.New("induced apply failure")
	res := runTxn(t, applyFailTxn(false, "nc_ok", "nc_fails"), nil, ok, bad)

	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed", res.Status)
	}
	if !res.Steps[0].Stranded {
		t.Error("the successful non-capturable step lost its Stranded flag")
	}
	if res.Steps[1].Stranded {
		t.Error("the FAILED non-capturable step was marked Stranded")
	}
}

// TestFailedApply_AlsoFailedRollback covers both causes at once. The status is
// already RollbackFailed before this change because the rollback failed, so
// the status assertion is preservation; what this adds is that both causes
// stay visible.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_AlsoFailedRollback(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	ok := capOK("both_ok")
	ok.RollbackResult = &api.RollbackResult{Success: false, Detail: "induced rollback failure"}
	bad := capOK("both_fails")
	bad.ApplyErr = errors.New("induced apply failure")
	res := runTxn(t, applyFailTxn(true, "both_ok", "both_fails"), nil, ok, bad)

	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed", res.Status)
	}
	if res.Steps[1].Success {
		t.Error("the failed apply step is not recorded as failed")
	}
	if len(res.RollbackResults) != 1 || res.RollbackResults[0].Success {
		t.Error("the failed rollback of step 0 is not visible")
	}
}

// TestFailedApply_ResidualHostChange is the stateful fixture. The handler
// writes a real file and then fails, so the run has an observable residual
// change to sit beside the verdict. Before the fix this reported RolledBack
// with HostUnchanged true while the file was on disk.
// @spec engine-transaction
// @ac AC-26
func TestFailedApply_ResidualHostChange(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-26")
	dir := t.TempDir()
	residue := filepath.Join(dir, "written-before-failure")
	h := &mutatingFailHandler{name: "mutating_fail", path: residue}
	res := runTxn(t, applyFailTxn(true, "mutating_fail"), nil, h)

	if _, err := os.Stat(residue); err != nil {
		t.Fatalf("fixture did not leave a residual change: %v", err)
	}
	if res.Status != api.StatusRollbackFailed {
		t.Errorf("got Status=%s, want RollbackFailed, with a residual change on disk", res.Status)
	}
	if res.HostUnchanged {
		t.Error("reported HostUnchanged=true while a file written by Apply is still present")
	}
}

// mutatingFailHandler changes state and then reports failure, which is the
// shape the reporting contract exists for: the engine cannot know what a
// failed handler did before it failed.
type mutatingFailHandler struct {
	name string
	path string
}

func (h *mutatingFailHandler) Name() string     { return h.name }
func (h *mutatingFailHandler) Capturable() bool { return true }

func (h *mutatingFailHandler) Apply(_ context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	if err := os.WriteFile(h.path, []byte("partial change\n"), 0o600); err != nil {
		return nil, err
	}
	return nil, errors.New("induced failure after the change was made")
}

func (h *mutatingFailHandler) Capture(_ context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	return &api.PreState{
		Mechanism:  h.name,
		Capturable: true,
		Data:       map[string]any{"path": h.path, "file_existed": false},
	}, nil
}

func (h *mutatingFailHandler) Rollback(_ context.Context, _ api.Transport, _ *api.PreState) (*api.RollbackResult, error) {
	return nil, errors.New("rollback must not be invoked for a failed step")
}
