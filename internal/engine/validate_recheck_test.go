package engine_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// checkTxn builds a single-step transactional txn carrying a command-method
// post-apply check that runs recheckCmd.
func checkTxn(mechanism, recheckCmd string) *api.Transaction {
	return &api.Transaction{
		ID:            uuid.New(),
		RuleID:        "test-rule",
		HostID:        "test-host",
		Steps:         []api.Step{{Index: 0, Mechanism: mechanism}},
		StartedAt:     time.Now().UTC(),
		Deadline:      time.Now().Add(time.Minute),
		Transactional: true,
		Check:         api.Check{Method: "command", Params: api.Params{"cmd": recheckCmd}},
	}
}

// recheckValidator returns the post-apply-recheck ValidatorResult from an
// envelope, or nil if none was produced.
func recheckValidator(env *api.EvidenceEnvelope) *api.ValidatorResult {
	if env == nil {
		return nil
	}
	for i := range env.ValidatorResults {
		if env.ValidatorResults[i].Name == "post-apply-recheck" {
			return &env.ValidatorResults[i]
		}
	}
	return nil
}

// erroringTransport makes Run fail for one specific command, modeling a
// transport/tool failure during the post-apply re-read.
type erroringTransport struct {
	*engine.FakeTransport
	errOn string
}

func (t *erroringTransport) Run(ctx context.Context, cmd string) (*api.CommandResult, error) {
	if cmd == t.errOn {
		return nil, errors.New("induced transport failure on re-check")
	}
	return t.FakeTransport.Run(ctx, cmd)
}

// @spec engine-transaction
// @ac AC-18
func TestEngine_AC18_RecheckPassCommits(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-18")
	h := &engine.FakeHandler{HandlerName: "rc_ok", IsCapturable: true}
	e := durabilityEngine(t, nil, nil, h)
	tr := engine.NewFakeTransport()
	tr.Results["rc-pass"] = &api.CommandResult{ExitCode: 0}

	res, err := e.Run(context.Background(), tr, checkTxn("rc_ok", "rc-pass"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Fatalf("re-check passed; want Committed, got %s", res.Status)
	}
	vr := recheckValidator(res.Envelope)
	if vr == nil || !vr.Passed {
		t.Errorf("expected a passing post-apply-recheck validator; got %+v", vr)
	}
}

// @spec engine-transaction
// @ac AC-19
func TestEngine_AC19_RecheckCleanFailRollsBack(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-19")
	h := &engine.FakeHandler{
		HandlerName:    "rc_fail",
		IsCapturable:   true,
		RollbackResult: &api.RollbackResult{Success: true},
	}
	e := durabilityEngine(t, nil, nil, h)
	tr := engine.NewFakeTransport()
	tr.Results["rc-fail"] = &api.CommandResult{ExitCode: 1}

	res, err := e.Run(context.Background(), tr, checkTxn("rc_fail", "rc-fail"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusRolledBack {
		t.Fatalf("a clean re-check failure must roll back; want RolledBack, got %s", res.Status)
	}
	// Pin the cause: apply succeeded (no ApplyErr) and there are no other
	// validators, so the single rollback must have been driven by the
	// re-check failure specifically.
	if h.RollbackCalls != 1 {
		t.Errorf("expected exactly one rollback driven by the re-check; got %d", h.RollbackCalls)
	}
	if vr := recheckValidator(res.Envelope); vr == nil || vr.Passed {
		t.Errorf("expected a failing post-apply-recheck validator; got %+v", vr)
	}
}

// @spec engine-transaction
// @ac AC-20
func TestEngine_AC20_RecheckErrorCommitsUnverified(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-20")
	h := &engine.FakeHandler{
		HandlerName:    "rc_err",
		IsCapturable:   true,
		RollbackResult: &api.RollbackResult{Success: true},
	}
	e := durabilityEngine(t, nil, nil, h)
	tr := &erroringTransport{FakeTransport: engine.NewFakeTransport(), errOn: "rc-err"}

	res, err := e.Run(context.Background(), tr, checkTxn("rc_err", "rc-err"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	// ERROR != FAIL: a re-check that could not read must NOT roll back.
	if res.Status != api.StatusCommitted {
		t.Fatalf("a re-check ERROR must not roll back; want Committed, got %s", res.Status)
	}
	if h.RollbackCalls != 0 {
		t.Errorf("rollback ran on a re-check ERROR (%d calls); ERROR != FAIL violated", h.RollbackCalls)
	}
	vr := recheckValidator(res.Envelope)
	if vr == nil || !vr.Passed {
		t.Fatalf("expected a non-blocking post-apply-recheck validator; got %+v", vr)
	}
	if !strings.Contains(vr.Detail, "unverified") {
		t.Errorf("re-check ERROR should be recorded as unverified; detail=%q", vr.Detail)
	}
}

// @spec engine-transaction
// @ac AC-21
func TestEngine_AC21_KillSwitchSuppressesRecheck(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac AC-21")
	r := handler.NewRegistry()
	r.Register(&engine.FakeHandler{
		HandlerName:    "ks",
		IsCapturable:   true,
		RollbackResult: &api.RollbackResult{Success: true},
	})
	e := engine.New(engine.WithRegistry(r), engine.WithPostApplyRecheck(false))
	tr := engine.NewFakeTransport()
	tr.Results["rc-fail"] = &api.CommandResult{ExitCode: 1} // would fail if run

	res, err := e.Run(context.Background(), tr, checkTxn("ks", "rc-fail"), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Fatalf("with the re-check disabled, the failing check must be ignored; want Committed, got %s", res.Status)
	}
	if vr := recheckValidator(res.Envelope); vr != nil {
		t.Errorf("kill switch must suppress the post-apply-recheck validator entirely; got %+v", vr)
	}
}
