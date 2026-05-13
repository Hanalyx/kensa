package engine_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

// @spec engine-transaction
// @ac validate
func TestControlChannelValidator_Passed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac validate")
	tp := engine.NewFakeTransport()
	// FakeTransport returns exit 0 for any unmatched command.
	v := engine.ControlChannelValidator{}
	r := v.Validate(context.Background(), tp, &api.Transaction{})
	if !r.Passed {
		t.Errorf("expected Passed=true; got Detail=%q", r.Detail)
	}
	if r.Name != "control_channel_reachability" {
		t.Errorf("unexpected Name %q", r.Name)
	}
}

// @spec engine-transaction
// @ac validate
func TestControlChannelValidator_Failed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac validate")
	tp := engine.NewFakeTransport()
	tp.Results["true"] = &api.CommandResult{ExitCode: 1, Stderr: "connection reset"}
	v := engine.ControlChannelValidator{}
	r := v.Validate(context.Background(), tp, &api.Transaction{})
	if r.Passed {
		t.Error("expected Passed=false when transport returns exit 1")
	}
}

// @spec engine-transaction
// @ac validate
func TestServiceHealthValidator_Passed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac validate")
	tp := engine.NewFakeTransport()
	// systemctl is-active sshd → exit 0 means active.
	tp.Results["systemctl is-active 'sshd'"] = &api.CommandResult{ExitCode: 0, Stdout: "active"}
	v := engine.ServiceHealthValidator{Service: "sshd"}
	r := v.Validate(context.Background(), tp, &api.Transaction{})
	if !r.Passed {
		t.Errorf("expected Passed=true; got Detail=%q", r.Detail)
	}
}

// @spec engine-transaction
// @ac validate
func TestServiceHealthValidator_Failed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac validate")
	tp := engine.NewFakeTransport()
	tp.Results["systemctl is-active 'sshd'"] = &api.CommandResult{ExitCode: 3, Stdout: "failed"}
	v := engine.ServiceHealthValidator{Service: "sshd"}
	r := v.Validate(context.Background(), tp, &api.Transaction{})
	if r.Passed {
		t.Error("expected Passed=false for inactive service")
	}
}

// @spec engine-transaction
// @ac validate
func TestServiceHealthValidator_EmptyService(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac validate")
	v := engine.ServiceHealthValidator{}
	r := v.Validate(context.Background(), engine.NewFakeTransport(), &api.Transaction{})
	if r.Passed {
		t.Error("expected Passed=false for empty Service field")
	}
}

// @spec engine-transaction
// @ac validate
func TestConfigSyntaxValidator_Passed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac validate")
	tp := engine.NewFakeTransport()
	// sshd -t → exit 0 means valid config.
	tp.Results["sshd -t"] = &api.CommandResult{ExitCode: 0}
	v := engine.ConfigSyntaxValidator{ValidatorName: "sshd_syntax", Command: "sshd -t"}
	r := v.Validate(context.Background(), tp, &api.Transaction{})
	if !r.Passed {
		t.Errorf("expected Passed=true; got Detail=%q", r.Detail)
	}
	if r.Name != "sshd_syntax" {
		t.Errorf("unexpected Name %q", r.Name)
	}
}

// @spec engine-transaction
// @ac validate
func TestConfigSyntaxValidator_Failed(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac validate")
	tp := engine.NewFakeTransport()
	tp.Results["sshd -t"] = &api.CommandResult{ExitCode: 1, Stderr: "bad config"}
	v := engine.ConfigSyntaxValidator{Command: "sshd -t"}
	r := v.Validate(context.Background(), tp, &api.Transaction{})
	if r.Passed {
		t.Error("expected Passed=false for syntax error")
	}
}

// @spec engine-transaction
// @ac validate
func TestConfigSyntaxValidator_DefaultName(t *testing.T) {
	t.Log("// @spec engine-transaction")
	t.Log("// @ac validate")
	v := engine.ConfigSyntaxValidator{Command: "nginx -t"}
	if v.Name() != "config_syntax" {
		t.Errorf("expected default name 'config_syntax', got %q", v.Name())
	}
}

// TestWithValidators_RollsBackOnValidatorFailure verifies that the engine
// rolls back when a custom Validator returns Passed=false.
func TestWithValidators_RollsBackOnValidatorFailure(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fake_v", IsCapturable: true}
	// Rebuild the engine with the same registry plus the failing validator.
	// newTestEngine wraps a fresh registry; we need to thread validators in.
	// Workaround: use newTestEngineWithValidators.
	e := newTestEngineWithValidators(t,
		[]api.Handler{h},
		engine.ConfigSyntaxValidator{
			ValidatorName: "always_fail",
			Command:       "false", // exit 1 → syntax check fails
		},
	)
	tp := engine.NewFakeTransport()
	tp.Results["false"] = &api.CommandResult{ExitCode: 1}

	res, err := e.Run(context.Background(), tp, basicTxn("fake_v"), false)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if res.Status != api.StatusRolledBack {
		t.Errorf("got Status=%s, want RolledBack", res.Status)
	}
	if h.RollbackCalls != 1 {
		t.Errorf("expected 1 rollback call, got %d", h.RollbackCalls)
	}
}

// TestWithValidators_CommittedOnAllPass verifies that the engine commits
// when all injected validators pass.
func TestWithValidators_CommittedOnAllPass(t *testing.T) {
	h := &engine.FakeHandler{HandlerName: "fake_vpassed", IsCapturable: true}
	e := newTestEngineWithValidators(t,
		[]api.Handler{h},
		engine.ConfigSyntaxValidator{
			ValidatorName: "always_pass",
			Command:       "true",
		},
	)

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_vpassed"), false)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Errorf("got Status=%s, want Committed", res.Status)
	}
	if len(res.Envelope.ValidatorResults) == 0 {
		t.Error("expected ValidatorResults in envelope")
	}
}

// newTestEngineWithValidators constructs a test engine with the given
// handlers and validators. Used by validator tests that need both.
func newTestEngineWithValidators(t *testing.T, handlers []api.Handler, vs ...engine.Validator) *engine.Engine {
	t.Helper()
	reg := handler.NewRegistry()
	for _, h := range handlers {
		reg.Register(h)
	}
	return engine.New(engine.WithRegistry(reg), engine.WithValidators(vs...))
}
