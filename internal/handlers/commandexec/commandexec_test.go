package commandexec_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/commandexec"
)

// @spec handler-command-exec
// @ac AC-01
func TestApply_RunsCommandVerbatim(t *testing.T) {
	t.Run("handler-command-exec/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	const cmd = `systemctl restart sshd && echo done`
	h := commandexec.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"run": cmd}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// The command must reach the transport verbatim, unmodified.
	if len(tp.Runs) != 1 || tp.Runs[0] != cmd {
		t.Errorf("expected exactly the verbatim command; runs=%v", tp.Runs)
	}
}

// @spec handler-command-exec
// @ac AC-02
func TestApply_ReportsFailureOnNonZeroExit(t *testing.T) {
	t.Run("handler-command-exec/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	const cmd = `false`
	tp.Results[cmd] = &api.CommandResult{ExitCode: 1, Stderr: "boom"}
	h := commandexec.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"run": cmd}, nil)
	if err != nil {
		t.Fatalf("Apply returned a Go error for a non-zero exit; want StepResult: %v", err)
	}
	if res.Success {
		t.Errorf("Success=true on non-zero exit; detail=%s", res.Detail)
	}
}

// @spec handler-command-exec
// @ac AC-03
func TestApply_RejectsInvalidParams(t *testing.T) {
	t.Run("handler-command-exec/AC-03", func(t *testing.T) {})
	h := commandexec.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"nil params", nil},
		{"missing run", api.Params{"other": "x"}},
		{"empty run", api.Params{"run": ""}},
		{"non-string run", api.Params{"run": 42}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.Apply(context.Background(), engine.NewFakeTransport(), tc.params, nil); err == nil {
				t.Errorf("expected error for %q", tc.name)
			}
		})
	}
}

// @spec handler-command-exec
// @ac AC-04
// @spec handler-interface
// @ac AC-05
func TestHandler_NonCapturable(t *testing.T) {
	t.Run("handler-command-exec/AC-04", func(t *testing.T) {})
	t.Run("handler-interface/AC-05", func(t *testing.T) {})
	h := commandexec.New()
	if h.Capturable() {
		t.Error("command_exec must report Capturable() == false")
	}
	if _, ok := interface{}(h).(api.CombinedHandler); ok {
		t.Error("non-capturable handler must not satisfy CombinedHandler")
	}
}
