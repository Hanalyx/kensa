// Package commandexec implements the command_exec handler: run an
// arbitrary shell command on the target host as a remediation step.
//
// This handler is non-capturable — no pre-state is recorded and no
// automatic rollback is possible. Rules using command_exec must declare
// transactional: false.
package commandexec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

const mechanism = "command_exec"

func init() { handler.Register(New()) }

// Handler implements the command_exec mechanism.
type Handler struct{}

// New returns a new Handler.
func New() *Handler { return &Handler{} }

// Name returns "command_exec".
func (h *Handler) Name() string { return mechanism }

// Capturable returns false — command_exec is non-capturable.
func (h *Handler) Capturable() bool { return false }

// Apply runs the command specified by the "run" param.
// Params:
//
//	run  string  shell command to execute (required)
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	if params == nil {
		return nil, errors.New("command_exec: params is nil")
	}
	run, ok := params["run"]
	if !ok {
		return nil, errors.New("command_exec: missing required param 'run'")
	}
	cmd, ok := run.(string)
	if !ok || cmd == "" {
		return nil, errors.New("command_exec: param 'run' must be a non-empty string")
	}

	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command_exec: transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("command_exec: %q exited %d: %s", cmd, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("command_exec: %q succeeded", cmd),
	}, nil
}
