// Package servicedisabled implements the service_disabled handler:
// disable a systemd service at boot and stop it immediately
// (systemctl disable --now). The direct reverse of service_enabled.
// Spec: specs/handlers/service_disabled.spec.yaml.
package servicedisabled

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "service_disabled"

// Params is the decoded parameter struct for the service_disabled
// mechanism.
type Params struct {
	// Name is the systemd unit name (e.g. "bluetooth", "cups.service").
	// Required.
	Name string
}

// errMissingName is returned when params lacks the required name.
var errMissingName = errors.New("service_disabled: params missing required 'name'")

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingName
	}
	v, ok := p["name"]
	if !ok {
		return nil, errMissingName
	}
	name, ok := v.(string)
	if !ok || name == "" {
		return nil, errMissingName
	}
	return &Params{Name: name}, nil
}

// Handler implements the service_disabled mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "service_disabled".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply runs `systemctl disable --now <name>` which both disables
// the unit at boot and stops it immediately. Idempotent per spec C-04.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("systemctl disable --now %s", shellEscape(p.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_disabled: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("service_disabled: %s failed (exit %d): %s", p.Name, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_disabled: %s disabled and stopped", p.Name),
	}, nil
}

// Capture records UnitFileState and ActiveState via `systemctl show`
// in a single round trip per spec C-02.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("systemctl show -p UnitFileState -p ActiveState --value %s", shellEscape(p.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_disabled: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("service_disabled: capture failed for %s: %w (stderr: %s)",
			p.Name, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	enabled, active := parseShowOutput(res.Stdout)
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"name":          p.Name,
			"prior_enabled": enabled,
			"prior_active":  active,
		},
	}, nil
}

// parseShowOutput extracts enabled and active from the two-line output
// of `systemctl show -p UnitFileState -p ActiveState --value`.
func parseShowOutput(stdout string) (enabled, active string) {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) >= 1 {
		enabled = strings.TrimSpace(lines[0])
	}
	if len(lines) >= 2 {
		active = strings.TrimSpace(lines[1])
	}
	return enabled, active
}

// Rollback restores the prior enabled and active states per spec C-03.
//
// Enable layer:
//   - prior_enabled="enabled" or "enabled-runtime" → systemctl enable --now
//   - prior_enabled="static" → skip (static units are not enable-able)
//   - prior_enabled="disabled" or "" → skip (already in target state)
//
// Active layer (when enable layer issues no command):
//   - prior_active="active" → systemctl start
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("service_disabled: rollback called with nil pre-state")
	}
	name, _ := pre.Data["name"].(string)
	priorEnabled, _ := pre.Data["prior_enabled"].(string)
	priorActive, _ := pre.Data["prior_active"].(string)
	if name == "" {
		return nil, errors.New("service_disabled: pre-state missing 'name'")
	}

	enableCmd := enableRollbackCommand(name, priorEnabled)
	activeCmd := activeRollbackCommand(name, priorActive, enableCmd)

	var pipeline string
	switch {
	case enableCmd != "" && activeCmd != "":
		pipeline = enableCmd + " && " + activeCmd
	case enableCmd != "":
		pipeline = enableCmd
	case activeCmd != "":
		pipeline = activeCmd
	default:
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("service_disabled: nothing to rollback for %s (prior was already disabled+inactive)", name),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	res, err := transport.Run(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("service_disabled: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("service_disabled: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("service_disabled: restored %s to (enabled=%s, active=%s)", name, priorEnabled, priorActive),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// enableRollbackCommand returns the systemctl command to restore the
// captured enable-layer state, or "" when no command is needed.
func enableRollbackCommand(name, priorEnabled string) string {
	switch priorEnabled {
	case "enabled", "enabled-runtime":
		// The --now flag also starts the unit, which satisfies the
		// active layer at the same time; activeRollbackCommand skips
		// the separate start in that case.
		return fmt.Sprintf("systemctl enable --now %s", shellEscape(name))
	default:
		// disabled, static, masked, indirect, alias, generated, "":
		// no enable-layer change required.
		return ""
	}
}

// activeRollbackCommand returns the systemctl start command when the
// prior active state was "active" AND the enable command has not
// already issued --now (which starts implicitly).
func activeRollbackCommand(name, priorActive, enableCmd string) string {
	if priorActive != "active" {
		return ""
	}
	// If enableCmd already included --now, the start is covered.
	if strings.Contains(enableCmd, "--now") {
		return ""
	}
	return fmt.Sprintf("systemctl start %s", shellEscape(name))
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
