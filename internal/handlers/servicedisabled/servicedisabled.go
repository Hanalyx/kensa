// Package servicedisabled implements the service_disabled handler:
// disable a systemd service at boot and stop it immediately
// (systemctl disable --now). The direct reverse of service_enabled.
// Spec: specs/handlers/service_disabled.spec.yaml.
//
// Dual path: when the transport implements systemd.Transport (agent
// mode with the privileged kensa-systemd-helper available) the handler
// drives systemd over D-Bus; otherwise — and when the helper binary is
// absent (systemd.ErrHelperNotFound) — it falls back to `systemctl`
// shell-out, so a host without the helper behaves exactly as before.
package servicedisabled

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
	"github.com/Hanalyx/kensa/internal/handlers/servicedbus"
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

// Apply disables the unit at boot and stops it now. Idempotent per spec C-04.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if sd, ok := transport.(systemd.Transport); ok {
		res, err := h.applyDBus(ctx, sd, p.Name)
		if !errors.Is(err, systemd.ErrHelperNotFound) {
			return res, err
		}
		// Helper not installed — fall through to the shell path.
	}
	return h.applyShell(ctx, transport, p.Name)
}

// applyDBus disables then stops the unit via the D-Bus helper (the
// `disable --now` equivalent).
func (h *Handler) applyDBus(ctx context.Context, sd systemd.Transport, name string) (*api.StepResult, error) {
	if step, err := servicedbus.Step(mechanism, name, "disable", func() (*systemd.Response, error) { return sd.Disable(ctx, name) }); err != nil || step != nil {
		return step, err
	}
	if step, err := servicedbus.Step(mechanism, name, "stop", func() (*systemd.Response, error) { return sd.Stop(ctx, name) }); err != nil || step != nil {
		return step, err
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_disabled: %s disabled and stopped (D-Bus)", name),
	}, nil
}

// applyShell runs `systemctl disable --now <name>`.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, name string) (*api.StepResult, error) {
	cmd := fmt.Sprintf("systemctl disable --now %s", shellEscape(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_disabled: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("service_disabled: %s failed (exit %d): %s", name, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_disabled: %s disabled and stopped", name),
	}, nil
}

// Capture records UnitFileState and ActiveState. The captured PreState
// shape is identical on both paths so Rollback is path-agnostic.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if sd, ok := transport.(systemd.Transport); ok {
		pre, err := servicedbus.Capture(ctx, sd, mechanism, p.Name)
		if !errors.Is(err, systemd.ErrHelperNotFound) {
			return pre, err
		}
		// Helper not installed — fall through to the shell path.
	}
	return h.captureShell(ctx, transport, p.Name)
}

// captureShell reads UnitFileState + ActiveState via `systemctl show`.
func (h *Handler) captureShell(ctx context.Context, transport api.Transport, name string) (*api.PreState, error) {
	cmd := fmt.Sprintf("systemctl show -p UnitFileState -p ActiveState --value %s", shellEscape(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_disabled: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("service_disabled: capture failed for %s: %w (stderr: %s)",
			name, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	enabled, active := parseShowOutput(res.Stdout)
	return servicedbus.PreState(mechanism, name, enabled, active), nil
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
//   - prior_enabled="enabled" or "enabled-runtime" → enable + start
//     (the `enable --now` equivalent; the start also satisfies the
//     active layer).
//   - prior_enabled="static" / "disabled" / "" → skip.
//
// Active layer (only when the enable layer issued no start):
//   - prior_active="active" → start.
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

	if sd, ok := transport.(systemd.Transport); ok {
		res, err := h.rollbackDBus(ctx, sd, name, priorEnabled, priorActive)
		if !errors.Is(err, systemd.ErrHelperNotFound) {
			return res, err
		}
		// Helper not installed — fall through to the shell path.
	}
	return h.rollbackShell(ctx, transport, name, priorEnabled, priorActive)
}

// rollbackDBus restores the enable + active layers via the D-Bus helper,
// mirroring the shell path's `enable --now` semantics for an
// enabled/enabled-runtime prior state.
func (h *Handler) rollbackDBus(ctx context.Context, sd systemd.Transport, name, priorEnabled, priorActive string) (*api.RollbackResult, error) {
	switch priorEnabled {
	case "enabled", "enabled-runtime":
		if step, err := servicedbus.Step(mechanism, name, "enable", func() (*systemd.Response, error) { return sd.Enable(ctx, name) }); err != nil || step != nil {
			return servicedbus.RollbackFrom(step, err)
		}
		// `enable --now` starts the unit; mirror with an explicit start.
		if step, err := servicedbus.Step(mechanism, name, "start", func() (*systemd.Response, error) { return sd.Start(ctx, name) }); err != nil || step != nil {
			return servicedbus.RollbackFrom(step, err)
		}
	default:
		// No enable-layer change. Restore the active layer on its own.
		if priorActive == "active" {
			if step, err := servicedbus.Step(mechanism, name, "start", func() (*systemd.Response, error) { return sd.Start(ctx, name) }); err != nil || step != nil {
				return servicedbus.RollbackFrom(step, err)
			}
		}
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("service_disabled: restored %s to (enabled=%s, active=%s) (D-Bus)", name, priorEnabled, priorActive),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell restores via systemctl shell-out.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, name, priorEnabled, priorActive string) (*api.RollbackResult, error) {
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
