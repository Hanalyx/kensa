// Package serviceenabled implements the service_enabled handler:
// ensure a systemd service is both enabled at boot and running right
// now. Spec: specs/handlers/service_enabled.spec.yaml.
//
// Dual path: when the transport implements systemd.Transport (agent
// mode, with the privileged kensa-systemd-helper available) the handler
// drives systemd over D-Bus; otherwise it falls back to `systemctl`
// shell-out. The fallback also fires when the helper binary is not
// installed (systemd.ErrHelperNotFound), so a host without the helper
// behaves exactly as it did before — no regression.
package serviceenabled

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
const mechanism = "service_enabled"

// Params is the decoded parameter struct.
type Params struct {
	// Name is the systemd unit name (e.g. "auditd", "sshd.service").
	// Required.
	Name string
}

// errMissingName is returned when params lacks the required name.
var errMissingName = errors.New("service_enabled: params missing required 'name'")

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

// Handler implements the service_enabled mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "service_enabled".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply ensures the unit is enabled at boot and running now. Idempotent
// against units already in that state.
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

// applyDBus enables then starts the unit via the D-Bus helper. A
// structured HelperError (the op ran but systemd refused) becomes a
// failed StepResult, matching the shell path's non-zero-exit handling;
// an exec/transport-level failure is returned as an error. ErrHelperNotFound
// is propagated so Apply can fall back to shell.
func (h *Handler) applyDBus(ctx context.Context, sd systemd.Transport, name string) (*api.StepResult, error) {
	if step, err := servicedbus.Step(mechanism, name, "enable", func() (*systemd.Response, error) { return sd.Enable(ctx, name) }); err != nil || step != nil {
		return step, err
	}
	if step, err := servicedbus.Step(mechanism, name, "start", func() (*systemd.Response, error) { return sd.Start(ctx, name) }); err != nil || step != nil {
		return step, err
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_enabled: %s enabled and started (D-Bus)", name),
	}, nil
}

// applyShell runs `systemctl enable --now <name>`.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, name string) (*api.StepResult, error) {
	cmd := fmt.Sprintf("systemctl enable --now %s", shellEscape(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_enabled: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("service_enabled: %s failed (exit %d): %s", name, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_enabled: %s enabled and started", name),
	}, nil
}

// Capture records the unit's enable and active state. The captured
// PreState shape (name / prior_enabled / prior_active) is identical on
// both the D-Bus and shell paths, so Rollback works regardless of which
// path produced it.
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
		return nil, fmt.Errorf("service_enabled: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("service_enabled: capture failed for %s: %w (stderr: %s)",
			name, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	enabled, active := parseShowOutput(res.Stdout)
	return servicedbus.PreState(mechanism, name, enabled, active), nil
}

// parseShowOutput extracts enabled and active from the two-line
// `systemctl show -p UnitFileState -p ActiveState --value` output.
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

// Rollback restores the prior enabled and active states.
//
// Per handler-service-enabled spec C-03, the enable-layer restoration
// branches on the captured prior_enabled value:
//
//   - "enabled" / "enabled-runtime" / "static" / "" — no enable change
//     needed (already enabled, or the unit cannot be enabled/disabled).
//   - "disabled" / "indirect" / "alias" / "generated" — disable returns
//     to the prior state.
//   - "masked" — mask (rare; only if the rule somehow unmasked).
//
// The active-layer restoration is simpler: if prior_active was
// "active", ensure it stays running; otherwise stop.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("service_enabled: rollback called with nil pre-state")
	}
	name, _ := pre.Data["name"].(string)
	priorEnabled, _ := pre.Data["prior_enabled"].(string)
	priorActive, _ := pre.Data["prior_active"].(string)
	if name == "" {
		return nil, fmt.Errorf("service_enabled: pre-state missing 'name'")
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

// rollbackDBus restores the enable + active layers via the D-Bus helper.
func (h *Handler) rollbackDBus(ctx context.Context, sd systemd.Transport, name, priorEnabled, priorActive string) (*api.RollbackResult, error) {
	// Enable layer.
	switch priorEnabled {
	case "enabled", "enabled-runtime", "static", "":
		// No-op.
	case "masked":
		if step, err := servicedbus.Step(mechanism, name, "mask", func() (*systemd.Response, error) { return sd.Mask(ctx, name) }); err != nil || step != nil {
			return servicedbus.RollbackFrom(step, err)
		}
	default: // disabled, indirect, alias, generated, transient
		if step, err := servicedbus.Step(mechanism, name, "disable", func() (*systemd.Response, error) { return sd.Disable(ctx, name) }); err != nil || step != nil {
			return servicedbus.RollbackFrom(step, err)
		}
	}
	// Active layer: stop unless prior was active (or unknown).
	if priorActive != "active" && priorActive != "" {
		if step, err := servicedbus.Step(mechanism, name, "stop", func() (*systemd.Response, error) { return sd.Stop(ctx, name) }); err != nil || step != nil {
			return servicedbus.RollbackFrom(step, err)
		}
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("service_enabled: restored %s to (enabled=%s, active=%s) (D-Bus)", name, priorEnabled, priorActive),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell restores via systemctl shell-out.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, name, priorEnabled, priorActive string) (*api.RollbackResult, error) {
	enableCmd := enableRollbackCommand(name, priorEnabled)
	activeCmd := activeRollbackCommand(name, priorActive)

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
			Detail:     fmt.Sprintf("service_enabled: nothing to rollback for %s (prior was already enabled+active)", name),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	res, err := transport.Run(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("service_enabled: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("service_enabled: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("service_enabled: restored %s to (enabled=%s, active=%s)", name, priorEnabled, priorActive),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// enableRollbackCommand returns the systemctl command (or "") needed
// to restore the captured enable-layer state.
func enableRollbackCommand(name, priorEnabled string) string {
	switch priorEnabled {
	case "enabled", "enabled-runtime", "static", "":
		return ""
	case "masked":
		return fmt.Sprintf("systemctl mask %s", shellEscape(name))
	default: // disabled, indirect, alias, generated, transient — disable to prior state
		return fmt.Sprintf("systemctl disable %s", shellEscape(name))
	}
}

// activeRollbackCommand returns the systemctl command (or "") needed
// to restore the captured active-layer state.
func activeRollbackCommand(name, priorActive string) string {
	if priorActive == "active" || priorActive == "" {
		return ""
	}
	return fmt.Sprintf("systemctl stop %s", shellEscape(name))
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
