// Package servicemasked implements the service_masked handler:
// mask a systemd service (systemctl mask --now), preventing it from
// being started by any means including dependency chains.
// Spec: specs/handlers/service_masked.spec.yaml.
//
// Dual path: when the transport implements systemd.Transport (agent
// mode with the privileged kensa-systemd-helper available) the handler
// drives systemd over D-Bus; otherwise — and when the helper binary is
// absent (systemd.ErrHelperNotFound) — it falls back to `systemctl`
// shell-out, so a host without the helper behaves exactly as before.
// The rollback's unmask step is why the helper gained an `unmask` op.
package servicemasked

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
const mechanism = "service_masked"

// Params is the decoded parameter struct for the service_masked
// mechanism.
type Params struct {
	// Name is the systemd unit name (e.g. "cups", "avahi-daemon.service").
	// Required.
	Name string
}

// errMissingName is returned when params lacks the required name.
var errMissingName = errors.New("service_masked: params missing required 'name'")

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

// Handler implements the service_masked mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "service_masked".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply masks the unit and stops it. Masking prevents any future start
// including via dependency chains, which is stronger than disabling.
// Idempotent per spec C-04.
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

// applyDBus masks then stops the unit via the D-Bus helper (the
// `mask --now` equivalent). Mask creates the symlink-to-/dev/null;
// Stop satisfies the --now.
func (h *Handler) applyDBus(ctx context.Context, sd systemd.Transport, name string) (*api.StepResult, error) {
	if step, err := servicedbus.Step(mechanism, name, "mask", func() (*systemd.Response, error) { return sd.Mask(ctx, name) }); err != nil || step != nil {
		return step, err
	}
	if step, err := servicedbus.Step(mechanism, name, "stop", func() (*systemd.Response, error) { return sd.Stop(ctx, name) }); err != nil || step != nil {
		return step, err
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_masked: %s masked and stopped (D-Bus)", name),
	}, nil
}

// applyShell runs `systemctl mask --now <name>`.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, name string) (*api.StepResult, error) {
	cmd := fmt.Sprintf("systemctl mask --now %s", shellEscape(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_masked: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("service_masked: %s failed (exit %d): %s", name, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_masked: %s masked and stopped", name),
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
		return nil, fmt.Errorf("service_masked: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("service_masked: capture failed for %s: %w (stderr: %s)",
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

// Rollback unmasks the unit and restores prior enabled and active
// states per spec C-03:
//
//  1. Always unmask (the only safe reverse of mask is unmask).
//  2. If prior_enabled was "enabled" or "enabled-runtime", re-enable.
//  3. If prior_active was "active", start.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("service_masked: rollback called with nil pre-state")
	}
	name, _ := pre.Data["name"].(string)
	priorEnabled, _ := pre.Data["prior_enabled"].(string)
	priorActive, _ := pre.Data["prior_active"].(string)
	if name == "" {
		return nil, errors.New("service_masked: pre-state missing 'name'")
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

// rollbackDBus unmasks then restores the enable + active layers via the
// D-Bus helper. Unmask is always step one (it needs the helper's unmask
// op); enable/start mirror the shell path's restoration.
func (h *Handler) rollbackDBus(ctx context.Context, sd systemd.Transport, name, priorEnabled, priorActive string) (*api.RollbackResult, error) {
	if step, err := servicedbus.Step(mechanism, name, "unmask", func() (*systemd.Response, error) { return sd.Unmask(ctx, name) }); err != nil || step != nil {
		return servicedbus.RollbackFrom(step, err)
	}
	if priorEnabled == "enabled" || priorEnabled == "enabled-runtime" {
		if step, err := servicedbus.Step(mechanism, name, "enable", func() (*systemd.Response, error) { return sd.Enable(ctx, name) }); err != nil || step != nil {
			return servicedbus.RollbackFrom(step, err)
		}
	}
	if priorActive == "active" {
		if step, err := servicedbus.Step(mechanism, name, "start", func() (*systemd.Response, error) { return sd.Start(ctx, name) }); err != nil || step != nil {
			return servicedbus.RollbackFrom(step, err)
		}
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("service_masked: unmasked %s and restored (enabled=%s, active=%s) (D-Bus)", name, priorEnabled, priorActive),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell restores via systemctl shell-out.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, name, priorEnabled, priorActive string) (*api.RollbackResult, error) {
	// Unmask is always step one.
	cmds := []string{fmt.Sprintf("systemctl unmask %s", shellEscape(name))}

	needsEnable := priorEnabled == "enabled" || priorEnabled == "enabled-runtime"
	needsStart := priorActive == "active"

	switch {
	case needsEnable && needsStart:
		// enable --now covers both.
		cmds = append(cmds, fmt.Sprintf("systemctl enable --now %s", shellEscape(name)))
	case needsEnable:
		cmds = append(cmds, fmt.Sprintf("systemctl enable %s", shellEscape(name)))
	case needsStart:
		cmds = append(cmds, fmt.Sprintf("systemctl start %s", shellEscape(name)))
	}

	pipeline := strings.Join(cmds, " && ")
	res, err := transport.Run(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("service_masked: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("service_masked: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("service_masked: unmasked %s and restored (enabled=%s, active=%s)", name, priorEnabled, priorActive),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
