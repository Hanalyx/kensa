// Package serviceenabled implements the service_enabled handler:
// ensure a systemd service is both enabled at boot and running right
// now. Spec: specs/handlers/service_enabled.spec.yaml.
package serviceenabled

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
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

// Apply runs `systemctl enable --now <name>` which both enables the
// unit at boot and starts it immediately. Idempotent against units
// already in that state.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("systemctl enable --now %s", shellEscape(p.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_enabled: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("service_enabled: %s failed (exit %d): %s", p.Name, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_enabled: %s enabled and started", p.Name),
	}, nil
}

// Capture records `systemctl is-enabled` and `systemctl is-active`
// raw output. Both commands return non-zero on negative results
// (disabled, inactive) but their stdout is the meaningful answer; we
// preserve it verbatim so rollback can pick the right restoration.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	// `systemctl show` is more reliable than is-enabled/is-active for
	// capturing both fields in one round trip and never fails on
	// "negative" answers.
	cmd := fmt.Sprintf("systemctl show -p UnitFileState -p ActiveState --value %s", shellEscape(p.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_enabled: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("service_enabled: capture failed for %s: %w (stderr: %s)",
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

// parseShowOutput extracts enabled and active from the two-line
// `systemctl show -p UnitFileState -p ActiveState --value` output.
// The order of properties on the command line is preserved in the
// output, so line 0 is UnitFileState and line 1 is ActiveState.
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
//   - "disabled" / "indirect" / "alias" / "generated" — `systemctl
//     disable` returns to the prior state.
//   - "masked" — `systemctl mask` (rare; only if the rule somehow
//     unmasked).
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

	enableCmd := enableRollbackCommand(name, priorEnabled)
	activeCmd := activeRollbackCommand(name, priorActive)

	// Combine into one transport call when both are non-empty.
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
		// Already in the target enable state, or unit cannot be
		// disabled. No-op.
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
		// Already active or unknown — leave running.
		return ""
	}
	return fmt.Sprintf("systemctl stop %s", shellEscape(name))
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
