// Package servicemasked implements the service_masked handler:
// mask a systemd service (systemctl mask --now), preventing it from
// being started by any means including dependency chains.
// Spec: specs/handlers/service_masked.spec.yaml.
package servicemasked

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
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

// Apply runs `systemctl mask --now <name>`. The --now flag stops the
// unit if it is currently running. Masking prevents any future start
// including via dependency chains, which is stronger than disabling.
// Idempotent per spec C-04.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("systemctl mask --now %s", shellEscape(p.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("service_masked: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("service_masked: %s failed (exit %d): %s", p.Name, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("service_masked: %s masked and stopped", p.Name),
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
		return nil, fmt.Errorf("service_masked: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("service_masked: capture failed for %s: %w (stderr: %s)",
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

// Rollback unmasks the unit and restores prior enabled and active
// states per spec C-03:
//
//  1. Always unmask (the only safe reverse of mask is unmask).
//  2. If prior_enabled was "enabled" or "enabled-runtime", re-enable.
//  3. If prior_active was "active", start.
//
// Steps 2 and 3 are combined into `systemctl enable --now` when both
// apply, otherwise issued separately.
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
