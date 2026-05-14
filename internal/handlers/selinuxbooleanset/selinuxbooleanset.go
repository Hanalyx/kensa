// Package selinuxbooleanset implements the selinux_boolean_set handler:
// set an SELinux boolean persistently via setsebool -P.
// Spec: specs/handlers/selinux_boolean_set.spec.yaml.
package selinuxbooleanset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// mechanism is the canonical handler name.
const mechanism = "selinux_boolean_set"

// Params is the decoded parameter struct for the selinux_boolean_set
// mechanism.
type Params struct {
	// Boolean is the SELinux boolean name
	// (e.g. "httpd_can_network_connect"). Required.
	Boolean string
	// Value is the desired state: "on" or "off". Required.
	Value string
}

var (
	errMissingBoolean = errors.New("selinux_boolean_set: params missing required 'boolean'")
	errMissingValue   = errors.New("selinux_boolean_set: params missing required 'value'")
	errInvalidValue   = errors.New("selinux_boolean_set: 'value' must be 'on' or 'off'")
)

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingBoolean
	}
	boolRaw, ok := p["boolean"]
	if !ok {
		return nil, errMissingBoolean
	}
	boolean, ok := boolRaw.(string)
	if !ok || boolean == "" {
		return nil, errMissingBoolean
	}
	valRaw, ok := p["value"]
	if !ok {
		return nil, errMissingValue
	}
	value, ok := valRaw.(string)
	if !ok {
		return nil, errMissingValue
	}
	if value != "on" && value != "off" {
		return nil, fmt.Errorf("%w: got %q", errInvalidValue, value)
	}
	return &Params{Boolean: boolean, Value: value}, nil
}

// Handler implements the selinux_boolean_set mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "selinux_boolean_set".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply sets the SELinux boolean persistently via `setsebool -P`.
// Idempotent per spec C-01: setsebool -P with the same value is a no-op.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("setsebool -P %s %s", shellEscape(p.Boolean), p.Value)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("selinux_boolean_set: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("selinux_boolean_set: setsebool failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("selinux_boolean_set: %s=%s", p.Boolean, p.Value),
	}, nil
}

// Capture records the current boolean value via `getsebool`.
// Returns ErrCaptureIncomplete when getsebool fails (SELinux disabled
// or boolean unknown) per spec C-02.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	// getsebool output: "<boolean> --> on" or "<boolean> --> off"
	cmd := fmt.Sprintf("getsebool %s", shellEscape(p.Boolean))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("selinux_boolean_set: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("selinux_boolean_set: capture failed for %s: %w (stderr: %s)",
			p.Boolean, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	value, parseErr := parseGetsebool(res.Stdout)
	if parseErr != nil {
		return nil, fmt.Errorf("selinux_boolean_set: capture parse failed for %s: %w", p.Boolean, parseErr)
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"boolean":     p.Boolean,
			"prior_value": value,
		},
	}, nil
}

// parseGetsebool parses `getsebool <name>` output: "name --> on/off".
func parseGetsebool(stdout string) (string, error) {
	line := strings.TrimSpace(stdout)
	// Expected format: "<boolean> --> on" or "<boolean> --> off"
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return "", fmt.Errorf("unexpected getsebool output: %q", line)
	}
	value := parts[len(parts)-1]
	if value != "on" && value != "off" {
		return "", fmt.Errorf("unexpected getsebool value %q (want on/off)", value)
	}
	return value, nil
}

// Rollback restores the prior boolean value with `setsebool -P`.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("selinux_boolean_set: rollback called with nil pre-state")
	}
	boolean, _ := pre.Data["boolean"].(string)
	priorValue, _ := pre.Data["prior_value"].(string)
	if boolean == "" {
		return nil, errors.New("selinux_boolean_set: pre-state missing 'boolean'")
	}
	if priorValue != "on" && priorValue != "off" {
		return nil, fmt.Errorf("selinux_boolean_set: pre-state 'prior_value' is %q, want on/off", priorValue)
	}

	cmd := fmt.Sprintf("setsebool -P %s %s", shellEscape(boolean), priorValue)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("selinux_boolean_set: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("selinux_boolean_set: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("selinux_boolean_set: restored %s=%s", boolean, priorValue),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
