// Package grubparameterset implements the grub_parameter_set handler:
// add or update a kernel command-line parameter in /etc/default/grub
// and regenerate the GRUB configuration.
//
// This handler is non-capturable. The grub configuration change requires
// a reboot to take effect in the running kernel, so automatic rollback
// is not possible. Rules using grub_parameter_set must declare
// transactional: false.
package grubparameterset

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

const mechanism = "grub_parameter_set"

func init() { handler.Register(New()) }

// Handler implements the grub_parameter_set mechanism.
type Handler struct{}

// New returns a new Handler.
func New() *Handler { return &Handler{} }

// Name returns "grub_parameter_set".
func (h *Handler) Name() string { return mechanism }

// Capturable returns false — grub_parameter_set is non-capturable.
func (h *Handler) Capturable() bool { return false }

// Apply adds or updates key=value in GRUB_CMDLINE_LINUX inside
// /etc/default/grub and runs grub2-mkconfig. Params:
//
//	key    string  kernel parameter name (required)
//	value  string  value to set (required)
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	key, value, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	// Remove any existing key= or bare-key occurrence from GRUB_CMDLINE_LINUX,
	// then append key=value. Uses sed to edit /etc/default/grub in-place.
	//
	// Step 1 — strip any existing occurrence of the key.
	stripPattern := fmt.Sprintf(`s/\b%s=[^ "]*//g; s/\b%s\b//g`, key, key)
	stripCmd := fmt.Sprintf(
		"sed -i -E %s /etc/default/grub",
		shellQuote(stripPattern),
	)
	// Step 2 — append key=value before the closing quote of GRUB_CMDLINE_LINUX.
	appendPattern := fmt.Sprintf(`s/(GRUB_CMDLINE_LINUX="[^"]*)/\1 %s=%s/`, key, value)
	appendCmd := fmt.Sprintf(
		"sed -i -E %s /etc/default/grub",
		shellQuote(appendPattern),
	)
	// Step 3 — regenerate grub config (BLS systems use grub2-mkconfig).
	mkconfig := "grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null"

	pipeline := strings.Join([]string{stripCmd, appendCmd, mkconfig}, " && ")
	res, err := transport.Run(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("grub_parameter_set: transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("grub_parameter_set: failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("grub_parameter_set: %s=%s set in /etc/default/grub (reboot required)", key, value),
	}, nil
}

func decodeParams(params api.Params) (key, value string, err error) {
	if params == nil {
		return "", "", errors.New("grub_parameter_set: params is nil")
	}
	kv, ok := params["key"]
	if !ok {
		return "", "", errors.New("grub_parameter_set: missing required param 'key'")
	}
	key, ok = kv.(string)
	if !ok || key == "" {
		return "", "", errors.New("grub_parameter_set: param 'key' must be a non-empty string")
	}
	vv, ok := params["value"]
	if !ok {
		return "", "", errors.New("grub_parameter_set: missing required param 'value'")
	}
	value, ok = vv.(string)
	if !ok {
		return "", "", errors.New("grub_parameter_set: param 'value' must be a string")
	}
	return key, value, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
