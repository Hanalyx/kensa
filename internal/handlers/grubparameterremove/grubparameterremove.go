// Package grubparameterremove implements the grub_parameter_remove handler:
// remove a kernel command-line parameter from /etc/default/grub and
// regenerate the GRUB configuration.
//
// This handler is non-capturable. Rules using grub_parameter_remove must
// declare transactional: false.
package grubparameterremove

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/handler"
)

const mechanism = "grub_parameter_remove"

func init() { handler.Register(New()) }

// Handler implements the grub_parameter_remove mechanism.
type Handler struct{}

// New returns a new Handler.
func New() *Handler { return &Handler{} }

// Name returns "grub_parameter_remove".
func (h *Handler) Name() string { return mechanism }

// Capturable returns false — grub_parameter_remove is non-capturable.
func (h *Handler) Capturable() bool { return false }

// Apply strips key or key=value from GRUB_CMDLINE_LINUX inside
// /etc/default/grub and runs grub2-mkconfig. Params:
//
//	key  string  kernel parameter name to remove (required)
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	if params == nil {
		return nil, errors.New("grub_parameter_remove: params is nil")
	}
	kv, ok := params["key"]
	if !ok {
		return nil, errors.New("grub_parameter_remove: missing required param 'key'")
	}
	key, ok := kv.(string)
	if !ok || key == "" {
		return nil, errors.New("grub_parameter_remove: param 'key' must be a non-empty string")
	}

	// Remove key=<value> or bare key from GRUB_CMDLINE_LINUX.
	stripPattern := fmt.Sprintf(`s/\b%s=[^ "]*//g; s/\b%s\b//g`, key, key)
	stripCmd := fmt.Sprintf("sed -i -E %s /etc/default/grub", shellQuote(stripPattern))
	mkconfig := "grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null"

	pipeline := stripCmd + " && " + mkconfig
	res, err := transport.Run(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("grub_parameter_remove: transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("grub_parameter_remove: failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("grub_parameter_remove: %s removed from /etc/default/grub (reboot required)", key),
	}, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
