// Package grubparameterremove implements the grub_parameter_remove handler.
//
// It does NOT strip GRUB_CMDLINE_LINUX directly. Instead it arms the boot guard
// (internal/bootguard) with a REMOVAL: the targeted key is stripped from a
// throwaway one-shot TRIAL boot entry's args while the saved default is left
// untouched. On the operator's next reboot the trial boots once — a healthy
// boot promotes the removal onto the default (grubby --remove-args on BLS /
// strip from GRUB_CMDLINE_LINUX on legacy); a failed boot auto-falls-back to
// the saved default with the key still present. Kensa never reboots, so the
// removal is PENDING until the operator reboots.
//
// Preflight refuses, without touching the bootloader, when the key is not on
// the boot-guard allowlist or the host is outside the validated arming
// envelope (CheckArmable: UEFI / ostree / encrypted /boot / non-GRUB).
//
// The handler stays non-capturable (rules declare transactional: false): the
// guard owns boot-atomicity via the untouched saved default + a self-limiting
// confirm unit.
package grubparameterremove

import (
	"context"
	"errors"
	"fmt"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/bootguard"
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

// Capturable returns false — the boot guard owns boot-atomicity, so the engine
// does not capture/rollback this handler (rules declare transactional: false).
func (h *Handler) Capturable() bool { return false }

// Apply arms the boot guard with a REMOVAL of params.key instead of editing the
// default entry. Params:
//
//	key  string  kernel parameter name to remove (required; must be on the guard allowlist)
//
// On success the removal is staged on a one-shot trial and is PENDING until the
// operator reboots. Returns an error for a malformed rule (bad params or an
// off-allowlist key — deterministic, host untouched); returns a StepResult with
// Success=false for a runtime refusal/failure (non-armable host, arm failure).
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	key, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	// Preflight 1 — pure, no host mutation: the key must be on the guard
	// allowlist. An off-allowlist key is a rule-level error (deterministic).
	if err := bootguard.CheckParamArmable(key); err != nil {
		return nil, err
	}

	// Preflight 2 — the host must be within the validated arming envelope.
	dec, err := bootguard.CheckArmable(ctx, transport)
	if err != nil {
		return nil, fmt.Errorf("grub_parameter_remove: arm-ability probe: %w", err)
	}
	if !dec.Armable {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("grub_parameter_remove: refusing to arm on this host: %v", dec.Refusals),
		}, nil
	}

	// Install the confirm unit FIRST, then arm the one-shot. Fail-safe ordering:
	// if confirm install fails, nothing is armed; if arming fails after, the
	// confirm unit is inert (its ConditionPathExists trial marker is absent, so
	// systemd skips it). The saved default is never modified by arming.
	if err := bootguard.InstallConfirmUnit(ctx, transport, dec.Flavor); err != nil {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("grub_parameter_remove: confirm-unit install failed (host unchanged): %v", err),
		}, nil
	}
	if _, err := bootguard.ArmOneshotRemove(ctx, transport, dec.Flavor, key); err != nil {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("grub_parameter_remove: arm failed: %v", err),
		}, nil
	}

	return &api.StepResult{
		Success: true,
		Detail: fmt.Sprintf("grub_parameter_remove: armed REMOVAL of %s on a one-shot trial boot (flavor=%s); "+
			"reboot to apply — auto-reverts to the saved default if it breaks boot (PENDING until reboot)",
			key, dec.Flavor),
	}, nil
}

func decodeParams(params api.Params) (string, error) {
	if params == nil {
		return "", errors.New("grub_parameter_remove: params is nil")
	}
	kv, ok := params["key"]
	if !ok {
		return "", errors.New("grub_parameter_remove: missing required param 'key'")
	}
	key, ok := kv.(string)
	if !ok {
		return "", errors.New("grub_parameter_remove: param 'key' must be a string")
	}
	if key == "" {
		return "", errors.New("grub_parameter_remove: param 'key' must not be empty")
	}
	return key, nil
}
