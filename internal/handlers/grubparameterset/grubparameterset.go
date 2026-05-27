// Package grubparameterset implements the grub_parameter_set handler.
//
// It does NOT edit GRUB_CMDLINE_LINUX directly. Instead it arms the boot guard
// (internal/bootguard): the new parameter is staged on a one-shot TRIAL boot
// entry while the saved default stays known-good. On the operator's
// next reboot the trial boots once — a healthy boot promotes the parameter onto
// the default (via grubby on BLS / GRUB_CMDLINE_LINUX on legacy); a failed boot
// auto-reverts to the saved default. Kensa never reboots, so the parameter is
// PENDING until the operator reboots.
//
// Preflight refuses, without touching the bootloader, when (a) the key is not on
// the boot-guard allowlist or (b) the host is outside the validated arming
// envelope (CheckArmable: UEFI / ostree / encrypted /boot / non-GRUB).
//
// The handler stays non-capturable (rules declare transactional: false): the
// guard owns boot-atomicity via the untouched saved default + a self-limiting
// confirm unit, so the engine does not drive capture/rollback for it.
package grubparameterset

import (
	"context"
	"errors"
	"fmt"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/handler"
)

const mechanism = "grub_parameter_set"

func init() { handler.Register(New()) }

// Handler implements the grub_parameter_set mechanism.
type Handler struct{}

// New returns a new Handler.
func New() *Handler { return &Handler{} }

// Name returns "grub_parameter_set".
func (h *Handler) Name() string { return mechanism }

// Capturable returns false — the boot guard owns boot-atomicity, so the engine
// does not capture/rollback this handler (rules declare transactional: false).
func (h *Handler) Capturable() bool { return false }

// Apply arms the boot guard with key=value instead of editing the default entry.
// Params:
//
//	key    string  kernel parameter name (required; must be on the guard allowlist)
//	value  string  value to set (required)
//
// On success the parameter is staged on a one-shot trial and is PENDING until
// the operator reboots. Returns an error for a malformed rule (bad params or an
// off-allowlist key — deterministic, host untouched); returns a StepResult with
// Success=false for a runtime refusal/failure (non-armable host, arm failure).
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	key, value, err := decodeParams(params)
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
		return nil, fmt.Errorf("grub_parameter_set: arm-ability probe: %w", err)
	}
	if !dec.Armable {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("grub_parameter_set: refusing to arm on this host: %v", dec.Refusals),
		}, nil
	}

	// Install the confirm unit FIRST, then arm the one-shot. Fail-safe ordering:
	// if confirm install fails, nothing is armed; if arming fails after, the
	// confirm unit is inert (its ConditionPathExists trial marker is absent, so
	// systemd skips it). The saved default is never modified by arming.
	if err := bootguard.InstallConfirmUnit(ctx, transport, dec.Flavor); err != nil {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("grub_parameter_set: confirm-unit install failed (host unchanged): %v", err),
		}, nil
	}
	param := key + "=" + value
	if _, err := bootguard.ArmOneshot(ctx, transport, dec.Flavor, param); err != nil {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("grub_parameter_set: arm failed: %v", err),
		}, nil
	}

	return &api.StepResult{
		Success: true,
		Detail: fmt.Sprintf("grub_parameter_set: armed %s on a one-shot trial boot (flavor=%s); "+
			"reboot to apply — auto-reverts to the saved default if it breaks boot (PENDING until reboot)",
			param, dec.Flavor),
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
	if !ok {
		return "", "", errors.New("grub_parameter_set: param 'key' must be a string")
	}
	if key == "" {
		return "", "", errors.New("grub_parameter_set: param 'key' must not be empty")
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
