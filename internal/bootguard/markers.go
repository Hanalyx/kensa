package bootguard

import (
	"context"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// bootMarker is the per-family boot-attempt state the guard sets before a
// guarded reboot ("this boot is not yet confirmed") and reads afterward to
// decide confirm-vs-revert. RHEL uses the native grubenv boot_success flag;
// Ubuntu uses recordfail (a separate increment).
type bootMarker interface {
	// Arm sets the marker to "this boot is not yet confirmed healthy".
	Arm(ctx context.Context, t api.Transport) error
	// Confirmed reports whether the last boot reached a healthy state.
	Confirmed(ctx context.Context, t api.Transport) (bool, error)
	// Clear marks the boot confirmed / disarms the revert.
	Clear(ctx context.Context, t api.Transport) error
}

// markerFor returns the boot marker for a bootloader flavor.
func markerFor(flavor Flavor) (bootMarker, error) {
	switch flavor {
	case FlavorBLS:
		return rhelMarker{}, nil
	case FlavorLegacy:
		return ubuntuMarker{}, nil
	default:
		return nil, fmt.Errorf("bootguard: no boot marker implemented for flavor %q", flavor)
	}
}

const ubuntuGrubenv = "/boot/grub/grubenv"

// ubuntuMarker uses the native Ubuntu grubenv recordfail flag. Real-host recon
// (2026-05-26/27) confirmed grub-editenv + /boot/grub/grubenv; but native
// clearing is NOT reliably observed (.248 showed recordfail=1 while up), so —
// mirroring the RHEL boot_success ownership — the confirm step (separate
// increment) clears recordfail on a healthy boot rather than trusting the
// grub-initrd-fallback machinery.
type ubuntuMarker struct{}

// Arm sets recordfail=1 — "this boot has not been confirmed healthy".
func (ubuntuMarker) Arm(ctx context.Context, t api.Transport) error {
	_, err := runOK(ctx, t, "grub-editenv "+ubuntuGrubenv+" set recordfail=1")
	return err
}

// Confirmed reports whether recordfail is absent (cleared = healthy).
func (ubuntuMarker) Confirmed(ctx context.Context, t api.Transport) (bool, error) {
	res, err := t.Run(ctx, "grub-editenv "+ubuntuGrubenv+" list")
	if err != nil {
		return false, fmt.Errorf("bootguard: grub-editenv list: transport error: %w", err)
	}
	if !res.OK() {
		return false, fmt.Errorf("bootguard: grub-editenv list failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return grubenvValue(res.Stdout, "recordfail") == "", nil
}

// Clear unsets recordfail, marking the boot confirmed / disarming the revert.
func (ubuntuMarker) Clear(ctx context.Context, t api.Transport) error {
	_, err := runOK(ctx, t, "grub-editenv "+ubuntuGrubenv+" unset recordfail")
	return err
}

// rhelMarker uses the native RHEL grubenv boot_success flag. Real-host recon
// (2026-05-26, RHEL 8.10 / 10.1) confirmed boot_success + boot_indeterminate
// are present and grub2-set-bootflag exists. Note: grub-boot-success.service
// is NOT present on these server installs (only grub-boot-indeterminate), so
// the confirm step (separate increment) must set boot_success=1 on a healthy
// boot — the guard cannot free-ride on a graphical-session service.
type rhelMarker struct{}

// Arm sets boot_success=0 — "this boot has not been confirmed healthy".
func (rhelMarker) Arm(ctx context.Context, t api.Transport) error {
	_, err := runOK(ctx, t, "grub2-editenv - set boot_success=0")
	return err
}

// Confirmed reports whether grubenv boot_success is 1.
func (rhelMarker) Confirmed(ctx context.Context, t api.Transport) (bool, error) {
	res, err := t.Run(ctx, "grub2-editenv - list")
	if err != nil {
		return false, fmt.Errorf("bootguard: grub2-editenv list: transport error: %w", err)
	}
	if !res.OK() {
		return false, fmt.Errorf("bootguard: grub2-editenv list failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return grubenvValue(res.Stdout, "boot_success") == "1", nil
}

// Clear marks the boot confirmed (boot_success=1), disarming the revert.
func (rhelMarker) Clear(ctx context.Context, t api.Transport) error {
	_, err := runOK(ctx, t, "grub2-editenv - set boot_success=1")
	return err
}

// grubenvValue extracts the value for key from `grub2-editenv list` output
// (one KEY=VALUE per line); returns "" when absent.
func grubenvValue(list, key string) string {
	for _, line := range strings.Split(list, "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimSpace(line[len(key)+1:])
		}
	}
	return ""
}
