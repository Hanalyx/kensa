package bootguard

import (
	"context"
	"fmt"

	"github.com/Hanalyx/kensa/api"
)

// Read-only probe commands for the refuse-to-arm gate. Each is a fixed
// command string (no host interpolation) so it is deterministic and
// unit-testable; the SSH transport wraps them in `sudo -n sh -c`.
const (
	// grubProbeCmd exits 0 when GRUB is the bootloader: a grub config
	// generator is on PATH AND /etc/default/grub exists. Necessary because
	// /boot/loader/entries exists for BOTH grub-BLS and systemd-boot, so
	// flavor detection alone cannot confirm GRUB.
	grubProbeCmd = `{ command -v grub2-mkconfig || command -v grub-mkconfig || command -v update-grub ; } >/dev/null 2>&1 && test -f /etc/default/grub`
	// uefiProbeCmd exits 0 on UEFI firmware (untested; BIOS only validated).
	uefiProbeCmd = `test -d /sys/firmware/efi`
	// ostreeProbeCmd exits 0 on an ostree/image-based boot (CoreOS, Ubuntu
	// Core, rpm-ostree) — these own their boot rollback.
	ostreeProbeCmd = `test -e /run/ostree-booted`
	// encBootProbeCmd exits 0 (best-effort) when /boot (or / when /boot is
	// not a separate mount) sits atop a LUKS/crypt device — boot would be
	// interactive, defeating unattended reboot/recovery.
	encBootProbeCmd = `t=$(findmnt -no SOURCE /boot 2>/dev/null || findmnt -no SOURCE / 2>/dev/null); test -n "$t" && lsblk -nso TYPE "$t" 2>/dev/null | grep -qx crypt`
)

// ArmDecision is the result of [CheckArmable]: whether the host is inside the
// guard's validated envelope, and if not, why.
type ArmDecision struct {
	// Armable is true only when there are zero refusals (fail closed).
	Armable bool
	// Flavor is the detected GRUB flavor (set only when GRUB is present).
	Flavor Flavor
	// Refusals lists every reason the host is outside the validated envelope.
	Refusals []string
}

// CheckArmable runs read-only probes and reports whether the boot guard may
// arm on this host. It fails closed: the guard is "armable" only on a tested
// configuration (GRUB on BIOS, not image-based, not encrypted /boot). Every
// out-of-envelope condition (UEFI, non-GRUB, ostree, encrypted /boot) yields a
// refusal rather than a silent best-effort, because the guard's recovery path
// has only been validated on the BIOS/GRUB configurations above.
//
// CheckArmable mutates nothing. It should run over a privileged (Sudo)
// transport so the probes can read root-only boot paths.
func CheckArmable(ctx context.Context, t api.Transport) (ArmDecision, error) {
	grubOK, err := probe(ctx, t, grubProbeCmd)
	if err != nil {
		return ArmDecision{}, fmt.Errorf("bootguard: grub probe: %w", err)
	}
	uefi, err := probe(ctx, t, uefiProbeCmd)
	if err != nil {
		return ArmDecision{}, fmt.Errorf("bootguard: uefi probe: %w", err)
	}
	ostree, err := probe(ctx, t, ostreeProbeCmd)
	if err != nil {
		return ArmDecision{}, fmt.Errorf("bootguard: ostree probe: %w", err)
	}
	enc, err := probe(ctx, t, encBootProbeCmd)
	if err != nil {
		return ArmDecision{}, fmt.Errorf("bootguard: encrypted-boot probe: %w", err)
	}

	var refusals []string
	if !grubOK {
		refusals = append(refusals, "no GRUB bootloader detected (grub2-mkconfig/grub-mkconfig/update-grub absent or /etc/default/grub missing) — the guard supports GRUB only")
	}
	if uefi {
		refusals = append(refusals, "UEFI firmware — the boot guard is validated on BIOS only")
	}
	if ostree {
		refusals = append(refusals, "image-based/ostree system — use the platform's native boot rollback")
	}
	if enc {
		refusals = append(refusals, "encrypted /boot — unattended reboot and recovery would be interactive")
	}

	var flavor Flavor
	if grubOK {
		flavor, err = DetectFlavor(ctx, t)
		if err != nil {
			return ArmDecision{}, err
		}
	}

	return ArmDecision{
		Armable:  len(refusals) == 0,
		Flavor:   flavor,
		Refusals: refusals,
	}, nil
}

// probe runs a read-only command and reports whether it exited 0.
func probe(ctx context.Context, t api.Transport, cmd string) (bool, error) {
	res, err := t.Run(ctx, cmd)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}
