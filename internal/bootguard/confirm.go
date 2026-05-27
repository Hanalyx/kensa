package bootguard

import (
	"context"
	"fmt"

	"github.com/Hanalyx/kensa/api"
)

const (
	confirmUnitName = "kensa-bootguard-confirm.service"
	confirmUnitPath = "/etc/systemd/system/" + confirmUnitName
)

// InstallConfirmUnit writes and enables a systemd oneshot that, on reaching a
// healthy boot (multi-user + network-online), clears the per-family boot
// marker and removes the staged revert artifacts — standing the guard down.
//
// Both families need this because native marker-clearing was found unreliable
// on the fleet: RHEL server lacks grub-boot-success.service, and Ubuntu 26.04
// left recordfail=1 while healthy (design §10). So the guard owns the
// "confirm healthy boot" signal rather than trusting native services.
//
// This is the success/stand-down half of the boot-resident mechanism; the
// revert TRIGGER (run revert.sh on a failed boot) is a separate increment.
// Must run over a privileged (Sudo) transport.
func InstallConfirmUnit(ctx context.Context, t api.Transport, flavor Flavor) error {
	unit, err := buildConfirmUnit(flavor)
	if err != nil {
		return err
	}
	if err := writeRemoteFile(ctx, t, confirmUnitPath, unit); err != nil {
		return err
	}
	if _, err := runOK(ctx, t, "systemctl daemon-reload"); err != nil {
		return err
	}
	_, err = runOK(ctx, t, "systemctl enable "+confirmUnitName)
	return err
}

// buildConfirmUnit renders the confirm oneshot unit for flavor. The marker
// clear runs first, then the staged artifacts are removed (disarm).
func buildConfirmUnit(flavor Flavor) (string, error) {
	var clear string
	switch flavor {
	case FlavorBLS:
		// grub2-set-bootflag is the supported atomic flag-setter; fall back
		// to grub2-editenv if absent.
		clear = "/bin/sh -c 'grub2-set-bootflag boot_success 2>/dev/null || grub2-editenv - set boot_success=1'"
	case FlavorLegacy:
		clear = "/bin/sh -c 'grub-editenv " + ubuntuGrubenv + " unset recordfail'"
	default:
		return "", fmt.Errorf("bootguard: no confirm unit for flavor %q", flavor)
	}
	unit := "[Unit]\n" +
		"Description=kensa bootguard - confirm healthy boot and stand down\n" +
		"After=multi-user.target network-online.target\n" +
		"Wants=network-online.target\n" +
		"\n" +
		"[Service]\n" +
		"Type=oneshot\n" +
		"ExecStart=" + clear + "\n" +
		"ExecStart=/bin/rm -rf " + StateDir + "\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"
	return unit, nil
}
