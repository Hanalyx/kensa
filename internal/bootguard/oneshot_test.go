package bootguard_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/engine"
)

// @spec bootguard-oneshot
// @ac AC-01
// @spec bootguard-oneshot
// @ac AC-02
// @spec bootguard-oneshot
// @ac AC-03
func TestArmOneshot_RHEL_CreatesTrialAndOneShot(t *testing.T) {
	t.Run("bootguard-oneshot/AC-01", func(t *testing.T) {})
	t.Run("bootguard-oneshot/AC-02", func(t *testing.T) {})
	t.Run("bootguard-oneshot/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results["grubby --default-kernel"] = &api.CommandResult{Stdout: "/boot/vmlinuz-x\n"}

	title, err := bootguard.ArmOneshot(context.Background(), tp, bootguard.FlavorBLS, "audit=1")
	if err != nil {
		t.Fatalf("ArmOneshot: %v", err)
	}
	if title != "kensa-bootguard-trial" {
		t.Errorf("title=%q, want kensa-bootguard-trial", title)
	}
	if !runsContain(tp.Runs, "grubby --add-kernel='/boot/vmlinuz-x' --copy-default --args='audit=1 kensa_bootguard_trial' --title='kensa-bootguard-trial'") {
		t.Errorf("expected trial-entry creation via grubby --copy-default with the sentinel; runs=%v", tp.Runs)
	}
	if runsContain(tp.Runs, "--update-kernel") {
		t.Errorf("ArmOneshot must not modify the default entry (--update-kernel); runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "grub2-reboot 'kensa-bootguard-trial'") {
		t.Errorf("expected grub2-reboot one-shot; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "base64 -d > '/var/lib/kensa/bootguard/trial_entry'") ||
		!runsContain(tp.Runs, "base64 -d > '/var/lib/kensa/bootguard/param_applied'") {
		t.Errorf("expected trial identity + param recorded; runs=%v", tp.Runs)
	}
}

const sampleUbuntuGrubCfg = `# generated
set timeout=5
menuentry 'Ubuntu' --class ubuntu --class os $menuentry_id_option 'gnulinux-simple-uuid' {
	recordfail
	load_video
	gfxmode $linux_gfx_mode
	insmod gzio
	search --no-floppy --fs-uuid --set=root 1a3e85dc
	linux	/vmlinuz-5.15.0-179-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro
	initrd	/initrd.img-5.15.0-179-generic
}
submenu 'Advanced options for Ubuntu' {
	menuentry 'Ubuntu, with Linux 5.15.0-179' {
		linux /vmlinuz-5.15.0-179-generic root=X ro
	}
}
`

// @spec bootguard-oneshot
// @ac AC-04
func TestArmOneshot_Ubuntu_ClonesAndOneShot(t *testing.T) {
	t.Run("bootguard-oneshot/AC-04", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results["cat /boot/grub/grub.cfg"] = &api.CommandResult{Stdout: sampleUbuntuGrubCfg}

	title, err := bootguard.ArmOneshot(context.Background(), tp, bootguard.FlavorLegacy, "audit=1")
	if err != nil {
		t.Fatalf("ArmOneshot(legacy): %v", err)
	}
	if title != "kensa-bootguard-trial" {
		t.Errorf("title=%q", title)
	}
	if !runsContain(tp.Runs, "base64 -d > '/etc/grub.d/09_kensa_bootguard'") {
		t.Errorf("expected the trial menuentry script to be written; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "update-grub") {
		t.Errorf("expected update-grub; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "grub-reboot 'kensa-bootguard-trial'") {
		t.Errorf("expected grub-reboot one-shot; runs=%v", tp.Runs)
	}
}

// @spec bootguard-oneshot
// @ac AC-06
func TestArmOneshot_RejectsUnsupportedFlavor(t *testing.T) {
	t.Run("bootguard-oneshot/AC-06", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	if _, err := bootguard.ArmOneshot(context.Background(), tp, bootguard.Flavor("weird"), "audit=1"); err == nil {
		t.Error("expected error for unsupported flavor")
	}
}
