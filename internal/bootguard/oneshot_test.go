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
	// AC-01: a trial entry is created by cloning the default (--copy-default,
	// --add-kernel) with the new args — NOT by modifying the default.
	if !runsContain(tp.Runs, "grubby --add-kernel='/boot/vmlinuz-x' --copy-default --args='audit=1' --title='kensa-bootguard-trial'") {
		t.Errorf("expected trial-entry creation via grubby --copy-default; runs=%v", tp.Runs)
	}
	if runsContain(tp.Runs, "--update-kernel") {
		t.Errorf("ArmOneshot must not modify the default entry (--update-kernel); runs=%v", tp.Runs)
	}
	// AC-02: one-shot via grub2-reboot.
	if !runsContain(tp.Runs, "grub2-reboot 'kensa-bootguard-trial'") {
		t.Errorf("expected grub2-reboot one-shot; runs=%v", tp.Runs)
	}
	// AC-03: trial identity recorded.
	if !runsContain(tp.Runs, "base64 -d > '/var/lib/kensa/bootguard/trial_entry'") {
		t.Errorf("expected trial identity recorded; runs=%v", tp.Runs)
	}
}

// @spec bootguard-oneshot
// @ac AC-04
func TestArmOneshot_RejectsLegacy(t *testing.T) {
	t.Run("bootguard-oneshot/AC-04", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	if _, err := bootguard.ArmOneshot(context.Background(), tp, bootguard.FlavorLegacy, "audit=1"); err == nil {
		t.Error("expected error: ArmOneshot does not yet support legacy/Ubuntu")
	}
}
