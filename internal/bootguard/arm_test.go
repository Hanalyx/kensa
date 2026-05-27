package bootguard_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/engine"
)

// @spec bootguard-arm
// @ac AC-01
func TestStageRevert_BLS_BacksUpFiles(t *testing.T) {
	t.Run("bootguard-arm/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	snap := &bootguard.Snapshot{
		Flavor:      bootguard.FlavorBLS,
		DefaultGrub: "GRUB_CMDLINE_LINUX=\"quiet\"\n",
		GrubCfgPath: "/boot/grub2/grub.cfg",
		BLSEntries:  map[string]string{"/boot/loader/entries/abc-5.14.conf": "options root=/dev/vda1 ro quiet\n"},
	}
	if err := bootguard.StageRevert(context.Background(), tp, snap); err != nil {
		t.Fatalf("StageRevert: %v", err)
	}
	if !runsContain(tp.Runs, "base64 -d > '/var/lib/kensa/bootguard/default_grub.bak'") {
		t.Errorf("expected /etc/default/grub backup; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "base64 -d > '/var/lib/kensa/bootguard/entries/abc-5.14.conf'") {
		t.Errorf("expected BLS entry backup; runs=%v", tp.Runs)
	}
}

// @spec bootguard-arm
// @ac AC-02
func TestStageRevert_WritesExecutableRevertScript(t *testing.T) {
	t.Run("bootguard-arm/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	snap := &bootguard.Snapshot{Flavor: bootguard.FlavorLegacy, DefaultGrub: "x\n", GrubCfgPath: "/boot/grub/grub.cfg"}
	if err := bootguard.StageRevert(context.Background(), tp, snap); err != nil {
		t.Fatalf("StageRevert: %v", err)
	}
	if !runsContain(tp.Runs, "base64 -d > '/var/lib/kensa/bootguard/revert.sh'") {
		t.Errorf("expected revert.sh write; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "chmod 0750") {
		t.Errorf("expected revert.sh to be made executable; runs=%v", tp.Runs)
	}
}

// @spec bootguard-arm
// @ac AC-04
func TestDisarm_RemovesStateDir(t *testing.T) {
	t.Run("bootguard-arm/AC-04", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	if err := bootguard.Disarm(context.Background(), tp); err != nil {
		t.Fatalf("Disarm: %v", err)
	}
	if !runsContain(tp.Runs, "rm -rf '/var/lib/kensa/bootguard'") {
		t.Errorf("expected state-dir removal; runs=%v", tp.Runs)
	}
}
