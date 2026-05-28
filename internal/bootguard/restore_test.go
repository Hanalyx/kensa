package bootguard_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/engine"
)

// writeCmd reconstructs the exact command Restore issues to write content
// to path, so tests can program a result for it.
func writeCmd(path, content string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	return "echo '" + b64 + "' | base64 -d > '" + path + "'"
}

func runsContain(runs []string, sub string) bool {
	for _, r := range runs {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// @spec bootguard-restore
// @ac AC-01
// @spec bootguard-restore
// @ac AC-02
func TestRestore_BLS_WritesEntriesNoRegenerate(t *testing.T) {
	t.Run("bootguard-restore/AC-01", func(t *testing.T) {})
	t.Run("bootguard-restore/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	snap := &bootguard.Snapshot{
		Flavor:      bootguard.FlavorBLS,
		DefaultGrub: "GRUB_CMDLINE_LINUX=\"quiet\"\n",
		GrubCfgPath: "/boot/grub2/grub.cfg",
		BLSEntries: map[string]string{
			"/boot/loader/entries/abc-5.14.conf": "title rhel\noptions root=/dev/vda1 ro quiet\n",
		},
	}
	if err := bootguard.Restore(context.Background(), tp, snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !runsContain(tp.Runs, "base64 -d > '/etc/default/grub'") {
		t.Errorf("expected /etc/default/grub write; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "base64 -d > '/boot/loader/entries/abc-5.14.conf'") {
		t.Errorf("expected BLS entry write; runs=%v", tp.Runs)
	}
	// BLS MUST NOT regenerate (would clobber the restored entry args).
	for _, bad := range []string{"grub2-mkconfig", "grub-mkconfig", "update-grub"} {
		if runsContain(tp.Runs, bad) {
			t.Errorf("BLS Restore must not run %q; runs=%v", bad, tp.Runs)
		}
	}
}

// @spec bootguard-restore
// @ac AC-03
func TestRestore_Legacy_WritesAndRegenerates(t *testing.T) {
	t.Run("bootguard-restore/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	snap := &bootguard.Snapshot{
		Flavor:      bootguard.FlavorLegacy,
		DefaultGrub: "GRUB_CMDLINE_LINUX=\"quiet splash\"\n",
		GrubCfgPath: "/boot/grub/grub.cfg",
	}
	if err := bootguard.Restore(context.Background(), tp, snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !runsContain(tp.Runs, "base64 -d > '/etc/default/grub'") {
		t.Errorf("expected /etc/default/grub write; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "update-grub") {
		t.Errorf("expected legacy regenerate (update-grub); runs=%v", tp.Runs)
	}
}

// @spec bootguard-restore
// @ac AC-04
func TestRestore_NilSnapshot(t *testing.T) {
	t.Run("bootguard-restore/AC-04", func(t *testing.T) {})
	if err := bootguard.Restore(context.Background(), engine.NewFakeTransport(), nil); err == nil {
		t.Fatal("expected error on nil snapshot")
	}
}

// @spec bootguard-restore
// @ac AC-05
func TestRestore_ErrorOnWriteFailure(t *testing.T) {
	t.Run("bootguard-restore/AC-05", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[writeCmd("/etc/default/grub", "x")] = &api.CommandResult{ExitCode: 1, Stderr: "read-only filesystem"}
	snap := &bootguard.Snapshot{Flavor: bootguard.FlavorLegacy, DefaultGrub: "x"}
	if err := bootguard.Restore(context.Background(), tp, snap); err == nil {
		t.Fatal("expected error when the /etc/default/grub write fails")
	}
}
