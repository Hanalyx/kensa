package bootguard_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/engine"
)

// @spec bootguard-confirm
// @ac AC-01
func TestInstallConfirmUnit_WritesAndEnables(t *testing.T) {
	t.Run("bootguard-confirm/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	if err := bootguard.InstallConfirmUnit(context.Background(), tp, bootguard.FlavorBLS); err != nil {
		t.Fatalf("InstallConfirmUnit: %v", err)
	}
	if !runsContain(tp.Runs, "base64 -d > '/etc/systemd/system/kensa-bootguard-confirm.service'") {
		t.Errorf("expected the unit to be written; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "systemctl daemon-reload") {
		t.Errorf("expected daemon-reload; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "systemctl enable kensa-bootguard-confirm.service") {
		t.Errorf("expected unit enable; runs=%v", tp.Runs)
	}
}

// Robustness (unannotated): unknown flavor must error rather than install a
// malformed unit.
func TestInstallConfirmUnit_UnknownFlavorErrors(t *testing.T) {
	tp := engine.NewFakeTransport()
	if err := bootguard.InstallConfirmUnit(context.Background(), tp, bootguard.Flavor("weird")); err == nil {
		t.Error("expected error for unknown flavor")
	}
}
