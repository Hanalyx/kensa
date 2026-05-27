package bootguard_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/engine"
)

// @spec bootguard-confirm
// @ac AC-01
func TestInstallConfirmUnit_StagesScriptAndUnit(t *testing.T) {
	t.Run("bootguard-confirm/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	if err := bootguard.InstallConfirmUnit(context.Background(), tp, bootguard.FlavorBLS); err != nil {
		t.Fatalf("InstallConfirmUnit: %v", err)
	}
	if !runsContain(tp.Runs, "base64 -d > '/var/lib/kensa/bootguard/confirm.sh'") {
		t.Errorf("expected the confirm script to be staged; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "chmod 0750 '/var/lib/kensa/bootguard/confirm.sh'") {
		t.Errorf("expected the confirm script to be made executable; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "base64 -d > '/etc/systemd/system/kensa-bootguard-confirm.service'") {
		t.Errorf("expected the unit to be written; runs=%v", tp.Runs)
	}
	if !runsContain(tp.Runs, "systemctl daemon-reload") || !runsContain(tp.Runs, "systemctl enable kensa-bootguard-confirm.service") {
		t.Errorf("expected daemon-reload + enable; runs=%v", tp.Runs)
	}
}

// Robustness (unannotated): an unsupported flavor errors rather than installing
// a malformed script.
func TestInstallConfirmUnit_UnknownFlavorErrors(t *testing.T) {
	tp := engine.NewFakeTransport()
	if err := bootguard.InstallConfirmUnit(context.Background(), tp, bootguard.Flavor("weird")); err == nil {
		t.Error("expected error for unsupported flavor")
	}
}
