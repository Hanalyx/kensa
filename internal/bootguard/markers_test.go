package bootguard

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
)

func hasRun(runs []string, sub string) bool {
	for _, r := range runs {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// @spec bootguard-boot-marker
// @ac AC-01
func TestRHELMarker_Arm(t *testing.T) {
	t.Run("bootguard-boot-marker/AC-01", func(t *testing.T) {})
	m, err := markerFor(FlavorBLS)
	if err != nil {
		t.Fatalf("markerFor(BLS): %v", err)
	}
	tp := engine.NewFakeTransport()
	if err := m.Arm(context.Background(), tp); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if !hasRun(tp.Runs, "grub2-editenv - set boot_success=0") {
		t.Errorf("expected boot_success=0; runs=%v", tp.Runs)
	}
}

// @spec bootguard-boot-marker
// @ac AC-02
func TestRHELMarker_Confirmed(t *testing.T) {
	t.Run("bootguard-boot-marker/AC-02", func(t *testing.T) {})
	m := rhelMarker{}

	healthy := engine.NewFakeTransport()
	healthy.Results["grub2-editenv - list"] = &api.CommandResult{Stdout: "saved_entry=x\nboot_success=1\nboot_indeterminate=0\n"}
	if ok, err := m.Confirmed(context.Background(), healthy); err != nil || !ok {
		t.Errorf("expected confirmed=true on boot_success=1 (ok=%v err=%v)", ok, err)
	}

	unhealthy := engine.NewFakeTransport()
	unhealthy.Results["grub2-editenv - list"] = &api.CommandResult{Stdout: "saved_entry=x\nboot_success=0\nboot_indeterminate=1\n"}
	if ok, err := m.Confirmed(context.Background(), unhealthy); err != nil || ok {
		t.Errorf("expected confirmed=false on boot_success=0 (ok=%v err=%v)", ok, err)
	}
}

// @spec bootguard-boot-marker
// @ac AC-03
func TestRHELMarker_Clear(t *testing.T) {
	t.Run("bootguard-boot-marker/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	if err := (rhelMarker{}).Clear(context.Background(), tp); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if !hasRun(tp.Runs, "grub2-editenv - set boot_success=1") {
		t.Errorf("expected boot_success=1; runs=%v", tp.Runs)
	}
}
