package bootguard_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/bootguard"
	"github.com/Hanalyx/kensa/internal/engine"
)

// Fixed probe command strings (must match gate.go).
const (
	grubProbe   = `{ command -v grub2-mkconfig || command -v grub-mkconfig || command -v update-grub ; } >/dev/null 2>&1 && test -f /etc/default/grub`
	uefiProbe   = `test -d /sys/firmware/efi`
	ostreeProbe = `test -e /run/ostree-booted`
	encProbe    = `t=$(findmnt -no SOURCE /boot 2>/dev/null || findmnt -no SOURCE / 2>/dev/null); test -n "$t" && lsblk -nso TYPE "$t" 2>/dev/null | grep -qx crypt`
	flavorProbe = `test -d '/boot/loader/entries'`
)

// bootGrubBIOS programs a FakeTransport as a BIOS GRUB host (armable): GRUB
// present, not UEFI, not ostree, not encrypted /boot.
func bootGrubBIOS() *engine.FakeTransport {
	tp := engine.NewFakeTransport()
	tp.Results[grubProbe] = &api.CommandResult{ExitCode: 0}
	tp.Results[uefiProbe] = &api.CommandResult{ExitCode: 1}
	tp.Results[ostreeProbe] = &api.CommandResult{ExitCode: 1}
	tp.Results[encProbe] = &api.CommandResult{ExitCode: 1}
	tp.Results[flavorProbe] = &api.CommandResult{ExitCode: 1} // legacy
	return tp
}

func refusalsContain(refusals []string, sub string) bool {
	for _, r := range refusals {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// @spec bootguard-arm-gate
// @ac AC-01
func TestCheckArmable_BIOS_GRUB_Armable(t *testing.T) {
	t.Run("bootguard-arm-gate/AC-01", func(t *testing.T) {})
	d, err := bootguard.CheckArmable(context.Background(), bootGrubBIOS())
	if err != nil {
		t.Fatalf("CheckArmable: %v", err)
	}
	if !d.Armable {
		t.Errorf("expected Armable on BIOS GRUB host; refusals=%v", d.Refusals)
	}
	if len(d.Refusals) != 0 {
		t.Errorf("expected no refusals; got %v", d.Refusals)
	}
}

// @spec bootguard-arm-gate
// @ac AC-02
func TestCheckArmable_RefusesUEFI(t *testing.T) {
	t.Run("bootguard-arm-gate/AC-02", func(t *testing.T) {})
	tp := bootGrubBIOS()
	tp.Results[uefiProbe] = &api.CommandResult{ExitCode: 0} // UEFI
	d, err := bootguard.CheckArmable(context.Background(), tp)
	if err != nil {
		t.Fatalf("CheckArmable: %v", err)
	}
	if d.Armable {
		t.Error("expected refusal on UEFI")
	}
	if !refusalsContain(d.Refusals, "UEFI") {
		t.Errorf("expected a UEFI refusal; got %v", d.Refusals)
	}
}

// @spec bootguard-arm-gate
// @ac AC-03
func TestCheckArmable_RefusesNonGRUB(t *testing.T) {
	t.Run("bootguard-arm-gate/AC-03", func(t *testing.T) {})
	tp := bootGrubBIOS()
	tp.Results[grubProbe] = &api.CommandResult{ExitCode: 1} // no GRUB
	d, err := bootguard.CheckArmable(context.Background(), tp)
	if err != nil {
		t.Fatalf("CheckArmable: %v", err)
	}
	if d.Armable {
		t.Error("expected refusal when GRUB absent")
	}
	if !refusalsContain(d.Refusals, "GRUB") {
		t.Errorf("expected a non-GRUB refusal; got %v", d.Refusals)
	}
}

// @spec bootguard-arm-gate
// @ac AC-04
func TestCheckArmable_RefusesOstree(t *testing.T) {
	t.Run("bootguard-arm-gate/AC-04", func(t *testing.T) {})
	tp := bootGrubBIOS()
	tp.Results[ostreeProbe] = &api.CommandResult{ExitCode: 0} // ostree-booted
	d, err := bootguard.CheckArmable(context.Background(), tp)
	if err != nil {
		t.Fatalf("CheckArmable: %v", err)
	}
	if d.Armable {
		t.Error("expected refusal on ostree/image-based")
	}
	if !refusalsContain(d.Refusals, "ostree") {
		t.Errorf("expected an ostree refusal; got %v", d.Refusals)
	}
}

// @spec bootguard-arm-gate
// @ac AC-05
func TestCheckArmable_RefusesEncryptedBoot(t *testing.T) {
	t.Run("bootguard-arm-gate/AC-05", func(t *testing.T) {})
	tp := bootGrubBIOS()
	tp.Results[encProbe] = &api.CommandResult{ExitCode: 0} // encrypted /boot
	d, err := bootguard.CheckArmable(context.Background(), tp)
	if err != nil {
		t.Fatalf("CheckArmable: %v", err)
	}
	if d.Armable {
		t.Error("expected refusal on encrypted /boot")
	}
	if !refusalsContain(d.Refusals, "encrypted /boot") {
		t.Errorf("expected an encrypted-/boot refusal; got %v", d.Refusals)
	}
}
