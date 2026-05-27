package bootguard

import (
	"strings"
	"testing"
)

// @spec bootguard-confirm
// @ac AC-02
func TestBuildConfirmUnit_RHEL_ClearsBootSuccess(t *testing.T) {
	t.Run("bootguard-confirm/AC-02", func(t *testing.T) {})
	u, err := buildConfirmUnit(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmUnit(BLS): %v", err)
	}
	if !strings.Contains(u, "boot_success") {
		t.Errorf("RHEL confirm unit must set boot_success; got:\n%s", u)
	}
	if !strings.Contains(u, "Type=oneshot") {
		t.Errorf("confirm unit must be a oneshot; got:\n%s", u)
	}
}

// @spec bootguard-confirm
// @ac AC-03
func TestBuildConfirmUnit_Ubuntu_UnsetsRecordfail(t *testing.T) {
	t.Run("bootguard-confirm/AC-03", func(t *testing.T) {})
	u, err := buildConfirmUnit(FlavorLegacy)
	if err != nil {
		t.Fatalf("buildConfirmUnit(legacy): %v", err)
	}
	if !strings.Contains(u, "grub-editenv /boot/grub/grubenv unset recordfail") {
		t.Errorf("Ubuntu confirm unit must unset recordfail; got:\n%s", u)
	}
	if strings.Contains(u, "boot_success") {
		t.Errorf("Ubuntu confirm unit must not touch boot_success; got:\n%s", u)
	}
}

// @spec bootguard-confirm
// @ac AC-04
func TestBuildConfirmUnit_DisarmsAndOrdered(t *testing.T) {
	t.Run("bootguard-confirm/AC-04", func(t *testing.T) {})
	u, err := buildConfirmUnit(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmUnit: %v", err)
	}
	if !strings.Contains(u, "rm -rf "+StateDir) {
		t.Errorf("confirm unit must remove the staged state dir; got:\n%s", u)
	}
	if !strings.Contains(u, "After=multi-user.target") {
		t.Errorf("confirm unit must be ordered after multi-user.target; got:\n%s", u)
	}
}
