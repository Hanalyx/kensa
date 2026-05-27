package bootguard

import (
	"strings"
	"testing"
)

// @spec bootguard-confirm
// @ac AC-02
func TestBuildConfirmScript_RHEL_Promotes(t *testing.T) {
	t.Run("bootguard-confirm/AC-02", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmScript(BLS): %v", err)
	}
	if !strings.Contains(s, "grep -q kensa_bootguard_trial /proc/cmdline") {
		t.Errorf("confirm script must detect the trial via /proc/cmdline; got:\n%s", s)
	}
	if !strings.Contains(s, "grubby --update-kernel=DEFAULT --args=") {
		t.Errorf("confirm script must promote the param onto the default entry; got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-03
func TestBuildConfirmScript_RHEL_CleansUpOnFallback(t *testing.T) {
	t.Run("bootguard-confirm/AC-03", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmScript(BLS): %v", err)
	}
	// The else (fallback) branch removes the trial without promoting.
	if !strings.Contains(s, "else") || !strings.Contains(s, "remove_trial") {
		t.Errorf("confirm script must clean up the trial on fallback; got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-04
func TestBuildConfirmScript_RemovesSpecificEntry(t *testing.T) {
	t.Run("bootguard-confirm/AC-04", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorBLS)
	if err != nil {
		t.Fatalf("buildConfirmScript(BLS): %v", err)
	}
	if !strings.Contains(s, "grep -l kensa_bootguard_trial /boot/loader/entries/*.conf") {
		t.Errorf("trial removal must target the sentinel-bearing entry file; got:\n%s", s)
	}
	if strings.Contains(s, "grubby --remove-kernel") {
		t.Errorf("must NOT use grubby --remove-kernel (would drop the default too); got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-05
func TestBuildConfirmScript_Ubuntu_Promotes(t *testing.T) {
	t.Run("bootguard-confirm/AC-05", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorLegacy)
	if err != nil {
		t.Fatalf("buildConfirmScript(legacy): %v", err)
	}
	if !strings.Contains(s, "grep -q kensa_bootguard_trial /proc/cmdline") {
		t.Errorf("Ubuntu confirm must detect the trial via /proc/cmdline; got:\n%s", s)
	}
	if !strings.Contains(s, "GRUB_CMDLINE_LINUX") || !strings.Contains(s, "/etc/default/grub") {
		t.Errorf("Ubuntu promote must append the param to GRUB_CMDLINE_LINUX; got:\n%s", s)
	}
	if !strings.Contains(s, "update-grub") {
		t.Errorf("Ubuntu confirm must regenerate via update-grub; got:\n%s", s)
	}
}

// @spec bootguard-confirm
// @ac AC-06
func TestBuildConfirmScript_Ubuntu_CleansUpTrialScript(t *testing.T) {
	t.Run("bootguard-confirm/AC-06", func(t *testing.T) {})
	s, err := buildConfirmScript(FlavorLegacy)
	if err != nil {
		t.Fatalf("buildConfirmScript(legacy): %v", err)
	}
	if !strings.Contains(s, "rm -f /etc/grub.d/09_kensa_bootguard") {
		t.Errorf("Ubuntu confirm must remove the trial /etc/grub.d script; got:\n%s", s)
	}
	if !strings.Contains(s, "else") {
		t.Errorf("Ubuntu confirm must have a fallback (else) branch; got:\n%s", s)
	}
}

func TestBuildConfirmScript_UnsupportedFlavor(t *testing.T) {
	if _, err := buildConfirmScript(Flavor("weird")); err == nil {
		t.Error("expected error for unsupported flavor")
	}
}
