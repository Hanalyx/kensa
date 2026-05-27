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

func TestBuildConfirmScript_LegacyNotYetImplemented(t *testing.T) {
	if _, err := buildConfirmScript(FlavorLegacy); err == nil {
		t.Error("expected error: legacy confirm script not implemented yet")
	}
}
