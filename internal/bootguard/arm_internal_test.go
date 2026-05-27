package bootguard

import (
	"strings"
	"testing"
)

// @spec bootguard-arm
// @ac AC-03
func TestBuildRevertScript_BLS(t *testing.T) {
	t.Run("bootguard-arm/AC-03", func(t *testing.T) {})
	s := buildRevertScript(&Snapshot{
		Flavor:     FlavorBLS,
		GrubCfgPath: "/boot/grub2/grub.cfg",
		BLSEntries: map[string]string{"/boot/loader/entries/x.conf": "options ro\n"},
	})
	if !strings.Contains(s, "cp -f '/var/lib/kensa/bootguard/default_grub.bak' /etc/default/grub") {
		t.Errorf("BLS revert.sh must restore /etc/default/grub; got:\n%s", s)
	}
	if !strings.Contains(s, "/boot/loader/entries/") {
		t.Errorf("BLS revert.sh must copy entry files back; got:\n%s", s)
	}
	if strings.Contains(s, "update-grub") || strings.Contains(s, "grub2-mkconfig") || strings.Contains(s, "grub-mkconfig") {
		t.Errorf("BLS revert.sh MUST NOT regenerate (would clobber per-entry args); got:\n%s", s)
	}
}

// @spec bootguard-arm
// @ac AC-03
func TestBuildRevertScript_Legacy(t *testing.T) {
	t.Run("bootguard-arm/AC-03", func(t *testing.T) {})
	s := buildRevertScript(&Snapshot{Flavor: FlavorLegacy, GrubCfgPath: "/boot/grub/grub.cfg"})
	if !strings.Contains(s, "cp -f '/var/lib/kensa/bootguard/default_grub.bak' /etc/default/grub") {
		t.Errorf("legacy revert.sh must restore /etc/default/grub; got:\n%s", s)
	}
	if !strings.Contains(s, "update-grub") {
		t.Errorf("legacy revert.sh must regenerate via update-grub; got:\n%s", s)
	}
	if strings.Contains(s, "/boot/loader/entries") {
		t.Errorf("legacy revert.sh must not touch BLS entries; got:\n%s", s)
	}
}
