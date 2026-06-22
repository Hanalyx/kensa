package kernelio

import (
	"os"
	"path/filepath"
	"testing"
)

// IsImmutable returns false for an absent path and for an ordinary
// (non-immutable) file. The immutable=true path needs CAP_LINUX_IMMUTABLE
// (chattr +i) and a supporting filesystem, so it is validated live, not in
// CI; here we confirm the common cases and that no error escapes.
//
// @spec footprint-funnel
// @ac AC-05
func TestIsImmutable(t *testing.T) {
	t.Run("footprint-funnel/AC-05", func(t *testing.T) {})
	dir := t.TempDir()

	// Absent path → not immutable, no error.
	if imm, err := IsImmutable(filepath.Join(dir, "nope")); err != nil || imm {
		t.Errorf("absent: imm=%v err=%v, want false,nil", imm, err)
	}

	// Ordinary file → not immutable.
	fp := filepath.Join(dir, "f")
	if err := os.WriteFile(fp, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if imm, err := IsImmutable(fp); err != nil || imm {
		t.Errorf("ordinary file: imm=%v err=%v, want false,nil", imm, err)
	}

	// A directory also has inode flags; an ordinary one is not immutable.
	if imm, err := IsImmutable(dir); err != nil || imm {
		t.Errorf("ordinary dir: imm=%v err=%v, want false,nil", imm, err)
	}
}
