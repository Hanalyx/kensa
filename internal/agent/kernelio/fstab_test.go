package kernelio

import (
	"errors"
	"testing"
)

const sampleFstab = `# /etc/fstab
UUID=aaaa /     ext4 defaults        0 1
UUID=bbbb /tmp  ext4 defaults,nodev  0 2
UUID=cccc /home ext4 defaults        0 2
`

// @spec kernelio-mount
// @ac AC-01
func TestFstabFindLine(t *testing.T) {
	t.Run("kernelio-mount/AC-01", func(t *testing.T) {})
	line, found := FstabFindLine(sampleFstab, "/tmp")
	if !found || line != "UUID=bbbb /tmp  ext4 defaults,nodev  0 2" {
		t.Errorf("FstabFindLine(/tmp) = (%q, %v)", line, found)
	}
	if _, found := FstabFindLine(sampleFstab, "/nonexistent"); found {
		t.Error("FstabFindLine should not find a missing mount point")
	}
	// A commented mount point is not matched.
	if _, found := FstabFindLine("# UUID=x /tmp ext4 defaults 0 0\n", "/tmp"); found {
		t.Error("a comment line must not match")
	}
}

// @spec kernelio-mount
// @ac AC-01
func TestFstabAddOptions(t *testing.T) {
	t.Run("kernelio-mount/AC-01", func(t *testing.T) {})

	// Add missing options; existing one (nodev) not duplicated; fields
	// re-joined single-spaced.
	got, err := FstabAddOptions(sampleFstab, "/tmp", []string{"nodev", "nosuid", "noexec"})
	if err != nil {
		t.Fatalf("FstabAddOptions: %v", err)
	}
	wantLine := "UUID=bbbb /tmp ext4 defaults,nodev,nosuid,noexec 0 2"
	if l, _ := FstabFindLine(got, "/tmp"); l != wantLine {
		t.Errorf("modified line = %q, want %q", l, wantLine)
	}
	// Other lines untouched.
	if l, _ := FstabFindLine(got, "/home"); l != "UUID=cccc /home ext4 defaults        0 2" {
		t.Errorf("/home line should be untouched, got %q", l)
	}

	// Idempotent: adding an already-present option is a no-op on that token.
	got2, _ := FstabAddOptions(got, "/tmp", []string{"nosuid"})
	if l, _ := FstabFindLine(got2, "/tmp"); l != wantLine {
		t.Errorf("idempotent add changed the line: %q", l)
	}

	// No matching entry → ErrNoFstabEntry.
	if _, err := FstabAddOptions(sampleFstab, "/missing", []string{"nodev"}); !errors.Is(err, ErrNoFstabEntry) {
		t.Errorf("err = %v, want ErrNoFstabEntry", err)
	}
}

// @spec kernelio-mount
// @ac AC-01
func TestFstabReplaceLine(t *testing.T) {
	t.Run("kernelio-mount/AC-01", func(t *testing.T) {})
	prior := "UUID=bbbb /tmp ext4 defaults 0 2"
	got, err := FstabReplaceLine(sampleFstab, "/tmp", prior)
	if err != nil {
		t.Fatalf("FstabReplaceLine: %v", err)
	}
	if l, _ := FstabFindLine(got, "/tmp"); l != prior {
		t.Errorf("replaced line = %q, want %q", l, prior)
	}
	if _, err := FstabReplaceLine(sampleFstab, "/missing", prior); !errors.Is(err, ErrNoFstabEntry) {
		t.Errorf("err = %v, want ErrNoFstabEntry", err)
	}
}
