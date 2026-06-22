package mountoptionset

import (
	"os/exec"
	"strings"
	"testing"
)

// runAwk executes a real awk against the given fstab text with the supplied
// KENSA_* environment, returning stdout. A non-zero exit (e.g. an awk syntax
// error — the bug live validation caught, where values were single-quoted
// inside the program) fails the test. This is the regression guard the
// transport-faking unit tests could not provide: they never run awk.
func runAwk(t *testing.T, program, fstab string, env map[string]string) string {
	t.Helper()
	cmd := exec.Command("awk", program)
	cmd.Stdin = strings.NewReader(fstab)
	cmd.Env = []string{}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("awk failed (program rejected by real awk): %v\nprogram:\n%s", err, program)
	}
	return string(out)
}

// The apply awk program must run under real awk and append missing options
// to field 4 of the matching line, leaving other lines untouched.
//
// @spec kernelio-mount
// @ac AC-04
func TestFstabAddAwk_RealAwk(t *testing.T) {
	t.Run("kernelio-mount/AC-04", func(t *testing.T) {})
	fstab := "UUID=aaaa / ext4 defaults 0 1\ntmpfs /tmp tmpfs defaults 0 0\n"
	out := runAwk(t, fstabAddAwk, fstab, map[string]string{
		"KENSA_MP": "/tmp", "KENSA_OPTS": "nodev,nosuid",
	})
	if !strings.Contains(out, "nodev") || !strings.Contains(out, "nosuid") {
		t.Errorf("apply awk did not add options:\n%s", out)
	}
	if !strings.Contains(out, "UUID=aaaa / ext4 defaults 0 1") {
		t.Errorf("apply awk altered a non-matching line:\n%s", out)
	}
	// Idempotent: an already-present option is not duplicated.
	out2 := runAwk(t, fstabAddAwk, out, map[string]string{
		"KENSA_MP": "/tmp", "KENSA_OPTS": "nodev",
	})
	if strings.Count(out2, "nodev") != 1 {
		t.Errorf("apply awk duplicated an already-present option:\n%s", out2)
	}
}

// The rollback awk program must run under real awk and replace the matching
// line with KENSA_LINE verbatim — including a value with shell/awk
// metacharacters, which the previous single-quote-in-program form rejected.
//
// @spec handler-mount-option-set
// @ac AC-03
func TestFstabRestoreAwk_RealAwk(t *testing.T) {
	t.Run("handler-mount-option-set/AC-03", func(t *testing.T) {})
	fstab := "UUID=aaaa / ext4 defaults 0 1\ntmpfs /tmp tmpfs defaults,nodev 0 0\n"
	prior := "tmpfs /tmp tmpfs defaults 0 0"
	out := runAwk(t, fstabRestoreAwk, fstab, map[string]string{
		"KENSA_MP": "/tmp", "KENSA_LINE": prior,
	})
	if !strings.Contains(out, prior) || strings.Contains(out, "defaults,nodev") {
		t.Errorf("rollback awk did not restore the prior line:\n%s", out)
	}
	if !strings.Contains(out, "UUID=aaaa / ext4 defaults 0 1") {
		t.Errorf("rollback awk altered a non-matching line:\n%s", out)
	}
	// A prior line bearing an apostrophe must round-trip (the bug case).
	weird := "tmpfs /tmp tmpfs defaults 0 0 # don't break"
	out2 := runAwk(t, fstabRestoreAwk, fstab, map[string]string{
		"KENSA_MP": "/tmp", "KENSA_LINE": weird,
	})
	if !strings.Contains(out2, weird) {
		t.Errorf("rollback awk mangled a value with an apostrophe:\n%s", out2)
	}
}
