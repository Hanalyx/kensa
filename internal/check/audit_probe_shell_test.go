package check

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runProbe runs AuditTargetProbe(lines) in sh with bin first on PATH, so a
// fake uname and ausyscall stand in for the host's.
func runProbe(t *testing.T, bin string, lines []string) *AuditTarget {
	t.Helper()
	cmd := exec.Command("sh", "-c", AuditTargetProbe(lines))
	cmd.Env = []string{"PATH=" + bin}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return ParseAuditTarget(string(out))
}

func writeExe(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The probe keeps an ausyscall answer only when ausyscall succeeds and
// prints exactly one number. A failed lookup, several lines, a word, or no
// ausyscall at all leaves the name unresolved, and then two siblings that
// differ only in -S are Unresolved, which the guard refuses.
//
// @spec check-audit-rule-match
// @ac AC-19
func TestAuditProbe_AusyscallAnswersAreStrict(t *testing.T) {
	t.Run("check-audit-rule-match/AC-19", func(t *testing.T) {
		shPath, err := exec.LookPath("sh")
		if err != nil {
			t.Skip("no sh")
		}
		bin := t.TempDir()
		if err := os.Symlink(shPath, filepath.Join(bin, "sh")); err != nil {
			t.Fatal(err)
		}
		writeExe(t, bin, "uname", "echo x86_64\n")
		writeExe(t, bin, "ausyscall", `case "$2" in
chmod) echo 90;;
chown) exit 1;;
fchown) printf '93\nwarning: table is old\n';;
lchown) echo lchown;;
*) exit 1;;
esac
`)
		a := "-a always,exit -F arch=b64 -S chmod -F auid>=1000 -k perm_mod"
		lines := []string{a,
			"-a always,exit -F arch=b64 -S chown -k k",
			"-a always,exit -F arch=b64 -S fchown -k k",
			"-a always,exit -F arch=b64 -S lchown -k k"}
		tg := runProbe(t, bin, lines)
		if tg.Syscalls["b64"]["chmod"] != 90 {
			t.Fatalf("a clean answer was lost: %+v", tg.Syscalls)
		}
		for _, sc := range []string{"chown", "fchown", "lchown"} {
			if n, ok := tg.Syscalls["b64"][sc]; ok {
				t.Errorf("%s kept as %d from a bad ausyscall answer", sc, n)
			}
		}
		tg.AuditctlVersion = "3.1.2" // off the measured gate: names alone decide nothing
		for _, sc := range []string{"chown", "fchown", "lchown"} {
			b := "-a always,exit -F arch=b64 -S " + sc + " -F auid>=1000 -k perm_mod"
			if id, why := AuditRuleIdentity(a, b, tg); id != AuditUnresolved {
				t.Errorf("chmod vs %s with %s unresolved: %v (%s), want unresolved", sc, sc, id, why)
			}
		}
		// No ausyscall on the host at all.
		bare := t.TempDir()
		if err := os.Symlink(shPath, filepath.Join(bare, "sh")); err != nil {
			t.Fatal(err)
		}
		writeExe(t, bare, "uname", "echo x86_64\n")
		tg = runProbe(t, bare, lines)
		if len(tg.Syscalls) != 0 {
			t.Errorf("syscall numbers without ausyscall: %+v", tg.Syscalls)
		}
		tg.AuditctlVersion = "3.1.2"
		if id, _ := AuditRuleIdentity(a, "-a always,exit -F arch=b64 -S chown -F auid>=1000 -k perm_mod", tg); id != AuditUnresolved {
			t.Errorf("siblings with no ausyscall: %v, want unresolved", id)
		}
	})
}
