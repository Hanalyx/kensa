package auditruleset

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runScan runs auditRulesScanCmd with /etc/audit moved under root.
func runScan(t *testing.T, root string) (string, int) {
	t.Helper()
	cmd := strings.ReplaceAll(auditRulesScanCmd, "/etc/audit", filepath.Join(root, "audit"))
	out, err := exec.Command("sh", "-c", cmd).Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

// The rules.d scan reads what augenrules loads: each *.rules file at the top
// of rules.d, through a symlink too, and nothing else (not a .conf or .bak
// file, not a subdirectory). It exits 0 with no output when there is
// nothing to load, and non-zero when it cannot read what may be there.
//
// @spec auditnl-rule-set
// @ac AC-09
func TestRulesScan_ReadsWhatAugenrulesLoads(t *testing.T) {
	t.Run("auditnl-rule-set/AC-09", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("permission cases need a non-root user")
		}
		root := t.TempDir()
		audit := filepath.Join(root, "audit")
		if err := os.MkdirAll(audit, 0o755); err != nil {
			t.Fatal(err)
		}
		if out, rc := runScan(t, root); rc != 0 || out != "" {
			t.Errorf("no rules.d: rc=%d out=%q", rc, out)
		}
		d := filepath.Join(audit, "rules.d")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if out, rc := runScan(t, root); rc != 0 || out != "" {
			t.Errorf("empty rules.d: rc=%d out=%q", rc, out)
		}
		vendor := filepath.Join(root, "vendor.rules")
		write := func(p, s string) {
			if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write(vendor, "-w /etc/shadow -p wa -k vendor\n")
		if err := os.Symlink(vendor, filepath.Join(d, "30-vendor.rules")); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(d, "50-kensa.rules"), "# comment\n-a always,exit -F arch=b64 -S chown -k k\n -w/etc/passwd -pwa\n-e 2\n")
		write(filepath.Join(d, "50-kensa.rules.bak"), "-w /etc/stale -p wa -k old\n")
		write(filepath.Join(d, "audit.conf"), "-w /etc/conf -p wa -k conf\n")
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(d, "sub", "70-nested.rules"), "-w /etc/nested -p wa -k nested\n")
		out, rc := runScan(t, root)
		if rc != 0 {
			t.Fatalf("rc=%d", rc)
		}
		for _, want := range []string{"-w /etc/shadow -p wa -k vendor", "-a always,exit -F arch=b64 -S chown -k k", " -w/etc/passwd -pwa"} {
			if !strings.Contains(out, want) {
				t.Errorf("scan lacks %q:\n%s", want, out)
			}
		}
		for _, not := range []string{"/etc/stale", "/etc/conf", "/etc/nested", "-e 2", "# comment"} {
			if strings.Contains(out, not) {
				t.Errorf("scan read %q:\n%s", not, out)
			}
		}
		// An unreadable rules file refuses.
		locked := filepath.Join(d, "60-locked.rules")
		write(locked, "-w /etc/group -p wa\n")
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		if _, rc := runScan(t, root); rc == 0 || rc == 1 {
			t.Errorf("unreadable rules file: rc=%d", rc)
		}
		_ = os.Chmod(locked, 0o644)
		// A rules.d that cannot be listed or searched may hold rules: refuse.
		for _, mode := range []os.FileMode{0o100, 0o400, 0} {
			if err := os.Chmod(d, mode); err != nil {
				t.Fatal(err)
			}
			if _, rc := runScan(t, root); rc == 0 || rc == 1 {
				t.Errorf("rules.d mode %o: rc=%d", mode, rc)
			}
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
		// A parent that cannot be searched may hide rules.d: refuse.
		if err := os.Chmod(audit, 0o600); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(audit, 0o755) }()
		if _, rc := runScan(t, root); rc == 0 || rc == 1 {
			t.Errorf("unsearchable /etc/audit: rc=%d", rc)
		}
	})
}
