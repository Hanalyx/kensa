package check

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capturedPrints reads a testdata file of rule<TAB>printed-line pairs.
func capturedPrints(t *testing.T, name string) [][2]string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "auditctl", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][2]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, printed, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("%s: no tab in %q", name, line)
		}
		out = append(out, [2]string{rule, printed})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("%s: no rows", name)
	}
	return out
}

// printsAsLimit reports the two captured cases the listing cannot match,
// both recorded in the spec (C-06): a never path rule prints as the always
// watch, and, when auditctl loaded it, an explicit syscall list prints
// widened to the perm class. Loaded through netlink, an explicit list prints
// as written and matches.
func printsAsLimit(rule string, viaAuditctl bool) bool {
	if strings.Contains(rule, "never,") {
		return true
	}
	if !viaAuditctl {
		return false
	}
	f := strings.Fields(rule)
	for i, x := range f {
		if x == "-S" && i+1 < len(f) && f[i+1] != "all" {
			return true
		}
	}
	return false
}

// Every path= and dir= rule captured on a real host matches the line
// auditctl -l printed for it: the expanded perm-class list for an arch rule,
// the -w form for a rule without arch, and -S all for a rule loaded through
// netlink, on both captured audit versions.
//
// @spec check-audit-rule-match
// @ac AC-09
func TestAuditPermClass_CapturedPrintsMatch(t *testing.T) {
	t.Run("check-audit-rule-match/AC-09", func(t *testing.T) {
		for _, name := range []string{"audit-4.0.3-auditctl.tsv", "audit-3.1.5-auditctl.tsv", "audit-4.0.3-netlink.tsv",
			"audit-3.1.5-netlink.tsv"} {
			for _, row := range capturedPrints(t, name) {
				rule, printed := row[0], row[1]
				want := !printsAsLimit(rule, !strings.HasSuffix(name, "-netlink.tsv"))
				if got := AuditLineLoaded(rule, []string{printed}); got != want {
					t.Errorf("%s: AuditLineLoaded(%q, printed)=%v want %v\n printed: %s", name, rule, got, want, printed)
				}
				if got := AuditActionLoaded(rule, []string{printed}) != ""; got != want {
					t.Errorf("%s: AuditActionLoaded(%q, printed)=%v want %v", name, rule, got, want)
				}
				// The rollback verdict (interim union) counts it as loaded too.
				if want && !AuditLineMaybeLoaded(rule, []string{printed}) {
					t.Errorf("%s: AuditLineMaybeLoaded(%q, printed)=false", name, rule)
				}
			}
		}
	})
}

// The check compares against the printed listing. A loaded line missing one
// syscall of the class, a different perm, a different arch, or a different
// path does not satisfy the rule, and the failure detail names what is
// missing.
//
// @spec check-audit-rule-match
// @ac AC-10
func TestAuditPermClass_CheckRefusesNarrower(t *testing.T) {
	t.Run("check-audit-rule-match/AC-10", func(t *testing.T) {
		const rule = "-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k identity"
		var printed string
		for _, row := range capturedPrints(t, "audit-4.0.3-auditctl.tsv") {
			if row[0] == "-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k pm" {
				printed = strings.Replace(row[1], "-F key=pm", "-F key=identity", 1)
			}
		}
		if printed == "" {
			t.Fatal("fixture row not found")
		}
		if !AuditLineLoaded(rule, []string{printed}) {
			t.Fatalf("control: the captured line does not satisfy the rule")
		}
		dropped := strings.Replace(printed, ",fchownat,", ",", 1)
		cases := map[string]string{
			"one syscall missing": dropped,
			"perm w only":         strings.Replace(printed, "-F perm=wa", "-F perm=w", 1),
			"arch b32":            strings.Replace(printed, "arch=b64", "arch=b32", 1),
			"another path":        strings.Replace(printed, "path=/etc/shadow", "path=/etc/gshadow", 1),
			"never action":        strings.Replace(printed, "always,exit", "never,exit", 1),
		}
		for name, loaded := range cases {
			if AuditLineLoaded(rule, []string{loaded}) || AuditActionLoaded(rule, []string{loaded}) != "" {
				t.Errorf("%s: matched %q", name, loaded)
			}
		}
		passed, detail := auditCheck(t, rule, dropped)
		if passed {
			t.Fatalf("one syscall missing: passed")
		}
		if !strings.Contains(detail, "lacks syscalls fchownat") {
			t.Errorf("detail does not name the missing syscall: %s", detail)
		}
	})
}

// The guard compares against rules.d text as written: no -S, or -S all.
// Two hand-written path rules with the same arch and path but different perm
// values are never duplicates, whether the other is written plainly, with
// -S all, or with the expanded list pasted from a listing; the same perm is.
//
// @spec check-audit-rule-match
// @ac AC-11
func TestAuditPermClass_GuardKeepsPermsApart(t *testing.T) {
	t.Run("check-audit-rule-match/AC-11", func(t *testing.T) {
		perms := []string{"r", "w", "x", "a", "wa", "rwa", "rwxa"}
		for _, arch := range []string{"b32", "b64"} {
			for _, p := range perms {
				rule := "-a always,exit -F arch=" + arch + " -F path=/etc/shadow -F perm=" + p + " -k new"
				for _, q := range perms {
					forms := []string{
						"-a always,exit -F arch=" + arch + " -F path=/etc/shadow -F perm=" + q + " -k old",
						"-a always,exit -F arch=" + arch + " -S all -F path=/etc/shadow -F perm=" + q + " -k old",
						"-a always,exit -F arch=" + arch + " -S " + strings.Join(auditPermClass[arch][q][0], ",") +
							" -F path=/etc/shadow -F perm=" + q + " -k old",
					}
					for _, onDisk := range forms {
						dup := AuditActionLoaded(rule, []string{onDisk}) != ""
						if dup != (p == q) {
							t.Errorf("guard: rule perm=%s against %q: duplicate=%v want %v", p, onDisk, dup, p == q)
						}
					}
				}
			}
		}
	})
}

// A dir= rule without arch is the -w watch auditctl -l prints for it, with or
// without a trailing slash on either side.
//
// @spec check-audit-rule-match
// @ac AC-07
func TestAuditPermClass_DirFoldsIntoWatch(t *testing.T) {
	t.Run("check-audit-rule-match/AC-07", func(t *testing.T) {
		for _, c := range [][2]string{
			{"-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k d", "-w /etc/sudoers.d -p wa -k d"},
			{"-a always,exit -F dir=/etc/sudoers.d/ -F perm=wa -k d", "-w /etc/sudoers.d/ -p wa -k d"},
			{"-w /etc/sudoers.d -p wa -k d", "-w /etc/sudoers.d/ -p wa -k d"},
		} {
			if !AuditLineLoaded(c[0], []string{c[1]}) {
				t.Errorf("%q does not match %q", c[0], c[1])
			}
		}
		if AuditLineLoaded("-a always,exit -F dir=/etc/sudoers.d -F perm=wa -F auid>=1000 -k d",
			[]string{"-w /etc/sudoers.d -p wa -k d"}) {
			t.Error("a dir rule with another filter matched a plain watch")
		}
	})
}

// The guard against the kernel's own duplicate test: for each pair the kernel
// refused as "Rule exists" (one kernel rule), the guard calls the second a
// duplicate of the first, so it never lets augenrules hit that refusal at
// boot. The four name and alias pairs are the C-06 limit (values compared as
// written), where the guard still misses the duplicate.
//
// @spec check-audit-rule-match
// @ac AC-12
func TestAuditPermClass_GuardAgreesWithKernelDuplicates(t *testing.T) {
	t.Run("check-audit-rule-match/AC-12", func(t *testing.T) {
		nameLimit := map[string]bool{"exit-name-vs-number": true, "auid-name-vs-number": true,
			"euid-name-vs-number-samekey": true, "arch-alias-samekey": true}
		f, err := os.ReadFile(filepath.Join("testdata", "auditctl", "audit-4.0.3-pairs.tsv"))
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, line := range strings.Split(strings.TrimRight(string(f), "\n"), "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			c := strings.Split(line, "\t")
			if len(c) != 5 || c[4] != "Rule exists" {
				continue
			}
			seen++
			dup := AuditActionLoaded(c[2], []string{c[1]}) != ""
			if dup == nameLimit[c[0]] {
				t.Errorf("%s: kernel says one rule; guard duplicate=%v (name limit %v)", c[0], dup, nameLimit[c[0]])
			}
		}
		if seen < 10 {
			t.Fatalf("only %d Rule-exists pairs in the fixture", seen)
		}
	})
}

// A rule that says -S all is matched exactly: the kernel's perm classes hold
// syscalls auditctl's list lacks, so the expanded line audits less. A rule
// with an arch filter other than equality never takes the perm-class path.
//
// @spec check-audit-rule-match
// @ac AC-10
func TestAuditPermClass_ExplicitAllAndArchOperator(t *testing.T) {
	t.Run("check-audit-rule-match/AC-10", func(t *testing.T) {
		list := strings.Join(auditPermClass["b32"]["wa"][0], ",")
		expanded := "-a always,exit -F arch=b32 -S " + list + " -F path=/etc/hosts -F perm=wa -F key=system-locale"
		if AuditLineLoaded("-a always,exit -F arch=b32 -S all -F path=/etc/hosts -F perm=wa -F key=system-locale",
			[]string{expanded}) {
			t.Error("an explicit -S all rule matched the expanded list")
		}
		if !AuditLineLoaded("-a always,exit -F arch=b32 -F path=/etc/hosts -F perm=wa -F key=system-locale",
			[]string{expanded}) {
			t.Error("control: the rule with no -S did not match its expanded list")
		}
		b64 := strings.Join(auditPermClass["b64"]["wa"][0], ",")
		if AuditLineLoaded("-a always,exit -F arch!=b64 -F path=/etc/shadow -F perm=wa -k x",
			[]string{"-a always,exit -F arch!=b64 -S " + b64 + " -F path=/etc/shadow -F perm=wa -F key=x"}) {
			t.Error("an arch!= rule took the perm-class path")
		}
	})
}
