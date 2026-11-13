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

// isNeverRule reports the captured limit the listing cannot match: a never
// path rule prints as the always watch, so its action is lost (C-11).
func isNeverRule(rule string) bool { return strings.Contains(rule, "never,") }

// explicitWithPerm reports an explicit syscall list with a perm filter, which
// auditctl loads joined with the class list.
func explicitWithPerm(rule string) bool {
	return strings.Contains(rule, " -S ") && !strings.Contains(rule, " -S all") && strings.Contains(rule, "-F perm=")
}

// archClassRule reports a rule auditctl loads with a perm class list: an
// equality arch, a path or dir field, a perm and no -S.
func archClassRule(rule string) bool {
	return strings.Contains(rule, "-F arch=") && strings.Contains(rule, "-F perm=") &&
		!strings.Contains(rule, " -S ") && (strings.Contains(rule, "path=") || strings.Contains(rule, "dir="))
}

// Every path= and dir= rule captured on a real host compares with the line
// auditctl -l printed for it. Loaded by auditctl, the listed line is the rule
// auditctl built (AuditLoadedIdentity never says Distinct), and it covers the
// rule or, for an arch-less watch, cannot show it (never NotCovered).
// Loaded through netlink, as the agent loads it, a rule with no -S lists as
// -S all: for an arch rule that is a different kernel rule from the class
// list auditctl builds (pair 20), and it still covers the rule.
//
// @spec check-audit-rule-match
// @ac AC-09
func TestAuditPermClass_CapturedPrintsMatch(t *testing.T) {
	t.Run("check-audit-rule-match/AC-09", func(t *testing.T) {
		target := testAuditTarget()
		for _, name := range []string{"audit-4.0.3-auditctl.tsv", "audit-3.1.5-auditctl.tsv", "audit-4.0.3-netlink.tsv",
			"audit-3.1.5-netlink.tsv"} {
			netlink := strings.HasSuffix(name, "-netlink.tsv")
			for _, row := range capturedPrints(t, name) {
				rule, printed := row[0], row[1]
				if isNeverRule(rule) {
					continue
				}
				id, why := AuditLoadedIdentity(rule, printed, target)
				switch {
				case netlink && (archClassRule(rule) || explicitWithPerm(rule)):
					// auditctl builds these with the class list; netlink loads
					// them as written, a different kernel rule.
					if id != AuditDistinct {
						t.Errorf("%s: %q listed as %q: identity %v, want distinct (auditctl and netlink build different rules)",
							name, rule, printed, id)
					}
				case id == AuditDistinct:
					t.Errorf("%s: %q listed as %q: identity distinct (%s)", name, rule, printed, why)
				}
				c, cwhy := auditRuleCovers(parseAuditK(rule, auditSource), parseAuditK(printed, auditLoaded), target)
				if c == AuditNotCovered {
					t.Errorf("%s: %q not covered by its own listing %q (%s)", name, rule, printed, cwhy)
				}
				if c == AuditCoverAmbiguous && !strings.HasPrefix(printed, "-w ") {
					t.Errorf("%s: %q ambiguous against an explicit listing %q (%s)", name, rule, printed, cwhy)
				}
			}
		}
	})
}

// covers reports whether the listed line covers the requirement on the
// test target.
func covers(req, listed string) AuditCoverage {
	c, _ := auditRuleCovers(parseAuditK(req, auditSource), parseAuditK(listed, auditLoaded), testAuditTarget())
	return c
}

// The check compares against the printed listing. A loaded line missing one
// syscall of the class, a different perm, a different arch, or a different
// path does not cover the rule, and the failure detail names what is
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
		if covers(rule, printed) != AuditCovered {
			t.Fatalf("control: the captured line does not cover the rule")
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
			if c := covers(rule, loaded); c != AuditNotCovered {
				t.Errorf("%s: coverage %v for %q", name, c, loaded)
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

// The guard compares rules.d lines as auditctl will load them. A path rule
// with no -S loads as the class list for its arch and perm, and so does the
// same rule with that list pasted in (an explicit list with a perm filter
// loads as the list joined with the class list). Rules with different perm
// values are never duplicates, and -S all is a different kernel rule from
// the class list (captured pair 20).
//
// @spec check-audit-rule-match
// @ac AC-11
func TestAuditPermClass_GuardKeepsPermsApart(t *testing.T) {
	t.Run("check-audit-rule-match/AC-11", func(t *testing.T) {
		perms := []string{"r", "w", "x", "a", "wa", "rwa", "rwxa"}
		for _, arch := range []string{"b32", "b64"} {
			for _, p := range perms {
				rule := "-a always,exit -F arch=" + arch + " -F path=/etc/shadow -F perm=" + p + " -k k"
				for _, q := range perms {
					forms := map[string]bool{
						"-a always,exit -F arch=" + arch + " -F path=/etc/shadow -F perm=" + q + " -k k":        p == q,
						"-a always,exit -F arch=" + arch + " -S all -F path=/etc/shadow -F perm=" + q + " -k k": false,
						"-a always,exit -F arch=" + arch + " -S " + strings.Join(auditPermClass[arch][q][0], ",") +
							" -F path=/etc/shadow -F perm=" + q + " -k k": p == q,
					}
					for onDisk, want := range forms {
						if dup := guardRefuses(rule, onDisk); dup != want {
							t.Errorf("guard: rule perm=%s against %q: refuse=%v want %v", p, onDisk, dup, want)
						}
					}
				}
			}
		}
	})
}

// An arch-less dir= or path= rule, or a -w, lists as -w, which cannot show
// whether the kernel rule has a path or a dir field. Coverage is then
// ambiguous, unless the listing shows the field: a trailing slash only a
// dir= rule keeps, or the netlink rendering that names the field.
//
// @spec check-audit-rule-match
// @ac AC-07
func TestAuditPermClass_WatchListingNeedsTheFieldType(t *testing.T) {
	t.Run("check-audit-rule-match/AC-07", func(t *testing.T) {
		netDir := "-a always,exit -S all -F dir=/etc/sudoers.d -F perm=wa -F key=d"
		netPath := "-a always,exit -S all -F path=/etc/sudoers.d -F perm=wa -F key=d"
		cases := []struct {
			req, listed string
			want        AuditCoverage
		}{
			{"-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k d", "-w /etc/sudoers.d -p wa -k d", AuditCoverAmbiguous},
			{"-w /etc/sudoers.d -p wa -k d", "-w /etc/sudoers.d -p wa -k d", AuditCoverAmbiguous},
			{"-w /etc/passwd -p wa -k d", "-w /etc/passwd -p wa -k d", AuditCoverAmbiguous},
			{"-a always,exit -F dir=/etc/sudoers.d/ -F perm=wa -k d", "-w /etc/sudoers.d/ -p wa -k d", AuditCovered},
			{"-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k d", "-w /etc/sudoers.d/ -p wa -k d", AuditCoverAmbiguous},
			{"-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k d", netDir, AuditCovered},
			{"-w /etc/sudoers.d -p wa -k d", netDir, AuditCovered},
			{"-a always,exit -F path=/etc/sudoers.d -F perm=wa -k d", netDir, AuditNotCovered},
			{"-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k d", netPath, AuditNotCovered},
			{"-a always,exit -F path=/etc/sudoers.d -F perm=wa -k d", netPath, AuditCovered},
			{"-a always,exit -F dir=/etc/sudoers.d -F perm=wa -F auid>=1000 -k d", netDir, AuditNotCovered},
		}
		for _, c := range cases {
			if got := covers(c.req, c.listed); got != c.want {
				t.Errorf("%q against %q: %v want %v", c.req, c.listed, got, c.want)
			}
		}
	})
}

// The guard against the kernel's own duplicate test, on every captured pair
// (two fixtures, both audit versions): a pair the kernel loads once ("Rule
// exists") is never Distinct, and a pair it loads twice is Distinct, apart
// from the named over-refusals, which refuse a rule the kernel would accept.
// A pair whose rule the kernel or auditctl refuses outright is never
// Distinct.
//
// @spec check-audit-rule-match
// @ac AC-12
func TestAuditPermClass_GuardAgreesWithKernelDuplicates(t *testing.T) {
	t.Run("check-audit-rule-match/AC-12", func(t *testing.T) {
		target := testAuditTarget()
		target.Paths["/etc/localtime"] = AuditPathSymlink
		target.Paths["/etc/kensa-missing"] = AuditPathMissing
		// Over-refusals: the kernel loads both, the guard cannot show they differ.
		overRefuse := map[string]AuditIdentity{
			"field-order-samekey":  AuditSame,       // the kernel compares fields in order; we compare sets
			"leading-zero-samekey": AuditUnresolved, // auditctl reads 01000 as octal; non-canonical numbers stay unresolved
		}
		// One kernel rule that the guard reaches only as Unresolved.
		unresolvedOne := map[string]bool{"symlink-watch-vs-pathrule-samekey": true}
		type row struct{ name, a, b, aExit, bExit, bErr string }
		var rows []row
		for _, f := range []string{"audit-4.0.3-pairs.tsv", "audit-pairs-2.tsv"} {
			b, err := os.ReadFile(filepath.Join("testdata", "auditctl", f))
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
				if strings.HasPrefix(line, "#") {
					continue
				}
				c := strings.Split(line, "\t")
				switch len(c) {
				case 5:
					rows = append(rows, row{c[0], c[1], c[2], "0", c[3], c[4]})
				case 6:
					rows = append(rows, row{c[0], c[1], c[2], c[3], c[4], c[5]})
				default:
					t.Fatalf("%s: bad row %q", f, line)
				}
			}
		}
		var one, two int
		for _, r := range rows {
			id, why := AuditRuleIdentity(r.b, r.a, target)
			switch {
			case r.aExit != "0" || (r.bExit != "0" && r.bErr != "Rule exists"):
				if id == AuditDistinct {
					t.Errorf("%s: a rule the host refuses outright compared distinct (%s)", r.name, why)
				}
			case r.bErr == "Rule exists":
				one++
				want := AuditSame
				if unresolvedOne[r.name] {
					want = AuditUnresolved
				}
				if id != want {
					t.Errorf("%s: kernel says one rule; identity %v want %v (%s)", r.name, id, want, why)
				}
			default:
				two++
				want, ok := overRefuse[r.name]
				if !ok {
					want = AuditDistinct
				}
				if id != want {
					t.Errorf("%s: kernel loads both; identity %v want %v (%s)", r.name, id, want, why)
				}
			}
		}
		if one < 15 || two < 15 {
			t.Fatalf("too few rows: %d one-rule, %d two-rule", one, two)
		}
	})
}

// A rule that says -S all needs a loaded rule over every syscall: the
// kernel's perm classes hold syscalls auditctl's list lacks, so the expanded
// line covers less. A rule with an arch filter other than equality never
// takes the perm-class path, so its loaded list is not known.
//
// @spec check-audit-rule-match
// @ac AC-10
func TestAuditPermClass_ExplicitAllAndArchOperator(t *testing.T) {
	t.Run("check-audit-rule-match/AC-10", func(t *testing.T) {
		list := strings.Join(auditPermClass["b32"]["wa"][0], ",")
		expanded := "-a always,exit -F arch=b32 -S " + list + " -F path=/etc/hosts -F perm=wa -F key=system-locale"
		if c := covers("-a always,exit -F arch=b32 -S all -F path=/etc/hosts -F perm=wa -F key=system-locale", expanded); c != AuditNotCovered {
			t.Errorf("an explicit -S all rule: %v against the expanded list", c)
		}
		if c := covers("-a always,exit -F arch=b32 -F path=/etc/hosts -F perm=wa -F key=system-locale", expanded); c != AuditCovered {
			t.Errorf("control: the rule with no -S: %v against its expanded list", c)
		}
		b64 := strings.Join(auditPermClass["b64"]["wa"][0], ",")
		if c := covers("-a always,exit -F arch!=b64 -F path=/etc/shadow -F perm=wa -k x",
			"-a always,exit -F arch!=b64 -S "+b64+" -F path=/etc/shadow -F perm=wa -F key=x"); c == AuditCovered {
			t.Error("an arch!= rule took the perm-class path")
		}
	})
}
