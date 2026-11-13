package check

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// The loaded lines in these tests are written the way auditctl -l prints a
// rule: -a action,list first, arch before -S, the key last as -F key=, auid
// unset as auid!=-1, and a -C comparison in the order libaudit's table
// names it (uid!=euid, not euid!=uid). The execpriv and identity lines are
// copied from the auditctl -l output quoted in the vendored STIG check text
// under catalog/sources/stig/.

// auditCheck runs audit_rule_exists for rule against a host whose
// auditctl -l prints loaded.
func auditCheck(t *testing.T, rule, loaded string) (bool, string) {
	t.Helper()
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, loaded)}}
	passed, detail, err := runForTest(context.Background(), ft,
		api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": rule}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return passed, detail
}

// TestAuditMatch_ActionAndList covers the -a action and list. A never rule
// suppresses the records an always rule produces, so it can never satisfy
// one, under the rule's own key or another.
//
// @spec check-audit-rule-match
// @ac AC-01
func TestAuditMatch_ActionAndList(t *testing.T) {
	t.Run("check-audit-rule-match/AC-01", func(t *testing.T) {
		cases := []struct {
			name, rule, loaded string
			want               bool
		}{
			{"never under another key fails",
				"-a always,exit -F arch=b64 -S execve -k expected",
				"-a never,exit -F arch=b64 -S execve -F key=other", false},
			{"never under the same key fails",
				"-a always,exit -F arch=b64 -S execve -k expected",
				"-a never,exit -F arch=b64 -S execve -F key=expected", false},
			{"never on a path rule fails",
				"-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-su",
				"-a never,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-su", false},
			{"always under the same key passes",
				"-a always,exit -F arch=b64 -S execve -k expected",
				"-a always,exit -F arch=b64 -S execve -F key=expected", true},
		}
		for _, c := range cases {
			if got, detail := auditCheck(t, c.rule, c.loaded); got != c.want {
				t.Errorf("%s: passed=%v want %v (detail: %s)", c.name, got, c.want, detail)
			}
		}
	})
}

// TestAuditMatch_FiltersTwoWay covers the filters on the key-strict path.
// The exact-key match used to pass before any filter compare ran, so a loaded
// rule narrowed by success=0 satisfied the unrestricted rule.
//
// @spec check-audit-rule-match
// @ac AC-02
func TestAuditMatch_FiltersTwoWay(t *testing.T) {
	t.Run("check-audit-rule-match/AC-02", func(t *testing.T) {
		cases := []struct {
			name, rule, loaded string
			want               bool
		}{
			{"loaded narrowed by success=0 under the same key fails",
				"-a always,exit -F arch=b64 -S execve -k exec",
				"-a always,exit -F arch=b64 -S execve -F success=0 -F key=exec", false},
			{"loaded narrowed by -C and euid under the same key fails",
				"-a always,exit -F arch=b64 -S execve -k execpriv",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv", false},
			{"loaded missing the rule's -C and euid under the same key fails",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
				"-a always,exit -F arch=b64 -S execve -F key=execpriv", false},
			{"same filters under the same key passes",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv", true},
		}
		for _, c := range cases {
			if got, detail := auditCheck(t, c.rule, c.loaded); got != c.want {
				t.Errorf("%s: passed=%v want %v (detail: %s)", c.name, got, c.want, detail)
			}
		}
	})
}

// TestAuditMatch_EquivalentForms covers forms that load into the same kernel
// rule. libaudit parses euid!=uid and uid!=euid into one comparison, and
// auid!=unset, auid!=-1 and auid!=4294967295 into one value; auditctl
// accepts the action and list in either order, and -A only changes where
// the rule is inserted.
//
// @spec check-audit-rule-match
// @ac AC-03
func TestAuditMatch_EquivalentForms(t *testing.T) {
	t.Run("check-audit-rule-match/AC-03", func(t *testing.T) {
		cases := []struct {
			name, rule, loaded string
		}{
			{"reversed comparison under another key",
				"-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=sudo_log"},
			{"reversed comparison under the same key",
				"-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation"},
			{"auid unset printed as unset",
				"-a always,exit -F arch=b64 -S chown,fchown -F auid>=1000 -F auid!=unset -k perm_mod",
				"-a always,exit -F arch=b64 -S chown,fchown -F auid>=1000 -F auid!=unset -F key=perm_mod"},
			{"auid unset written as 4294967295",
				"-a always,exit -F arch=b64 -S chown,fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod",
				"-a always,exit -F arch=b64 -S chown,fchown -F auid>=1000 -F auid!=-1 -F key=perm_mod"},
			{"list before action",
				"-a exit,always -F arch=b64 -S execve -k exec",
				"-a always,exit -F arch=b64 -S execve -F key=exec"},
			{"prepend form",
				"-A always,exit -F arch=b64 -S execve -k exec",
				"-a always,exit -F arch=b64 -S execve -F key=exec"},
			{"flag arguments written against the flag",
				"-a always,exit -Farch=b64 -Sexecve -kexec",
				"-a always,exit -F arch=b64 -S execve -F key=exec"},
		}
		for _, c := range cases {
			if got, detail := auditCheck(t, c.rule, c.loaded); !got {
				t.Errorf("%s: an equivalent loaded rule failed (detail: %s)", c.name, detail)
			}
		}
		// Watches, against a listing line that names the field type.
		watches := []struct {
			name, rule, loaded string
		}{
			{"watch perms in another order", "-w /etc/passwd -p aw -k identity",
				"-a always,exit -S all -F path=/etc/passwd -F perm=wa -F key=identity"},
			{"watch written with a trailing slash", "-w /etc/sudoers.d/ -p wa -k identity",
				"-a always,exit -S all -F dir=/etc/sudoers.d -F perm=wa -F key=identity"},
			{"watch perms written against the flag", "-w /etc/passwd -pwa -k identity",
				"-a always,exit -S all -F path=/etc/passwd -F perm=wa -F key=identity"},
			{"watch with no -p is rwxa", "-w /etc/passwd -k identity",
				"-a always,exit -S all -F path=/etc/passwd -F perm=rwxa -F key=identity"},
		}
		for _, c := range watches {
			if got := covers(c.rule, c.loaded); got != AuditCovered {
				t.Errorf("%s: coverage %v", c.name, got)
			}
		}
	})
}

// TestAuditMatch_DifferentFiltersStayDifferent keeps genuinely different
// filters apart after canonicalization.
//
// @spec check-audit-rule-match
// @ac AC-04
func TestAuditMatch_DifferentFiltersStayDifferent(t *testing.T) {
	t.Run("check-audit-rule-match/AC-04", func(t *testing.T) {
		cases := []struct {
			name, rule, loaded string
		}{
			{"= is not !=",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
				"-a always,exit -F arch=b64 -S execve -C uid=euid -F euid=0 -F key=other"},
			{"gid comparison is not uid comparison",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
				"-a always,exit -F arch=b64 -S execve -C gid!=egid -F euid=0 -F key=other"},
			{"egid=0 is not euid=0",
				"-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv",
				"-a always,exit -F arch=b64 -S execve -C gid!=egid -F euid=0 -F key=other"},
			{"attached arch is still compared",
				"-a always,exit -Farch=b32 -Sexecve -k exec",
				"-a always,exit -F arch=b64 -S execve -F key=exec"},
			{"auid=0 is not auid!=-1",
				"-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod",
				"-a always,exit -F arch=b64 -S setxattr -F auid!=-1 -F key=other"},
		}
		for _, c := range cases {
			if got, detail := auditCheck(t, c.rule, c.loaded); got {
				t.Errorf("%s: a different loaded rule passed (detail: %s)", c.name, detail)
			}
		}
	})
}

// TestAuditMatch_CoverageIsNotIdentity keeps the two questions apart. A
// loaded rule under another key, or over more syscalls, covers the
// requirement, and is still a different kernel rule, so the guard lets the
// requirement be written next to it. A narrower rule is neither.
//
// @spec check-audit-rule-match
// @ac AC-05
func TestAuditMatch_CoverageIsNotIdentity(t *testing.T) {
	t.Run("check-audit-rule-match/AC-05", func(t *testing.T) {
		cases := []struct {
			name, rule, listed, source string
			cover                      AuditCoverage
			guardRefuses               bool
		}{
			{"another key covers and is distinct",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=unset -k other",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation",
				"-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation",
				AuditCovered, false},
			{"a superset covers and is distinct",
				"-a always,exit -F arch=b64 -S execve -k exec",
				"-a always,exit -F arch=b64 -S execve,execveat -F key=exec",
				"-a always,exit -F arch=b64 -S execve,execveat -k exec",
				AuditCovered, false},
			{"a narrower rule does not cover; its one-sided success filter is unresolved for the guard",
				"-a always,exit -F arch=b64 -S execve -k exec",
				"-a always,exit -F arch=b64 -S execve -F success=0 -F key=exec",
				"-a always,exit -F arch=b64 -S execve -F success=0 -k exec",
				AuditNotCovered, true},
			{"a never rule neither covers nor duplicates",
				"-a always,exit -F arch=b64 -S execve -k exec",
				"-a never,exit -F arch=b64 -S execve -F key=exec",
				"-a never,exit -F arch=b64 -S execve -k exec",
				AuditNotCovered, false},
			{"the same rule and key covers and duplicates",
				"-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -k user_emulation",
				AuditCovered, true},
		}
		for _, c := range cases {
			if got := covers(c.rule, c.listed); got != c.cover {
				t.Errorf("%s: coverage %v want %v", c.name, got, c.cover)
			}
			if got := guardRefuses(c.rule, c.source); got != c.guardRefuses {
				t.Errorf("%s: guard refuses %v want %v", c.name, got, c.guardRefuses)
			}
		}
	})
}

// TestAuditMatch_LineLoadedForRollback covers AuditLineLoaded as the
// audit_rule_set shell rollback uses it: a staged rule auditd loaded at boot
// must still read as loaded in the form auditctl -l prints it, and a never
// line must not.
//
// @spec check-audit-rule-match
// @ac AC-06
func TestAuditMatch_LineLoadedForRollback(t *testing.T) {
	t.Run("check-audit-rule-match/AC-06", func(t *testing.T) {
		staged := "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
		printed := "-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation"
		if !AuditLineLoaded(staged, []string{printed}) {
			t.Error("a staged rule loaded in auditctl -l form did not read as loaded")
		}
		if !AuditLineLoaded(staged, []string{strings.Replace(printed, "auid!=-1", "auid!=unset", 1)}) {
			t.Error("a staged rule loaded with auid!=unset printed did not read as loaded")
		}
		never := strings.Replace(printed, "always,exit", "never,exit", 1)
		if AuditLineLoaded(staged, []string{never}) {
			t.Error("a never line read as the staged always rule")
		}
	})
}

// TestAuditMatch_WatchAndPathRule covers watches and arch-less path rules
// through the check. auditctl -l prints a path= and a dir= rule on the same
// path both as -w, so over that listing alone a watch requirement is
// skipped (not assessable), never passed or failed. A rule with an arch
// covers one ABI only and is not the watch, and a path rule with another
// filter lists as -a, so both are decided from the listing.
//
// @spec check-audit-rule-match
// @ac AC-07
func TestAuditMatch_WatchAndPathRule(t *testing.T) {
	t.Run("check-audit-rule-match/AC-07", func(t *testing.T) {
		const pass, fail, skip = "pass", "fail", "skip"
		cases := []struct {
			name, rule, loaded string
			want               string
		}{
			{"path rule with no arch against a -w listing",
				"-a always,exit -F path=/etc/passwd -F perm=wa -k identity",
				"-w /etc/passwd -p wa -k identity", skip},
			{"watch against a -w listing",
				"-w /etc/shadow -p wa -k identity",
				"-w /etc/shadow -p wa -k identity", skip},
			{"watch against a b64 path rule fails",
				"-w /etc/passwd -p wa -k identity",
				"-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -F key=identity", fail},
			{"b64 path rule against a watch fails",
				"-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity",
				"-w /etc/passwd -p wa -k identity", fail},
			{"path rule with an auid filter is not the watch",
				"-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv",
				"-w /usr/bin/sudo -p x -k priv", fail},
			{"a listed slash shows a dir field",
				"-a always,exit -F dir=/etc/sudoers.d/ -F perm=wa -k identity",
				"-w /etc/sudoers.d/ -p wa -k identity", pass},
			{"watch on another path fails",
				"-w /etc/gshadow -p wa -k identity",
				"-w /etc/shadow -p wa -k identity", fail},
		}
		for _, c := range cases {
			ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, c.loaded)}}
			passed, detail, err := runForTest(context.Background(), ft,
				api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": c.rule}})
			got := fail
			switch {
			case errors.Is(err, ErrNotAssessable):
				got, detail = skip, err.Error()
			case err != nil:
				t.Fatalf("%s: %v", c.name, err)
			case passed:
				got = pass
			}
			if got != c.want {
				t.Errorf("%s: %s want %s (detail: %s)", c.name, got, c.want, detail)
			}
			if got == skip && !strings.Contains(detail, "coverage is not proven") {
				t.Errorf("%s: the skip detail does not explain the watch case: %s", c.name, detail)
			}
		}
	})
}

// TestAuditMatch_SupersetIsNotEqual pins the coverage policy's two edges. A
// loaded rule with fewer filters records more, and still does not cover the
// requirement, because the policy needs the same filters. A loaded rule
// with the same filters over more syscalls covers an always requirement,
// and does not cover a never requirement, which needs the same syscalls.
//
// @spec check-audit-rule-match
// @ac AC-08
func TestAuditMatch_SupersetIsNotEqual(t *testing.T) {
	t.Run("check-audit-rule-match/AC-08", func(t *testing.T) {
		rule := "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv"
		if got, detail := auditCheck(t, rule, "-a always,exit -F arch=b64 -S execve -F key=exec"); got {
			t.Errorf("a loaded rule with fewer filters passed (detail: %s)", detail)
		}
		if got, detail := auditCheck(t, rule,
			"-a always,exit -F arch=b64 -S execve,execveat -C uid!=euid -F euid=0 -F key=execpriv"); !got {
			t.Errorf("a loaded rule with the same filters over more syscalls failed (detail: %s)", detail)
		}
		if got := covers("-a never,exit -F arch=b64 -S execve -k n", "-a never,exit -F arch=b64 -S execve,execveat -F key=n"); got != AuditNotCovered {
			t.Errorf("a never requirement was covered by a wider never rule: %v", got)
		}
	})
}
