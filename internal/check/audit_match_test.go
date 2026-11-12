package check

import (
	"context"
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
			{"watch perms in another order",
				"-w /etc/passwd -p aw -k identity",
				"-w /etc/passwd -p wa -k identity"},
		}
		for _, c := range cases {
			if got, detail := auditCheck(t, c.rule, c.loaded); !got {
				t.Errorf("%s: an equivalent loaded rule failed (detail: %s)", c.name, detail)
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

// TestAuditMatch_CheckAndGuardAgree requires the check and the
// audit_rule_set duplicate guard to give one answer for a single-line rule
// without key_required. The guard reads rules.d source lines, so each
// fixture is tried both as auditctl -l prints it and as a rules file
// writes it.
//
// @spec check-audit-rule-match
// @ac AC-05
func TestAuditMatch_CheckAndGuardAgree(t *testing.T) {
	t.Run("check-audit-rule-match/AC-05", func(t *testing.T) {
		cases := []struct {
			rule, printed, source string
		}{
			{"-a always,exit -F arch=b64 -S execve -k expected",
				"-a never,exit -F arch=b64 -S execve -F key=other",
				"-a never,exit -F arch=b64 -S execve -k other"},
			{"-a always,exit -F arch=b64 -S execve -k exec",
				"-a always,exit -F arch=b64 -S execve -F success=0 -F key=exec",
				"-a always,exit -F arch=b64 -S execve -F success=0 -k exec"},
			{"-a always,exit -F arch=b64 -S execve -k other",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv"},
			{"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -k other",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation",
				"-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation"},
			{"-w /etc/passwd -p wa -k identity",
				"-w /etc/passwd -p wa -k audit_rules_usergroup_modification",
				"-w /etc/passwd -p wa -k audit_rules_usergroup_modification"},
		}
		for _, c := range cases {
			passed, detail := auditCheck(t, c.rule, c.printed)
			for _, loaded := range []string{c.printed, c.source} {
				guard := AuditActionLoaded(c.rule, []string{loaded}) != ""
				if passed != guard {
					t.Errorf("rule %q against %q: check passed=%v but the guard says action present=%v (check detail: %s)",
						c.rule, loaded, passed, guard, detail)
				}
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

// TestAuditMatch_WatchAndPathRule covers the watch form against the -a path
// form. An always,exit path or dir rule with no arch, no syscalls and only a
// perm filter is the kernel rule -w loads, so the two are one rule. A path
// rule with an arch covers one ABI only and is not the watch.
//
// @spec check-audit-rule-match
// @ac AC-07
func TestAuditMatch_WatchAndPathRule(t *testing.T) {
	t.Run("check-audit-rule-match/AC-07", func(t *testing.T) {
		cases := []struct {
			name, rule, loaded string
			want               bool
		}{
			{"path rule with no arch is the watch",
				"-a always,exit -F path=/etc/passwd -F perm=wa -k identity",
				"-w /etc/passwd -p wa -k identity", true},
			{"watch against a path rule with no arch",
				"-w /etc/passwd -p wa -k identity",
				"-a always,exit -S all -F path=/etc/passwd -F perm=wa -F key=identity", true},
			{"watch against a b64 path rule fails",
				"-w /etc/passwd -p wa -k identity",
				"-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -F key=identity", false},
			{"b64 path rule against a watch fails",
				"-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity",
				"-w /etc/passwd -p wa -k identity", false},
			{"path rule with an auid filter is not the watch",
				"-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv",
				"-w /usr/bin/sudo -p x -k priv", false},
			{"watch on RHEL 9 still passes against its listing",
				"-w /etc/shadow -p wa -k identity",
				"-w /etc/shadow -p wa -k identity", true},
		}
		for _, c := range cases {
			if got, detail := auditCheck(t, c.rule, c.loaded); got != c.want {
				t.Errorf("%s: passed=%v want %v (detail: %s)", c.name, got, c.want, detail)
			}
		}
	})
}

// TestAuditMatch_SupersetIsNotEqual records a known limit: the match is
// equality, so a loaded rule that audits strictly more than the required
// one does not satisfy it.
//
// @spec check-audit-rule-match
// @ac AC-08
func TestAuditMatch_SupersetIsNotEqual(t *testing.T) {
	t.Run("check-audit-rule-match/AC-08", func(t *testing.T) {
		rule := "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv"
		if got, detail := auditCheck(t, rule, "-a always,exit -F arch=b64 -S execve -F key=exec"); got {
			t.Errorf("a broader loaded rule passed; the match is equality (detail: %s)", detail)
		}
	})
}
