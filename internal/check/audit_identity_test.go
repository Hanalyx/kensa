package check

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// The review's counterexamples, each against the predicate it belongs to.
// Pair 14: euid=root and euid=0 under one key are one kernel rule, so the
// guard must refuse. dir= and path= on one directory are different rules
// and record different events. Pair 20: no -S and -S all on an arch path
// rule both load. A loaded list with execveat beyond the execute class, or
// chown32 beyond the b32 attribute class, covers the requirement but is not
// its duplicate.
//
// @spec check-audit-rule-match
// @ac AC-13
func TestAuditIdentity_ReviewCounterexamples(t *testing.T) {
	t.Run("check-audit-rule-match/AC-13", func(t *testing.T) {
		target := testAuditTarget()
		id := func(a, b string) AuditIdentity {
			got, _ := AuditRuleIdentity(a, b, target)
			return got
		}
		if got := id("-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k k1",
			"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=root -k k1"); got != AuditSame {
			t.Errorf("pair 14 (euid=0 vs euid=root, one key): %v, want same", got)
		}
		if got := id("-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k s",
			"-a always,exit -F path=/etc/sudoers.d -F perm=wa -k s"); got != AuditDistinct {
			t.Errorf("dir= vs path= on one directory: %v, want distinct", got)
		}
		if got := covers("-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k s",
			"-a always,exit -S all -F path=/etc/sudoers.d -F perm=wa -F key=s"); got != AuditNotCovered {
			t.Errorf("a path= rule on a directory covered a dir= requirement: %v", got)
		}
		if got := id("-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k k1",
			"-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=wa -k k1"); got != AuditDistinct {
			t.Errorf("pair 20 (no -S vs -S all): %v, want distinct", got)
		}
		supersets := []struct{ req, listed string }{
			{"-a always,exit -F arch=b64 -F path=/usr/bin/sudo -F perm=x -k p",
				"-a always,exit -F arch=b64 -S execve,execveat -F path=/usr/bin/sudo -F perm=x -F key=p"},
			{"-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=a -k p",
				"-a always,exit -F arch=b32 -S " + strings.Join(auditPermClass["b32"]["a"][0], ",") +
					",chown32 -F path=/etc/shadow -F perm=a -F key=p"},
		}
		for _, s := range supersets {
			if got := covers(s.req, s.listed); got != AuditCovered {
				t.Errorf("superset %q: coverage %v, want covered", s.listed, got)
			}
			if got, why := AuditLoadedIdentity(s.req, s.listed, target); got != AuditDistinct {
				t.Errorf("superset %q: identity %v (%s), want distinct", s.listed, got, why)
			}
		}
	})
}

// Every part the predicate cannot resolve gives Unresolved, never Distinct:
// a symlinked watch, a path not in clean form, a name only a directory
// service knows, syscall masks off the measured machine or audit version,
// a non-canonical number, and a field other than the pass-through ones on
// one side only.
//
// @spec check-audit-rule-match
// @ac AC-14
func TestAuditIdentity_UnresolvedNeverDistinct(t *testing.T) {
	t.Run("check-audit-rule-match/AC-14", func(t *testing.T) {
		target := testAuditTarget()
		target.Paths["/etc/localtime"] = AuditPathSymlink
		aarch := testAuditTarget()
		aarch.Machine = "aarch64"
		oldVer := testAuditTarget()
		oldVer.AuditctlVersion = "2.8.5"
		cases := []struct {
			name, a, b string
			t          *AuditTarget
		}{
			{"symlinked watch vs path rule", "-w /etc/localtime -p wa -k k", "-a always,exit -F path=/etc/localtime -F perm=wa -k k", target},
			{"doubled slash", "-a always,exit -F path=/etc//shadow -F perm=wa -k k", "-a always,exit -F path=/etc/shadow -F perm=wa -k k", target},
			{"dot segment", "-a always,exit -F path=/etc/./shadow -F perm=wa -k k", "-a always,exit -F path=/etc/shadow -F perm=wa -k k", target},
			{"relative path", "-a always,exit -F path=shadow -F perm=wa -k k", "-a always,exit -F path=/etc/shadow -F perm=wa -k k", target},
			{"name not in files", "-a always,exit -F arch=b64 -S chown -F auid=ldapuser -k k", "-a always,exit -F arch=b64 -S chown -F auid=1500 -k k", target},
			{"syscall sets off the measured machine", "-a always,exit -F arch=b64 -S chown -k k", "-a always,exit -F arch=b64 -S fchown -k k", aarch},
			{"class list off the measured version", "-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k k", "-a always,exit -F arch=b64 -S open -F path=/etc/shadow -F perm=wa -k k", oldVer},
			{"non-canonical number", "-a always,exit -F arch=b64 -S chown -F auid>=01000 -k k", "-a always,exit -F arch=b64 -S chown -F auid>=1000 -k k", target},
			{"success filter on one side", "-a always,exit -F arch=b64 -S execve -k k", "-a always,exit -F arch=b64 -S execve -F success=0 -k k", target},
			{"numeric syscall", "-a always,exit -F arch=b64 -S 59 -k k", "-a always,exit -F arch=b64 -S execve -k k", target},
		}
		for _, c := range cases {
			if got, why := AuditRuleIdentity(c.a, c.b, c.t); got != AuditUnresolved {
				t.Errorf("%s: %v (%s), want unresolved", c.name, got, why)
			}
		}
	})
}

// The host facts come from one read-only probe. Names resolve through the
// files service only; the perm-class table, the arch aliases and the errno
// names are trusted only on x86_64 with a captured audit version; a probe
// that fails leaves every fact unresolved.
//
// @spec check-audit-rule-match
// @ac AC-15
func TestAuditIdentity_HostFactsAndGate(t *testing.T) {
	t.Run("check-audit-rule-match/AC-15", func(t *testing.T) {
		probe := AuditTargetProbe([]string{
			"-a always,exit -F arch=b64 -S chown -F auid=root -F egid=wheel -k k",
			"-w /etc/sudoers.d -p wa -k s",
			"-a always,exit -F arch=b64 -S chown -F auid=x;rm -k k",
		})
		for _, want := range []string{"uname -m", "auditctl -v", "getent -s files passwd 'root'",
			"getent -s files group 'wheel'", "p='/etc/sudoers.d';"} {
			if !strings.Contains(probe, want) {
				t.Errorf("probe lacks %q: %s", want, probe)
			}
		}
		if strings.Contains(probe, "x;rm") {
			t.Errorf("an unsafe name reached the probe: %s", probe)
		}
		got := ParseAuditTarget("machine\tx86_64\nauditctl\tauditctl version 4.0.3\nuid\troot\t0\n" +
			"gid\twheel\t10\npath\t/etc/sudoers.d\tdir\npath\t/x\tbogus\nuid\tbad\t01\n")
		if got.Machine != "x86_64" || got.AuditctlVersion != "4.0.3" || got.UIDs["root"] != 0 ||
			got.GIDs["wheel"] != 10 || got.Paths["/etc/sudoers.d"] != AuditPathDir {
			t.Errorf("parse: %+v", got)
		}
		if _, ok := got.Paths["/x"]; ok {
			t.Error("an unknown path kind was kept")
		}
		if _, ok := got.UIDs["bad"]; ok {
			t.Error("a non-canonical id was kept")
		}
		if !got.measured() {
			t.Error("x86_64 with audit-4.0.3 is not measured")
		}
		for _, m := range []*AuditTarget{nil, {Machine: "aarch64", AuditctlVersion: "4.0.3"}, {Machine: "x86_64", AuditctlVersion: "3.0.7"}} {
			if m.measured() {
				t.Errorf("%+v counted as measured", m)
			}
			if _, ok := auditPermClassFor(m, "b64", "wa"); ok {
				t.Errorf("%+v: the perm-class table was used outside the gate", m)
			}
		}
		// errno names resolve on x86_64 and aarch64 whatever the audit
		// version; the perm-class table only on the measured gate.
		a, b := "-a always,exit -F arch=b64 -S open -F exit=-EACCES -k k", "-a always,exit -F arch=b64 -S open -F exit=-13 -k k"
		if id, _ := AuditRuleIdentity(a, b, testAuditTarget()); id != AuditSame {
			t.Errorf("exit=-EACCES vs -13 on a measured target: %v", id)
		}
		if id, _ := AuditRuleIdentity(a, b, &AuditTarget{Machine: "aarch64", AuditctlVersion: "3.0.7"}); id != AuditSame {
			t.Errorf("exit=-EACCES vs -13 on aarch64 with an unmeasured audit version: %v", id)
		}
		if id, _ := AuditRuleIdentity(a, b, &AuditTarget{Machine: "riscv64", AuditctlVersion: "4.0.3"}); id != AuditUnresolved {
			t.Errorf("exit=-EACCES vs -13 on a machine with no errno table: %v", id)
		}
		// errno aliases are one number, so one value.
		alias := "-a always,exit -F arch=b64 -S read -F exit=-EWOULDBLOCK -k k"
		if id, why := AuditRuleIdentity(alias, strings.Replace(alias, "EWOULDBLOCK", "EAGAIN", 1), testAuditTarget()); id != AuditSame {
			t.Errorf("exit=-EWOULDBLOCK vs -EAGAIN: %v (%s), want same", id, why)
		}
		if id, _ := AuditRuleIdentity(alias, strings.Replace(alias, "EWOULDBLOCK", "EKENSAUNKNOWN", 1), testAuditTarget()); id != AuditUnresolved {
			t.Errorf("an errno name not in the table: %v, want unresolved", id)
		}
		// A probe that cannot run is an error for the check.
		ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, "-w /etc/shadow -p wa -k k")},
			noAuditProbe: true}
		if _, _, err := runForTest(context.Background(), ft,
			api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": "-w /etc/shadow -p wa -k k"}}); err == nil ||
			errors.Is(err, ErrNotAssessable) {
			t.Errorf("a failed host-facts probe: err=%v, want a plain error", err)
		}
	})
}

// A requirement the listing cannot decide is ErrAmbiguousEvidence, which is
// also ErrNotAssessable, with a detail that names the watch case and says
// coverage is not proven. An unreadable ruleset is not assessable but not
// ambiguous: nothing was read, so remediate keeps its usual behavior there.
//
// @spec check-audit-rule-match
// @ac AC-18
func TestAuditIdentity_AmbiguousListingIsSkipped(t *testing.T) {
	t.Run("check-audit-rule-match/AC-18", func(t *testing.T) {
		const rule = "-w /etc/shadow -p wa -k identity"
		chk := api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": rule}}
		ssh := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, rule)}}
		_, err := Run(context.Background(), ssh, chk)
		if !errors.Is(err, ErrAmbiguousEvidence) || !errors.Is(err, ErrNotAssessable) {
			t.Fatalf("over the listing: %v", err)
		}
		for _, want := range []string{"replaced by rename", "coverage is not proven"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("detail lacks %q: %v", want, err)
			}
		}
		if strings.Contains(err.Error(), "agent") {
			t.Errorf("detail claims an agent path that does not exist: %v", err)
		}
		missing := &fakeTransport{cmdResult: map[string]api.CommandResult{
			"auditctl -l": {ExitCode: 127, Stderr: "sh: auditctl: command not found"}}}
		_, err = Run(context.Background(), missing, chk)
		if !errors.Is(err, ErrNotAssessable) || errors.Is(err, ErrAmbiguousEvidence) {
			t.Errorf("unreadable ruleset: %v, want not assessable and not ambiguous", err)
		}
		// A requirement with no candidate at all fails, not ambiguous.
		res, err := Run(context.Background(), &fakeTransport{cmdResult: map[string]api.CommandResult{
			"auditctl -l": result(0, "-w /etc/gshadow -p wa -k identity")}}, chk)
		if err != nil || res.Passed {
			t.Errorf("no candidate: passed=%v err=%v, want a fail", res.Passed, err)
		}
	})
}

// The captured pairs fixture parses; guards the reader the kernel-pair test
// uses against a silently empty file.
func TestAuditIdentity_PairsFixtureShape(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "auditctl", "audit-pairs-2.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := sc.Text(); l != "" && !strings.HasPrefix(l, "#") {
			if len(strings.Split(l, "\t")) != 6 {
				t.Errorf("row with %d fields: %q", len(strings.Split(l, "\t")), l)
			}
			n++
		}
	}
	if n != 19 {
		t.Errorf("%d rows, want 19", n)
	}
}

// Off the measured audit versions, syscall masks compare as numbers from
// ausyscall on the host, so corpus siblings that differ only in -S stay
// distinct on any version. A name ausyscall cannot resolve keeps the
// rule unresolved. b64 and b32 are different arches on any machine, and
// what b64 names is a fact of the machine, not the audit version.
//
// @spec check-audit-rule-match
// @ac AC-19
func TestAuditIdentity_SyscallNumbersFromHost(t *testing.T) {
	t.Run("check-audit-rule-match/AC-19", func(t *testing.T) {
		chmod := "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"
		chown := "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod"
		probe := AuditTargetProbe([]string{chmod, chown, "-a always,exit -F arch=b32 -S chmod -k k",
			"-a always,exit -S chown -k k", "-a always,exit -F arch=b64 -S 'x;y' -k k"})
		for _, want := range []string{`sc 'b64' "$a64" 'chmod';`, `sc 'b64' "$a64" 'lchown';`, `sc 'b32' "$a32" 'chmod';`,
			`sc '' "$a64" 'chown';`, `ausyscall "$2" "$3" --exact`} {
			if !strings.Contains(probe, want) {
				t.Errorf("probe lacks %q", want)
			}
		}
		if strings.Contains(probe, "x;y") {
			t.Error("an unsafe syscall name reached the probe")
		}
		out := "machine\tx86_64\nauditctl\tauditctl version 3.1.2\n" +
			"sc\tb64\tchmod\t90\nsc\tb64\tfchmod\t91\nsc\tb64\tfchmodat\t268\n" +
			"sc\tb64\tchown\t92\nsc\tb64\tfchown\t93\nsc\tb64\tfchownat\t260\nsc\tb64\tlchown\t94\n" +
			"sc\tb64\tbad\tx1\n"
		tg := ParseAuditTarget(out)
		if tg.measured() {
			t.Fatal("3.1.2 counted as measured")
		}
		if tg.Syscalls["b64"]["lchown"] != 94 {
			t.Errorf("parse: %+v", tg.Syscalls)
		}
		if _, ok := tg.Syscalls["b64"]["bad"]; ok {
			t.Error("a non-numeric answer was kept")
		}
		if id, why := AuditRuleIdentity(chmod, chown, tg); id != AuditDistinct {
			t.Errorf("siblings off the gate with numbers: %v (%s)", id, why)
		}
		if id, _ := AuditRuleIdentity(chmod, strings.Replace(chmod, "-S chmod,fchmod,fchmodat", "-S fchmodat,chmod,fchmod", 1), tg); id != AuditSame {
			t.Errorf("one mask in another order: %v", id)
		}
		delete(tg.Syscalls["b64"], "lchown")
		if id, _ := AuditRuleIdentity(chmod, chown, tg); id != AuditUnresolved {
			t.Errorf("a name ausyscall did not resolve: %v", id)
		}
		if id, _ := AuditRuleIdentity(strings.Replace(chmod, "b64", "b32", 1), chmod,
			&AuditTarget{Machine: "riscv64", AuditctlVersion: "9.9"}); id != AuditDistinct {
			t.Errorf("b32 vs b64 on an unknown machine: %v", id)
		}
		if id, _ := AuditRuleIdentity(chmod, strings.Replace(chmod, "b64", "x86_64", 1),
			&AuditTarget{Machine: "x86_64", AuditctlVersion: "3.0.7"}); id != AuditSame {
			t.Errorf("b64 vs x86_64 on x86_64 with an unmeasured version: %v", id)
		}
		if id, _ := AuditRuleIdentity(chmod, strings.Replace(chmod, "b64", "x86_64", 1),
			&AuditTarget{Machine: "riscv64", AuditctlVersion: "4.0.3"}); id != AuditUnresolved {
			t.Errorf("b64 vs x86_64 on another machine: %v", id)
		}
		alias := "-a always,exit -F arch=b64 -S read -F exit=-EDEADLOCK -k k"
		if id, _ := AuditRuleIdentity(alias, strings.Replace(alias, "EDEADLOCK", "EDEADLK", 1),
			&AuditTarget{Machine: "aarch64", AuditctlVersion: "3.0.7"}); id != AuditSame {
			t.Errorf("errno alias EDEADLOCK vs EDEADLK: %v, want same", id)
		}
	})
}

// Spellings libaudit builds into the same audit_rule_data are one kernel
// rule: field, syscall, action, list and comparison names without regard to
// case, loginuid as auid, and numbers stored in a u32. Each pair was built
// byte-identical by libaudit 3.1.2 in memory. Values that are not names, such
// as a path or a key, keep their case.
//
// @spec check-audit-rule-match
// @ac AC-20
func TestAuditIdentity_LibauditSpellings(t *testing.T) {
	t.Run("check-audit-rule-match/AC-20", func(t *testing.T) {
		base := "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=unset -k k"
		same := []string{
			"-a always,exit -F arch=b64 -S chown -F loginuid>=1000 -F loginuid!=unset -k k",
			"-a always,exit -F arch=b64 -S chown -F AUID>=1000 -F auid!=unset -k k",
			"-a always,exit -F arch=b64 -S CHOWN -F auid>=1000 -F auid!=unset -k k",
			"-a ALWAYS,EXIT -F arch=B64 -S chown -F auid>=1000 -F auid!=unset -k k",
			"-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k k",
		}
		for _, s := range same {
			if id, why := AuditRuleIdentity(base, s, testAuditTarget()); id != AuditSame {
				t.Errorf("%q: %v (%s), want same", s, id, why)
			}
		}
		pairs := [][2]string{
			{"-a always,exit -F arch=b64 -S execve -C EUID!=UID -k k", "-a always,exit -F arch=b64 -S execve -C uid!=euid -k k"},
			{"-a always,exit -F arch=b64 -S execve -C loginuid!=uid -k k", "-a always,exit -F arch=b64 -S execve -C auid!=uid -k k"},
			{"-a always,exit -F arch=b64 -S open -F exit=-13 -k k", "-a always,exit -F arch=b64 -S open -F exit=4294967283 -k k"},
			{"-a always,exit -F arch=b64 -S open -F exit=-eacces -k k", "-a always,exit -F arch=b64 -S open -F exit=-13 -k k"},
			{"-a always,exit -F arch=b64 -S chown -F uid=-2 -k k", "-a always,exit -F arch=b64 -S chown -F uid=4294967294 -k k"},
			{"-a always,exit -F arch=b64 -S chown -F uid=4294967296 -k k", "-a always,exit -F arch=b64 -S chown -F uid=0 -k k"},
			{"-a always,exit -F arch=b64 -S chown -F a0=-1 -k k", "-a always,exit -F arch=b64 -S chown -F a0=4294967295 -k k"},
		}
		for _, p := range pairs {
			if id, why := AuditRuleIdentity(p[0], p[1], testAuditTarget()); id != AuditSame {
				t.Errorf("%q vs %q: %v (%s), want same", p[0], p[1], id, why)
			}
		}
		if id, _ := AuditRuleIdentity(base, strings.Replace(base, "-k k", "-k K", 1), testAuditTarget()); id != AuditDistinct {
			t.Errorf("a key in another case: %v, want distinct (keys are strings)", id)
		}
		if id, _ := AuditRuleIdentity("-w /etc/Shadow -p wa -k k", "-w /etc/shadow -p wa -k k", testAuditTarget()); id == AuditSame {
			t.Error("a path in another case compared same")
		}
	})
}
