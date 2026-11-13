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
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
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
		// errno names and arch aliases resolve only on a measured target.
		a, b := "-a always,exit -F arch=b64 -S open -F exit=-EACCES -k k", "-a always,exit -F arch=b64 -S open -F exit=-13 -k k"
		if id, _ := AuditRuleIdentity(a, b, testAuditTarget()); id != AuditSame {
			t.Errorf("exit=-EACCES vs -13 on a measured target: %v", id)
		}
		if id, _ := AuditRuleIdentity(a, b, &AuditTarget{Machine: "aarch64", AuditctlVersion: "4.0.3"}); id != AuditUnresolved {
			t.Errorf("exit=-EACCES vs -13 off the gate: %v", id)
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

// RuleText renders a netlink rule as auditctl syntax, except that a watch
// keeps its field type as an explicit path= or dir=. Every rule in the
// netlink captures, rendered from the wire netlink builds, compares with
// the line auditctl -l printed for it without a provable difference.
//
// @spec check-audit-rule-match
// @ac AC-17
func TestAuditIdentity_NetlinkRendering(t *testing.T) {
	t.Run("check-audit-rule-match/AC-17", func(t *testing.T) {
		for line, want := range map[string]string{
			"-a always,exit -F path=/etc/shadow -F perm=wa -k k":   "-a always,exit -S all -F path=/etc/shadow -F perm=wa -F key=k",
			"-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k k": "-a always,exit -S all -F dir=/etc/sudoers.d -F perm=wa -F key=k",
		} {
			w, err := auditnl.BuildRule(line)
			if err != nil {
				t.Fatal(err)
			}
			got, err := auditnl.RuleText(w)
			if err != nil || got != want {
				t.Errorf("RuleText(%q) = %q, %v; want %q", line, got, err, want)
			}
		}
		target := testAuditTarget()
		for _, name := range []string{"audit-4.0.3-netlink.tsv", "audit-3.1.5-netlink.tsv"} {
			for _, row := range capturedPrints(t, name) {
				w, err := auditnl.BuildRule(row[0])
				if err != nil {
					t.Fatalf("build %q: %v", row[0], err)
				}
				text, err := auditnl.RuleText(w)
				if err != nil {
					t.Fatalf("render %q: %v", row[0], err)
				}
				if isNeverRule(row[0]) {
					// auditctl -l prints this as an always watch; netlink keeps "never".
					if !strings.HasPrefix(text, "-a never,exit") {
						t.Errorf("%s: never rule %q renders as %q", name, row[0], text)
					}
					continue
				}
				a, b := parseAuditK(text, auditLoaded), parseAuditK(row[1], auditLoaded)
				if id, why := auditIdentity(a, b, target); id == AuditDistinct {
					t.Errorf("%s: %q renders as %q, which differs from the listing %q (%s)", name, row[0], text, row[1], why)
				}
			}
		}
	})
}

// A requirement the listing cannot decide is skipped, with a detail that
// names the watch case, and the agent transport's netlink read decides it.
// The netlink read is recorded in the check evidence.
//
// @spec check-audit-rule-match
// @ac AC-18
func TestAuditIdentity_SkippedOverSSHDecidedOverNetlink(t *testing.T) {
	t.Run("check-audit-rule-match/AC-18", func(t *testing.T) {
		const rule = "-w /etc/shadow -p wa -k identity"
		listing := "-w /etc/shadow -p wa -k identity"
		chk := api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": rule}}
		ssh := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, listing)}}
		_, err := Run(context.Background(), ssh, chk)
		if !errors.Is(err, ErrNotAssessable) || !strings.Contains(err.Error(), "agent transport") ||
			!strings.Contains(err.Error(), "replaced by rename") {
			t.Fatalf("over the listing alone: %v", err)
		}
		agentPath := newNetlinkFake(t, listing, "-a always,exit -F path=/etc/shadow -F perm=wa -k identity")
		res, err := Run(context.Background(), agentPath, chk)
		if err != nil || !res.Passed {
			t.Fatalf("netlink path field: passed=%v err=%v", res.Passed, err)
		}
		found := false
		for _, ev := range res.Evidence {
			if ev.Command == auditNetlinkCommand && strings.Contains(ev.Stdout, "path=/etc/shadow") {
				found = true
			}
		}
		if !found {
			t.Errorf("the netlink read is not in the evidence: %+v", res.Evidence)
		}
		agentDir := newNetlinkFake(t, listing, "-a always,exit -F dir=/etc/shadow -F perm=wa -k identity")
		res, err = Run(context.Background(), agentDir, chk)
		if err != nil || res.Passed {
			t.Fatalf("netlink dir field on a file: passed=%v err=%v, want a fail", res.Passed, err)
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
