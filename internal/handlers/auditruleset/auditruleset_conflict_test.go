package auditruleset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/check"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
	"github.com/Hanalyx/kensa/internal/shellcapture"
)

// scanCmd is the rules.d scan the conflict guard runs (must match
// auditRulesScanCmd in the handler).
const scanCmd = "[ -d /etc/audit/rules.d ] || exit 0; " +
	"grep -rhsE '^[[:space:]]*-(w|a|A)' /etc/audit/rules.d/; rc=$?; [ $rc -le 1 ] && exit 0; exit $rc"

// measuredHost answers the host-facts probe for these lines as an x86_64
// host with audit-4.0.3 where every probed path is a regular file.
func measuredHost(tp *engine.FakeTransport, lines ...string) {
	out := "machine\tx86_64\nauditctl\tauditctl version 4.0.3\nuid\troot\t0\n"
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) > 1 && f[0] == "-w" {
			out += "path\t" + f[1] + "\tother\n"
		}
	}
	tp.Results[check.AuditTargetProbe(lines)] = &api.CommandResult{Stdout: out}
}

// assertNotWritten fails when Apply wrote or loaded the drop-in. The write
// path always ends in augenrules --load (or a netlink write), which the
// guard short-circuits before; the base64 existence-read is not a write.
func assertNotWritten(t *testing.T, tp *engine.FakeTransport) {
	t.Helper()
	for _, cmd := range tp.Runs {
		if strings.Contains(cmd, "augenrules") || strings.Contains(cmd, "> "+auditPath) {
			t.Errorf("Apply wrote the drop-in despite the refusal: %q", cmd)
		}
	}
}

// The same watch under the same key in another drop-in is one kernel rule,
// so writing it again would abort the audit load at reboot: refused. The
// same watch under another key is a different kernel rule (captured on RHEL
// 10.2 and Rocky 9.8: both load), so it is written.
//
// @spec auditnl-rule-set
// @ac AC-08
func TestApply_RefusesCrossFileDuplicate(t *testing.T) {
	t.Run("auditnl-rule-set/AC-08", func(t *testing.T) {})
	const rule = "-w /etc/shadow -p wa -k identity"
	for _, c := range []struct {
		onDisk string
		refuse bool
	}{
		{"-a always,exit -F path=/etc/shadow -F perm=wa -k identity", true},
		{"-w /etc/shadow -p wa -k audit_rules_usergroup_modification", false},
	} {
		tp := engine.NewFakeTransport()
		tp.Results[scanCmd] = &api.CommandResult{Stdout: c.onDisk + "\n"}
		measuredHost(tp, rule, c.onDisk)
		res, err := auditruleset.New().Apply(context.Background(), tp,
			api.Params{"rule": rule, "persist_file": auditPath}, nil)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if res.Success == c.refuse {
			t.Errorf("against %q: Success=%v, want refuse=%v (detail %q)", c.onDisk, res.Success, c.refuse, res.Detail)
		}
		if c.refuse {
			if !strings.Contains(res.Detail, "conflict") || !strings.Contains(res.Detail, "same kernel rule") {
				t.Errorf("conflict detail should explain the duplicate; got %q", res.Detail)
			}
			assertNotWritten(t, tp)
		}
	}
}

// A syscall rule already in rules.d under the same key, written with its
// syscalls in another order and auid!=-1 for auid!=unset, is refused; the
// same rule under another key loads beside it and is written.
//
// @spec auditnl-rule-set
// @ac AC-08
func TestApply_RefusesDuplicateSyscallDifferentKey(t *testing.T) {
	t.Run("auditnl-rule-set/AC-08", func(t *testing.T) {})
	const onDisk = "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod"
	for _, c := range []struct {
		rule   string
		refuse bool
	}{
		{"-a always,exit -F arch=b64 -S lchown,fchownat,fchown,chown -F auid>=1000 -F auid!=unset -k perm_mod", true},
		{"-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod_kensa", false},
	} {
		tp := engine.NewFakeTransport()
		tp.Results[scanCmd] = &api.CommandResult{Stdout: onDisk + "\n"}
		measuredHost(tp, c.rule, onDisk)
		res, err := auditruleset.New().Apply(context.Background(), tp,
			api.Params{"rule": c.rule, "persist_file": auditPath}, nil)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if res.Success == c.refuse {
			t.Errorf("%q: Success=%v, want refuse=%v (detail %q)", c.rule, res.Success, c.refuse, res.Detail)
		}
	}
}

// The guard fails closed: when it cannot read the target drop-in, the
// rules.d files or the host facts, it refuses rather than write a rule it
// cannot show is not a duplicate. A host with no rules.d directory has no
// rules to collide with, and a pair it cannot resolve is refused like a
// duplicate. A flag written against its argument still reaches the guard.
//
// @spec auditnl-rule-set
// @ac AC-09
func TestApply_GuardFailsClosed(t *testing.T) {
	t.Run("auditnl-rule-set/AC-09", func(t *testing.T) {
		const rule = "-a always,exit -F arch=b64 -S chown -F auid>=1000 -k perm_mod"
		apply := func(tp *engine.FakeTransport) *api.StepResult {
			t.Helper()
			res, err := auditruleset.New().Apply(context.Background(), tp,
				api.Params{"rule": rule, "persist_file": auditPath}, nil)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			return res
		}
		// Unreadable rules.d (grep exit 2, as for a non-root reader).
		tp := engine.NewFakeTransport()
		tp.Results[scanCmd] = &api.CommandResult{ExitCode: 2, Stderr: "Permission denied"}
		if res := apply(tp); res.Success || !strings.Contains(res.Detail, "cannot read /etc/audit/rules.d") {
			t.Errorf("unreadable rules.d: %+v", res)
		}
		assertNotWritten(t, tp)
		// A host-facts probe that fails.
		const onDisk = "-a always,exit -F arch=b64 -S chmod -F auid>=1000 -k perm_mod"
		tp = engine.NewFakeTransport()
		tp.Results[scanCmd] = &api.CommandResult{Stdout: onDisk + "\n"}
		tp.Results[check.AuditTargetProbe([]string{rule, onDisk})] = &api.CommandResult{ExitCode: 1}
		if res := apply(tp); res.Success || !strings.Contains(res.Detail, "host facts") {
			t.Errorf("failed probe: %+v", res)
		}
		assertNotWritten(t, tp)
		// Unreadable target drop-in.
		tp = engine.NewFakeTransport()
		tp.Results[shellcapture.ExistenceReadCmd("-e", "'"+auditPath+"'", "__KENSA_ABSENT__")] = &api.CommandResult{ExitCode: 1, Stderr: "Input/output error"}
		if res := apply(tp); res.Success || !strings.Contains(res.Detail, "cannot read "+auditPath) {
			t.Errorf("unreadable drop-in: %+v", res)
		}
		// An unresolved pair: the same syscall rule with auid written as a
		// name only a directory service knows. Refused, with the reason.
		const named = "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F euid=ldapuser -k perm_mod"
		const numeric = "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F euid=1500 -k perm_mod"
		tp = engine.NewFakeTransport()
		tp.Results[scanCmd] = &api.CommandResult{Stdout: named + "\n"}
		measuredHost(tp, numeric, named)
		res, err := auditruleset.New().Apply(context.Background(), tp,
			api.Params{"rule": numeric, "persist_file": auditPath}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Success || !strings.Contains(res.Detail, "cannot show") {
			t.Errorf("unresolved pair: %+v", res)
		}
		// No rules.d lines at all: nothing to collide with.
		tp = engine.NewFakeTransport()
		if res := apply(tp); !res.Success {
			t.Errorf("empty rules.d: %+v", res)
		}
		// An attached flag in rules.d reaches the comparison.
		tp = engine.NewFakeTransport()
		const attached = "-aalways,exit -Farch=b64 -Schown -Fauid>=1000 -kperm_mod"
		tp.Results[scanCmd] = &api.CommandResult{Stdout: attached + "\n"}
		measuredHost(tp, rule, attached)
		if res := apply(tp); res.Success || !strings.Contains(res.Detail, "same kernel rule") {
			t.Errorf("attached-flag duplicate: %+v", res)
		}
	})
}

// No conflict when the action is NOT already present: Apply proceeds normally.
//
// @spec auditnl-rule-set
// @ac AC-08
func TestApply_NoConflictWhenActionAbsent(t *testing.T) {
	t.Run("auditnl-rule-set/AC-08", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Live ruleset watches something else — no overlap with our rule.
	tp.Results[scanCmd] = &api.CommandResult{
		Stdout: "-w /etc/passwd -p wa -k identity\n",
	}
	res, err := auditruleset.New().Apply(context.Background(), tp,
		api.Params{"rule": "-w /etc/gshadow -p wa -k identity", "persist_file": auditPath}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should proceed when there is no conflict; got Success=false detail=%q", res.Detail)
	}
}
