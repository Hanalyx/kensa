package auditruleset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

// applyAgainstRulesD runs Apply for rule on a host whose rules.d files hold
// onDisk, and reports whether the duplicate guard refused it.
func applyAgainstRulesD(t *testing.T, rule, onDisk string) (refused bool, detail string) {
	t.Helper()
	tp := engine.NewFakeTransport()
	tp.Results[scanCmd] = &api.CommandResult{Stdout: onDisk + "\n"}
	measuredHost(tp, rule, onDisk)
	res, err := auditruleset.New().Apply(context.Background(), tp,
		api.Params{"rule": rule, "persist_file": auditPath}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return !res.Success && strings.Contains(res.Detail, "not applied"), res.Detail
}

// The guard refuses a write when the rules.d files already hold the same
// kernel rule, key included, or when it cannot show they do not. A never
// rule, a rule narrowed by a filter the new rule lacks, and the same rule
// under another key are different kernel rules and load beside it.
//
// @spec check-audit-rule-match
// @ac AC-16
func TestApply_GuardMatchesTheKernelRule(t *testing.T) {
	t.Run("check-audit-rule-match/AC-16", func(t *testing.T) {
		const execve = "-a always,exit -F arch=b64 -S execve -k kensa_exec"
		cases := []struct {
			name, rule, onDisk string
			refuse             bool
		}{
			{"never rule on disk is not a duplicate", execve,
				"-a never,exit -F arch=b64 -S execve -k kensa_exec", false},
			{"rule narrowed by success=0 under another key is not a duplicate", execve,
				"-a always,exit -F arch=b64 -S execve -F success=0 -k exec_fail", false},
			{"privileged-exec rule is not a plain execve duplicate", execve,
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k kensa_exec", false},
			{"reversed comparison under one key is a duplicate",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -k user_emulation",
				"-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation", true},
			{"same rule under another key is not a duplicate", execve,
				"-a always,exit -F arch=b64 -S execve -k other", false},
			{"same rule under the same key is a duplicate", execve,
				"-a always,exit -F arch=b64 -S execve -F key=kensa_exec", true},
			{"auid!=unset on both sides under one key is a duplicate",
				"-a always,exit -F arch=b64 -S chown,fchown -F auid>=1000 -F auid!=unset -k perm_mod",
				"-a always,exit -F arch=b64 -S chown,fchown -F auid>=1000 -F auid!=unset -k perm_mod", true},
			{"euid=root vs euid=0 under one key is a duplicate (resolved through files)",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
				"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=root -k execpriv", true},
		}
		for _, c := range cases {
			if refused, detail := applyAgainstRulesD(t, c.rule, c.onDisk); refused != c.refuse {
				t.Errorf("%s: refused=%v want %v (detail: %q)", c.name, refused, c.refuse, detail)
			}
		}
	})
}

// The shell staged rollback decides PartialRestore from auditctl -l, with
// check.AuditLineMaybeLoaded. A staged rule auditd loaded at boot reads as
// loaded in the form auditctl prints it, including auid printed as unset,
// which the earlier matcher missed. The interim union with the earlier
// matcher means a never line with the same fields still reads as loaded: a
// cautious PartialRestore, never a clean restore the earlier matcher would
// not have given.
//
// @spec check-audit-rule-match
// @ac AC-06
func TestRollback_Shell_StagedVerdictUsesKernelRule(t *testing.T) {
	t.Run("check-audit-rule-match/AC-06", func(t *testing.T) {
		const staged = "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
		const printed = "-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation"
		cases := []struct {
			name, loaded string
			partial      bool
		}{
			{"staged rule loaded in printed form", printed, true},
			{"auid printed as unset", strings.Replace(printed, "auid!=-1", "auid!=unset", 1), true},
			{"only a never line loaded (interim, cautious)", strings.Replace(printed, "always,exit", "never,exit", 1), true},
			{"an unrelated rule loaded", "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_mod", false},
		}
		for _, c := range cases {
			tp := engine.NewFakeTransport()
			tp.Results["auditctl -l 2>/dev/null"] = &api.CommandResult{Stdout: c.loaded + "\n"}
			pre := &api.PreState{
				Mechanism: "audit_rule_set",
				Data: map[string]interface{}{
					"path":             auditPath,
					"file_existed":     false,
					"prior_content":    "",
					"file_added_lines": []string{staged},
					"immutable_staged": true,
				},
			}
			rb, err := auditruleset.New().Rollback(context.Background(), tp, pre)
			if err != nil {
				t.Fatalf("%s: Rollback: %v", c.name, err)
			}
			if rb.PartialRestore != c.partial || rb.Success == c.partial {
				t.Errorf("%s: Success=%v PartialRestore=%v, want PartialRestore=%v (detail: %q)",
					c.name, rb.Success, rb.PartialRestore, c.partial, rb.Detail)
			}
		}
	})
}

// A staged watch written with a trailing slash reads as loaded when auditctl
// -l prints it without the slash; a clean restore there would over-claim.
//
// @spec check-audit-rule-match
// @ac AC-06
func TestRollback_Shell_StagedWatchTrailingSlash(t *testing.T) {
	t.Run("check-audit-rule-match/AC-06", func(t *testing.T) {
		tp := engine.NewFakeTransport()
		tp.Results["auditctl -l 2>/dev/null"] = &api.CommandResult{Stdout: "-w /etc/sudoers.d -p wa -k identity\n"}
		pre := &api.PreState{
			Mechanism: "audit_rule_set",
			Data: map[string]interface{}{
				"path":             auditPath,
				"file_existed":     false,
				"prior_content":    "",
				"file_added_lines": []string{"-w /etc/sudoers.d/ -p wa -k identity"},
				"immutable_staged": true,
			},
		}
		rb, err := auditruleset.New().Rollback(context.Background(), tp, pre)
		if err != nil {
			t.Fatalf("Rollback: %v", err)
		}
		if rb.Success || !rb.PartialRestore {
			t.Errorf("Success=%v PartialRestore=%v, want PartialRestore (detail: %q)", rb.Success, rb.PartialRestore, rb.Detail)
		}
	})
}
