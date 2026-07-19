package auditruleset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

// scanCmd is the rules.d scan the conflict guard runs (must match
// auditRulesScanCmd in the handler).
const scanCmd = "grep -rhsE '^[[:space:]]*-(w|a|A)[[:space:]]' /etc/audit/rules.d/ 2>/dev/null"

// The exact 211 scenario: /etc/shadow is already watched under a different key
// (audit_rules_usergroup_modification). Applying the identity-keyed watch would
// create a cross-file duplicate that aborts the audit load and drops
// immutability at reboot. Apply must DETECT the conflict and refuse to write —
// not silently create the duplicate.
//
// @spec auditnl-rule-set
// @ac AC-08
func TestApply_RefusesCrossFileDuplicate(t *testing.T) {
	t.Run("auditnl-rule-set/AC-08", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// The host already audits /etc/shadow (a different drop-in, different key).
	tp.Results[scanCmd] = &api.CommandResult{
		Stdout: "-w /etc/shadow -p wa -k audit_rules_usergroup_modification\n",
	}
	res, err := auditruleset.New().Apply(context.Background(), tp,
		api.Params{"rule": "-w /etc/shadow -p wa -k identity", "persist_file": auditPath}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Success {
		t.Fatalf("Apply must refuse a cross-file duplicate; got Success=true detail=%q", res.Detail)
	}
	if !strings.Contains(res.Detail, "conflict") || !strings.Contains(res.Detail, "already audited") {
		t.Errorf("conflict detail should explain the duplicate; got %q", res.Detail)
	}
	// It must NOT have written+loaded the drop-in — the write path always ends
	// in `augenrules --load` (or a netlink write), which the conflict guard
	// short-circuits before. The base64 existence-read is not a write.
	for _, cmd := range tp.Runs {
		if strings.Contains(cmd, "augenrules") || strings.Contains(cmd, "> "+auditPath) {
			t.Errorf("Apply wrote the drop-in despite the conflict: %q", cmd)
		}
	}
}

// A syscall rule whose action is already loaded under a DIFFERENT key (the
// perm_mod class that broke 211) is also refused — the kernel dedups the
// syscall signature, not the key.
//
// @spec auditnl-rule-set
// @ac AC-08
func TestApply_RefusesDuplicateSyscallDifferentKey(t *testing.T) {
	t.Run("auditnl-rule-set/AC-08", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results[scanCmd] = &api.CommandResult{
		Stdout: "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod\n",
	}
	res, err := auditruleset.New().Apply(context.Background(), tp,
		api.Params{"rule": "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod_kensa", "persist_file": auditPath}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Success {
		t.Errorf("Apply must refuse a duplicate syscall action; got Success=true detail=%q", res.Detail)
	}
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
