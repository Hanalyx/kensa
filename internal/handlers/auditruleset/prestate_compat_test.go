package auditruleset_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

// oldPreStates reads pre-states that Capture at 2a07253 produced, after a
// JSON round trip as the store gives them back. They lack persist_only and
// audit_immutable_at_capture.
func oldPreStates(t *testing.T) map[string]*api.PreState {
	t.Helper()
	b, err := os.ReadFile("testdata/prestate-2a07253.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	out := map[string]*api.PreState{}
	for k, d := range raw {
		out[k] = &api.PreState{Mechanism: "audit_rule_set", Capturable: true, Data: d}
	}
	return out
}

// bareLoad reports whether runs hold an augenrules --load whose failure is
// not tolerated, the load a staged or persist_only rollback must not run.
func bareLoad(runs []string) bool {
	for _, r := range runs {
		if strings.Contains(r, "augenrules --load") && !strings.Contains(r, "|| true") {
			return true
		}
	}
	return false
}

// A rollback of a pre-state captured before persist_only and
// audit_immutable_at_capture were recorded never runs a bare augenrules
// --load for a control line, and is clean only when the live state shows
// it. A persist_only -e 2 captured on a mutable host is rolled back as staged:
// clean when the status reads enabled 1, partial when it reads 2 or cannot be
// read. Without audit_immutable_at_capture an -e 2 captured on an immutable
// host reads the status too, which gives a cautious partial.
//
// @spec auditnl-rule-set
// @ac AC-15
func TestRollback_PreStateFrom2a07253(t *testing.T) {
	t.Run("auditnl-rule-set/AC-15", func(t *testing.T) {
		old := oldPreStates(t)
		const listed = "-a always,exit -F arch=b64 -S execve -F key=exec"
		const rule = "-a always,exit -F arch=b64 -S execve -k exec"
		shell := []struct {
			name, status, listing string
			partial               bool
		}{
			{"shell-persist-only-e2-mutable", "enabled 1", "No rules", false},
			{"shell-persist-only-e2-mutable", "enabled 2", "No rules", true},
			{"shell-persist-only-e2-mutable", "", "No rules", true},
			{"shell-persist-only-e2-immutable", "enabled 2", "No rules", true},
			{"shell-rule-mutable", "enabled 1", "No rules", false},
			{"shell-rule-mutable", "enabled 1", listed, true},
			{"shell-rule-immutable", "enabled 2", "No rules", false},
			{"shell-rule-immutable", "enabled 2", listed, true},
		}
		for _, c := range shell {
			pre, ok := old[c.name]
			if !ok {
				t.Fatalf("fixture %s missing", c.name)
			}
			tp := engine.NewFakeTransport()
			if c.status == "" {
				tp.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{ExitCode: 1}
			} else {
				tp.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{Stdout: c.status + "\n"}
			}
			tp.Results["auditctl -l"] = &api.CommandResult{Stdout: c.listing + "\n"}
			measuredHost(tp, rule, listed)
			rb, err := auditruleset.New().Rollback(context.Background(), tp, pre)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if rb.PartialRestore != c.partial || rb.Success == c.partial {
				t.Errorf("%s (%q, %q): Success=%v Partial=%v detail=%q, want Partial=%v",
					c.name, c.status, c.listing, rb.Success, rb.PartialRestore, rb.Detail, c.partial)
			}
			if strings.Contains(c.name, "persist-only") || strings.Contains(c.name, "immutable") {
				if bareLoad(tp.Runs) {
					t.Errorf("%s: ran a bare augenrules --load: %q", c.name, tp.Runs)
				}
			}
			if strings.Contains(c.name, "persist-only") {
				for _, r := range tp.Runs {
					if strings.Contains(r, "augenrules") {
						t.Errorf("%s: ran a load for a persist_only line: %q", c.name, r)
					}
				}
			}
		}
		netlink := []struct {
			name    string
			enabled int
			partial bool
		}{
			{"netlink-persist-only-e2-mutable", 1, false},
			{"netlink-persist-only-e2-mutable", 2, true},
			{"netlink-persist-only-e2-immutable", 2, true},
			{"netlink-rule-mutable", 1, false},
			{"netlink-rule-immutable", 2, false},
		}
		for _, c := range netlink {
			f := auditnl.NewFakeAudit()
			f.Enabled = c.enabled
			rb, err := auditruleset.New().Rollback(context.Background(), f, old[c.name])
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if rb.PartialRestore != c.partial || rb.Success == c.partial {
				t.Errorf("%s (enabled %d): Success=%v Partial=%v detail=%q, want Partial=%v",
					c.name, c.enabled, rb.Success, rb.PartialRestore, rb.Detail, c.partial)
			}
		}
	})
}

// A committed netlink pre-state whose added_rules holds a control line, which
// a current Capture never records (BuildRule refuses one), still gives
// PartialRestore: the listing cannot show the line is undone.
//
// @spec auditnl-rule-set
// @ac AC-15
func TestRollback_Netlink_AddedControlLineIsPartial(t *testing.T) {
	t.Run("auditnl-rule-set/AC-15", func(t *testing.T) {
		f := auditnl.NewFakeAudit()
		f.Enabled = 1
		pre := &api.PreState{Mechanism: "audit_rule_set", Capturable: true, Data: map[string]interface{}{
			"path":             "/etc/audit/rules.d/99-kensa.rules",
			"file_existed":     false,
			"prior_content":    "",
			"added_rules":      []interface{}{"-b 8192"},
			"file_added_lines": []interface{}{"-b 8192"},
			"persist_only":     false,
		}}
		rb, err := auditruleset.New().Rollback(context.Background(), f, pre)
		if err != nil {
			t.Fatal(err)
		}
		if rb.Success || !rb.PartialRestore || !strings.Contains(rb.Detail, "-b 8192") {
			t.Errorf("Success=%v Partial=%v detail=%q", rb.Success, rb.PartialRestore, rb.Detail)
		}
	})
}
