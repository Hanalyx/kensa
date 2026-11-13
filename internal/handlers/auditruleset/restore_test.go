package auditruleset_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
	"github.com/Hanalyx/kensa/internal/shellcapture"
)

const restoreRule = "-a always,exit -F arch=b64 -S execve -k kensa_restore"

// priorFiles are drop-ins an operator may already have, each of which
// rollback must give back byte for byte.
var priorFiles = map[string]string{
	"empty file":                 "",
	"comment-only file":          "# operator notes, kept on purpose\n",
	"no trailing newline":        "-a always,exit -F arch=b64 -S chmod -k other",
	"blank lines and comments":   "\n\n# header\n\n-a always,exit -F arch=b64 -S chmod -k other\n\n",
	"several trailing newlines":  "-a always,exit -F arch=b64 -S chmod -k other\n\n\n",
	"comment with no newline":    "# just a note",
	"carriage returns preserved": "# windows\r\n-a always,exit -F arch=b64 -S chmod -k other\r\n",
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Netlink: Capture, Apply and Rollback over a drop-in that existed with
// prior content leave the file byte for byte as it was, including an empty
// file, a comment-only file and the trailing newline state.
//
// @spec handler-audit-rule-set
// @ac AC-07
func TestRollback_Netlink_RestoresPriorFileBytes(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-07", func(t *testing.T) {
		for name, prior := range priorFiles {
			f := auditnl.NewFakeAudit()
			f.Enabled = 1
			f.Files[auditPath] = prior
			h := auditruleset.New()
			params := api.Params{"rule": restoreRule, "persist_file": auditPath}
			pre, err := h.Capture(context.Background(), f, params)
			if err != nil {
				t.Fatalf("%s: Capture: %v", name, err)
			}
			if res, err := h.Apply(context.Background(), f, params, nil); err != nil || !res.Success {
				t.Fatalf("%s: Apply: err=%v res=%+v", name, err, res)
			}
			if _, err := h.Rollback(context.Background(), f, pre); err != nil {
				t.Fatalf("%s: Rollback: %v", name, err)
			}
			got, ok := f.Files[auditPath]
			if !ok || got != prior {
				t.Errorf("%s: file after rollback = %q (exists %v), want %q", name, got, ok, prior)
			}
		}
	})
}

// shellHost answers the shell rollback's read of the drop-in with current.
func shellHost(current string, exists bool) *engine.FakeTransport {
	tp := engine.NewFakeTransport()
	out := "__KENSA_ABSENT__"
	if exists {
		out = base64.StdEncoding.EncodeToString([]byte(current))
	}
	tp.Results[shellcapture.ExistenceReadCmd("-e", shellQuote(auditPath), "__KENSA_ABSENT__")] = &api.CommandResult{Stdout: out}
	tp.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{Stdout: "enabled 1\n"}
	tp.Results["auditctl -l"] = &api.CommandResult{Stdout: "No rules\n"}
	return tp
}

// restoreCmd returns the rollback command that wrote or removed the drop-in.
func restoreCmd(t *testing.T, runs []string) string {
	t.Helper()
	for _, r := range runs {
		if strings.HasPrefix(r, "printf '%s' ") || strings.HasPrefix(r, "rm -f ") {
			return r
		}
	}
	t.Fatalf("no restore command in %q", runs)
	return ""
}

// Shell: the rollback writes the captured prior bytes back when the file is
// as Apply left it, and removes the file only when Kensa created it.
//
// @spec handler-audit-rule-set
// @ac AC-07
func TestRollback_Shell_RestoresPriorFileBytes(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-07", func(t *testing.T) {
		for name, prior := range priorFiles {
			// What applyShell writes: the merge of the prior file and the rule.
			merged := mergedForTest(prior)
			pre := &api.PreState{Mechanism: "audit_rule_set", Data: map[string]interface{}{
				"path": auditPath, "file_existed": true, "prior_content": prior,
				"file_added_lines": []string{restoreRule}, "persist_only": false,
			}}
			tp := shellHost(merged, true)
			if _, err := auditruleset.New().Rollback(context.Background(), tp, pre); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			want := "printf '%s' " + shellQuote(prior) + " > " + shellQuote(auditPath) + " && augenrules --load"
			if got := restoreCmd(t, tp.Runs); got != want {
				t.Errorf("%s: restore = %q, want %q", name, got, want)
			}
		}
		// Kensa created the file: removed.
		pre := &api.PreState{Mechanism: "audit_rule_set", Data: map[string]interface{}{
			"path": auditPath, "file_existed": false, "prior_content": "",
			"file_added_lines": []string{restoreRule}, "persist_only": false,
		}}
		tp := shellHost(mergedForTest(""), true)
		if _, err := auditruleset.New().Rollback(context.Background(), tp, pre); err != nil {
			t.Fatal(err)
		}
		if got := restoreCmd(t, tp.Runs); !strings.HasPrefix(got, "rm -f "+shellQuote(auditPath)) {
			t.Errorf("Kensa-created file: restore = %q, want rm -f", got)
		}
	})
}

// mergedForTest is what Apply writes for restoreRule over prior: Capture and
// Apply on a netlink fake give the same bytes as the shell merge.
func mergedForTest(prior string) string {
	f := auditnl.NewFakeAudit()
	f.Enabled = 2 // stage only: write the file, load nothing
	f.Files[auditPath] = prior
	params := api.Params{"rule": restoreRule, "persist_file": auditPath}
	if _, err := auditruleset.New().Apply(context.Background(), f, params, nil); err != nil {
		panic(err)
	}
	return f.Files[auditPath]
}

// A comment an operator appends after Apply survives the rollback with every
// prior byte, on both transports; only the rolled-back rule's line goes.
//
// @spec handler-audit-rule-set
// @ac AC-07
func TestRollback_KeepsCommentAddedAfterApply(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-07", func(t *testing.T) {
		const note = "# added by the operator after remediate\n"
		for name, prior := range map[string]string{
			"existing file":       "-a always,exit -F arch=b64 -S chmod -k other\n",
			"no trailing newline": "-a always,exit -F arch=b64 -S chmod -k other",
			"Kensa created":       "",
		} {
			after := mergedForTest(prior) + note
			want := prior + note
			if prior != "" && !strings.HasSuffix(prior, "\n") {
				// A line now follows the prior content, so it ends in one.
				want = prior + "\n" + note
			}
			if prior == "" {
				// The file Kensa created keeps its header, since it now holds
				// the operator's line.
				want = "# Managed by Kensa.\n" + note
			}
			f := auditnl.NewFakeAudit()
			f.Enabled = 1
			if prior != "" {
				f.Files[auditPath] = prior
			}
			h := auditruleset.New()
			params := api.Params{"rule": restoreRule, "persist_file": auditPath}
			pre, err := h.Capture(context.Background(), f, params)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
				t.Fatal(err)
			}
			f.Files[auditPath] = after
			if _, err := h.Rollback(context.Background(), f, pre); err != nil {
				t.Fatal(err)
			}
			if got, ok := f.Files[auditPath]; !ok || got != want {
				t.Errorf("%s, netlink: file = %q (exists %v), want %q", name, got, ok, want)
			}
			tp := shellHost(after, true)
			if _, err := auditruleset.New().Rollback(context.Background(), tp, pre); err != nil {
				t.Fatal(err)
			}
			wantCmd := "printf '%s' " + shellQuote(want) + " > " + shellQuote(auditPath) + " && augenrules --load"
			if got := restoreCmd(t, tp.Runs); got != wantCmd {
				t.Errorf("%s, shell: restore = %q, want %q", name, got, wantCmd)
			}
		}
	})
}

// A sibling rule merged into the drop-in after Apply survives the rollback,
// after every prior byte, including a trailing blank line Apply's merge
// dropped; only the rolled-back rule's line goes, on both transports.
//
// @spec handler-audit-rule-set
// @ac AC-07
func TestRollback_KeepsSiblingAddedAfterApply(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-07", func(t *testing.T) {
		const sibling = "-a always,exit -F arch=b64 -S chown -k sibling"
		// The prior file ends in a blank line, which Apply's merge drops.
		prior := "# operator notes\n-a always,exit -F arch=b64 -S chmod -k other\n\n"
		afterSibling := mergedForTest(prior) + sibling + "\n"
		want := prior + sibling + "\n"

		f := auditnl.NewFakeAudit()
		f.Enabled = 1
		f.Files[auditPath] = prior
		h := auditruleset.New()
		params := api.Params{"rule": restoreRule, "persist_file": auditPath}
		pre, err := h.Capture(context.Background(), f, params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
			t.Fatal(err)
		}
		f.Files[auditPath] = afterSibling
		if _, err := h.Rollback(context.Background(), f, pre); err != nil {
			t.Fatal(err)
		}
		if got := f.Files[auditPath]; got != want {
			t.Errorf("netlink: file = %q, want %q", got, want)
		}

		spre := &api.PreState{Mechanism: "audit_rule_set", Data: map[string]interface{}{
			"path": auditPath, "file_existed": true, "prior_content": prior,
			"file_added_lines": []string{restoreRule}, "persist_only": false,
		}}
		tp := shellHost(afterSibling, true)
		if _, err := auditruleset.New().Rollback(context.Background(), tp, spre); err != nil {
			t.Fatal(err)
		}
		wantCmd := "printf '%s' " + shellQuote(want) + " > " + shellQuote(auditPath) + " && augenrules --load"
		if got := restoreCmd(t, tp.Runs); got != wantCmd {
			t.Errorf("shell: restore = %q, want %q", got, wantCmd)
		}
	})
}

// Through Rollback on the netlink path: a file gone at rollback stays gone,
// and an edit after Apply that is not an append keeps every byte but ours.
//
// @spec handler-audit-rule-set
// @ac AC-07
func TestRollback_Netlink_GoneFileAndEdit(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-07", func(t *testing.T) {
		for name, after := range map[string]*string{"gone": nil, "edited": strPtr("# edited by the operator\n" + restoreRule + "\n")} {
			f := auditnl.NewFakeAudit()
			f.Enabled = 1
			f.Files[auditPath] = "# operator\n"
			h := auditruleset.New()
			params := api.Params{"rule": restoreRule, "persist_file": auditPath}
			pre, err := h.Capture(context.Background(), f, params)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
				t.Fatal(err)
			}
			if after == nil {
				delete(f.Files, auditPath)
			} else {
				f.Files[auditPath] = *after
			}
			if _, err := h.Rollback(context.Background(), f, pre); err != nil {
				t.Fatal(err)
			}
			got, ok := f.Files[auditPath]
			switch {
			case after == nil && ok:
				t.Errorf("%s: a file gone at rollback came back as %q", name, got)
			case after != nil && (!ok || got != "# edited by the operator\n"):
				t.Errorf("%s: file = %q (exists %v)", name, got, ok)
			}
		}
	})
}

func strPtr(s string) *string { return &s }
