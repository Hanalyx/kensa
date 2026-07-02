package auditruleset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

// lastAugenrulesCmd returns the most recent shell command that reloaded
// augenrules — the merge model reads the file first, so the write/rm is no
// longer Runs[0].
func lastAugenrulesCmd(t *testing.T, runs []string) string {
	t.Helper()
	for i := len(runs) - 1; i >= 0; i-- {
		if strings.Contains(runs[i], "augenrules --load") {
			return runs[i]
		}
	}
	t.Fatalf("no 'augenrules --load' command in runs: %v", runs)
	return ""
}

// @spec handler-audit-rule-set
// @ac AC-01
func TestApply_WritesRuleAndLoads(t *testing.T) {
	t.Log("// @spec handler-audit-rule-set")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := auditruleset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"persist_file": "/etc/audit/rules.d/kensa-watch-passwd.rules",
		"rule":         "-w /etc/passwd -p wa -k identity",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	cmd := lastAugenrulesCmd(t, tp.Runs)
	if !strings.Contains(cmd, "kensa-watch-passwd.rules") {
		t.Errorf("expected rule file path; got %q", cmd)
	}
	if !strings.Contains(cmd, "identity") {
		t.Errorf("expected merged rule content in the write; got %q", cmd)
	}
}

// @spec handler-audit-rule-set
// @ac AC-02
// @ac AC-03
func TestRollback_RemovesFileWhenAbsentAtCapture(t *testing.T) {
	t.Log("// @spec handler-audit-rule-set")
	t.Run("handler-audit-rule-set/AC-02", func(t *testing.T) {})
	t.Run("handler-audit-rule-set/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := auditruleset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"path":          "/etc/audit/rules.d/kensa-watch-passwd.rules",
			"file_existed":  false,
			"prior_content": "",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	cmd := lastAugenrulesCmd(t, tp.Runs)
	if !strings.Contains(cmd, "rm -f") {
		t.Errorf("expected rm -f (no managed rule left); got %q", cmd)
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = auditruleset.New()
}
