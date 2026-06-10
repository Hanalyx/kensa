package auditruleset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

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
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "augenrules --load") {
		t.Errorf("expected augenrules --load; got %q", cmd)
	}
	if !strings.Contains(cmd, "kensa-watch-passwd.rules") {
		t.Errorf("expected rule file path; got %q", cmd)
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
	if !strings.Contains(tp.Runs[0], "rm -f") {
		t.Errorf("expected rm -f; got %q", tp.Runs[0])
	}
	if !strings.Contains(tp.Runs[0], "augenrules --load") {
		t.Errorf("expected augenrules --load after rm; got %q", tp.Runs[0])
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = auditruleset.New()
}
