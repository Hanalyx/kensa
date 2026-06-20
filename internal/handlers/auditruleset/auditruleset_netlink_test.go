package auditruleset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

const ruleLine = "-w /etc/passwd -p wa -k identity"
const auditPath = "/etc/audit/rules.d/99-kensa.rules"

// Netlink Apply loads the rule into the kernel and writes the drop-in.
//
// @spec auditnl-rule-set
// @ac AC-02
func TestApply_Netlink(t *testing.T) {
	t.Run("auditnl-rule-set/AC-02", func(t *testing.T) {})
	f := auditnl.NewFakeAudit()
	res, err := auditruleset.New().Apply(context.Background(), f,
		api.Params{"rule": ruleLine}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	if f.LoadedCount() != 1 {
		t.Errorf("loaded rule count = %d, want 1", f.LoadedCount())
	}
	if got := f.Files[auditPath]; !strings.Contains(got, ruleLine) {
		t.Errorf("drop-in = %q, want the rule", got)
	}
}

// A malformed rule line is a failed step, not a Go error, and nothing is
// loaded or persisted.
//
// @spec auditnl-rule-set
// @ac AC-02
func TestApply_Netlink_BadRule(t *testing.T) {
	t.Run("auditnl-rule-set/AC-02", func(t *testing.T) {})
	f := auditnl.NewFakeAudit()
	res, err := auditruleset.New().Apply(context.Background(), f,
		api.Params{"rule": "not a valid audit rule"}, nil)
	if err != nil {
		t.Fatalf("bad rule must not be a Go error; got %v", err)
	}
	if res.Success {
		t.Error("want Success:false on a malformed rule")
	}
	if f.LoadedCount() != 0 {
		t.Error("nothing should be loaded on a malformed rule")
	}
	if _, ok := f.Files[auditPath]; ok {
		t.Error("drop-in must not be written when a rule fails to parse")
	}
}

// Netlink round trip: a rule not loaded at capture is unloaded on rollback,
// and the drop-in (absent at capture) is removed.
//
// @spec auditnl-rule-set
// @ac AC-03
func TestRoundTrip_Netlink(t *testing.T) {
	t.Run("auditnl-rule-set/AC-03", func(t *testing.T) {})
	f := auditnl.NewFakeAudit()
	h := auditruleset.New()
	params := api.Params{"rule": ruleLine}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.LoadedCount() != 1 {
		t.Fatalf("post-apply loaded = %d, want 1", f.LoadedCount())
	}
	rb, err := h.Rollback(context.Background(), f, pre)
	if err != nil || !rb.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, rb.Success)
	}
	if f.LoadedCount() != 0 {
		t.Errorf("rollback should have unloaded the rule it added; loaded=%d", f.LoadedCount())
	}
	if _, ok := f.Files[auditPath]; ok {
		t.Error("rollback should have removed the drop-in that did not exist at capture")
	}
}

// A rule already loaded at capture (owned by another drop-in) is NOT
// unloaded on rollback — the added_rules guard.
//
// @spec auditnl-rule-set
// @ac AC-04
func TestRollback_Netlink_KeepsPreexisting(t *testing.T) {
	t.Run("auditnl-rule-set/AC-04", func(t *testing.T) {})
	f := auditnl.NewFakeAudit()
	// Pre-load the rule, as if another drop-in owns it.
	c, _ := f.AuditClient()
	wire, _ := auditnl.BuildRule(ruleLine)
	_ = c.AddRule(wire)
	_ = c.Close()

	h := auditruleset.New()
	params := api.Params{"rule": ruleLine}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if f.LoadedCount() != 1 {
		t.Errorf("a pre-existing rule must survive rollback; loaded=%d, want 1", f.LoadedCount())
	}
}

// Fallback: AuditClient unavailable → augenrules shell path.
//
// @spec auditnl-rule-set
// @ac AC-05
func TestApply_FallsBackWhenAuditUnavailable(t *testing.T) {
	t.Run("auditnl-rule-set/AC-05", func(t *testing.T) {})
	f := auditnl.NewFakeAudit()
	f.OpenErr = auditnl.ErrAuditUnavailable
	res, err := auditruleset.New().Apply(context.Background(), f,
		api.Params{"rule": ruleLine}, nil)
	if err != nil || !res.Success {
		t.Fatalf("fallback Apply: err=%v success=%v", err, res.Success)
	}
	var sawAugenrules bool
	for _, cmd := range f.Runs {
		if strings.Contains(cmd, "augenrules --load") {
			sawAugenrules = true
		}
	}
	if !sawAugenrules {
		t.Errorf("expected augenrules shell fallback; Runs=%v", f.Runs)
	}
}

// Fallback: a transport without the audit capability uses the shell path.
//
// @spec auditnl-rule-set
// @ac AC-05
func TestApply_FallsBackWhenNoCapability(t *testing.T) {
	t.Run("auditnl-rule-set/AC-05", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	res, err := auditruleset.New().Apply(context.Background(), tp,
		api.Params{"rule": ruleLine}, nil)
	if err != nil || !res.Success {
		t.Fatalf("shell Apply: err=%v success=%v", err, res.Success)
	}
	var sawAugenrules bool
	for _, cmd := range tp.Runs {
		if strings.Contains(cmd, "augenrules --load") {
			sawAugenrules = true
		}
	}
	if !sawAugenrules {
		t.Errorf("expected augenrules shell path; Runs=%v", tp.Runs)
	}
}
