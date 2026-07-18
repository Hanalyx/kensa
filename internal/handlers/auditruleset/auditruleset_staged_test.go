package auditruleset_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

// On an immutable audit config (netlink GetStatus enabled 2) Apply stages the
// drop-in and returns Success:true, Staged:true WITHOUT loading into the
// kernel — the change takes effect on reboot.
//
// @spec auditnl-rule-set
// @ac AC-07
func TestApply_Netlink_StagedWhenImmutable(t *testing.T) {
	t.Run("auditnl-rule-set/AC-07", func(t *testing.T) {})
	f := auditnl.NewFakeAudit()
	f.Enabled = 2 // immutable: kernel refuses runtime loads until reboot
	res, err := auditruleset.New().Apply(context.Background(), f,
		api.Params{"rule": ruleLine}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success || !res.Staged {
		t.Fatalf("want Success=true Staged=true on immutable; got Success=%v Staged=%v detail=%q",
			res.Success, res.Staged, res.Detail)
	}
	if f.LoadedCount() != 0 {
		t.Errorf("immutable Apply must NOT load into the kernel; loaded=%d", f.LoadedCount())
	}
	if got := f.Files[auditPath]; !strings.Contains(got, ruleLine) {
		t.Errorf("staged drop-in must contain the rule; got %q", got)
	}
}

// Netlink staged round trip: Capture → Apply (staged, immutable) → Rollback
// removes the drop-in that was absent at capture; nothing is ever loaded, and
// the restore is byte-perfect.
//
// @spec auditnl-rule-set
// @ac AC-07
func TestRoundTrip_Netlink_StagedRollback(t *testing.T) {
	t.Run("auditnl-rule-set/AC-07", func(t *testing.T) {})
	f := auditnl.NewFakeAudit()
	f.Enabled = 2
	h := auditruleset.New()
	params := api.Params{"rule": ruleLine}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	res, err := h.Apply(context.Background(), f, params, nil)
	if err != nil || !res.Staged {
		t.Fatalf("Apply staged: err=%v staged=%v", err, res.Staged)
	}
	if f.LoadedCount() != 0 {
		t.Fatalf("staged apply must not load a rule; loaded=%d", f.LoadedCount())
	}
	rb, err := h.Rollback(context.Background(), f, pre)
	if err != nil || !rb.Success {
		t.Fatalf("Rollback: err=%v success=%v detail=%q", err, rb.Success, rb.Detail)
	}
	if _, ok := f.Files[auditPath]; ok {
		t.Error("rollback should have removed the staged drop-in absent at capture")
	}
}

// Regression (adversarial-panel BLOCKER): a REALISTIC immutable kernel rejects
// the unload of a never-loaded rule with EPERM. A staged rollback must NOT
// attempt that unload — Capture records no unload set on immutable, so Rollback
// removes the drop-in only and reports success. Pre-fix, Capture recorded
// added_rules (rules "not currently loaded") and Rollback called DeleteRule →
// EPERM → false Success=false/PartialRestore=true on a byte-perfect host. The
// earlier test masked it because the fake's DeleteRule succeeded at Enabled==2.
//
// @spec auditnl-rule-set
// @ac AC-07
func TestRollback_Netlink_StagedNoFalseUnloadFailure(t *testing.T) {
	t.Run("auditnl-rule-set/AC-07", func(t *testing.T) {})
	f := auditnl.NewFakeAudit()
	f.Enabled = 2                                       // immutable
	f.DeleteErr = errors.New("operation not permitted") // immutable kernel rejects unload
	h := auditruleset.New()
	params := api.Params{"rule": ruleLine}

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	rb, err := h.Rollback(context.Background(), f, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !rb.Success || rb.PartialRestore {
		t.Errorf("staged rollback on an immutable kernel must succeed without an unload; got Success=%v Partial=%v detail=%q",
			rb.Success, rb.PartialRestore, rb.Detail)
	}
	if _, ok := f.Files[auditPath]; ok {
		t.Error("staged rollback should have removed the drop-in")
	}
}

// Shell path: an immutable audit config (auditctl -s reports enabled 2) stages
// the drop-in and returns Success:true, Staged:true.
//
// @spec auditnl-rule-set
// @ac AC-07
func TestApply_Shell_StagedWhenImmutable(t *testing.T) {
	t.Run("auditnl-rule-set/AC-07", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{Stdout: "enabled 2\nfailure 1\n"}
	res, err := auditruleset.New().Apply(context.Background(), tp,
		api.Params{"rule": ruleLine}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success || !res.Staged {
		t.Fatalf("want Success=true Staged=true on immutable shell; got Success=%v Staged=%v detail=%q",
			res.Success, res.Staged, res.Detail)
	}
}
