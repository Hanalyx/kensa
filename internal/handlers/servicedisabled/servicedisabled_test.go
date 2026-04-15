package servicedisabled_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/servicedisabled"
)

// @spec handler-service-disabled
// @ac AC-01
func TestApply_AC01_RunsDisableNow(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := servicedisabled.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"name": "bluetooth"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "systemctl disable --now 'bluetooth'") {
		t.Errorf("got cmd %q, want systemctl disable --now", tp.Runs[0])
	}
}

// @spec handler-service-disabled
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := servicedisabled.New()
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, api.Params{"name": "cups"}, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d failed: err=%v success=%v", i+1, err, res.Success)
		}
	}
	if len(tp.Runs) != 3 {
		t.Errorf("got %d Run calls, want 3", len(tp.Runs))
	}
}

// @spec handler-service-disabled
// @ac AC-03
func TestCapture_AC03_RecordsBothFields(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["systemctl show -p UnitFileState -p ActiveState --value 'bluetooth'"] =
		&api.CommandResult{Stdout: "enabled\nactive\n"}

	h := servicedisabled.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "bluetooth"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["prior_enabled"] != "enabled" {
		t.Errorf("prior_enabled=%v, want enabled", pre.Data["prior_enabled"])
	}
	if pre.Data["prior_active"] != "active" {
		t.Errorf("prior_active=%v, want active", pre.Data["prior_active"])
	}
}

// @spec handler-service-disabled
// @ac AC-04
func TestRollback_AC04_ReenablesAndStartsWhenPriorWasEnabled(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := servicedisabled.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "bluetooth",
			"prior_enabled": "enabled",
			"prior_active":  "active",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Fatalf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	// enable --now covers both layers in one command.
	if !strings.Contains(tp.Runs[0], "systemctl enable --now") {
		t.Errorf("expected enable --now; got %q", tp.Runs[0])
	}
}

// @spec handler-service-disabled
// @ac AC-05
func TestRollback_AC05_NoOpWhenPriorWasDisabled(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := servicedisabled.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "cups",
			"prior_enabled": "disabled",
			"prior_active":  "inactive",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 0 {
		t.Errorf("got %d Run calls, want 0 (no-op rollback)", len(tp.Runs))
	}
}

// @spec handler-service-disabled
// @ac AC-06
func TestApply_AC06_FailsCleanlyOnNonexistentUnit(t *testing.T) {
	tp := engine.NewFakeTransport()
	tp.Results["systemctl disable --now 'nonexistent-unit'"] = &api.CommandResult{
		ExitCode: 5,
		Stderr:   "Failed to disable unit: Unit file nonexistent-unit.service does not exist.",
	}
	h := servicedisabled.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"name": "nonexistent-unit"}, nil)
	if err != nil {
		t.Fatalf("Apply transport err: %v", err)
	}
	if res.Success {
		t.Error("expected Success=false")
	}
	if !strings.Contains(res.Detail, "does not exist") {
		t.Errorf("expected detail to include unit-not-found stderr; got %q", res.Detail)
	}
}

// Rollback with prior_enabled=enabled but prior_active=inactive should
// enable without the --now start path issuing a separate start.
func TestRollback_EnabledButInactive_OnlyEnables(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := servicedisabled.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "auditd",
			"prior_enabled": "enabled",
			"prior_active":  "inactive",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// enable --now starts as well; no separate start command needed.
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "enable --now") {
		t.Errorf("expected enable --now; got %q", tp.Runs[0])
	}
}

// Static units cannot be enabled; rollback skips enable layer and only
// handles active layer when prior_active was active.
func TestRollback_StaticUnit_StartsIfWasActive(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := servicedisabled.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "systemd-journald",
			"prior_enabled": "static",
			"prior_active":  "active",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if strings.Contains(tp.Runs[0], "enable") {
		t.Errorf("static unit should not have enable command; got %q", tp.Runs[0])
	}
	if !strings.Contains(tp.Runs[0], "start") {
		t.Errorf("expected start for prior_active=active; got %q", tp.Runs[0])
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = servicedisabled.New()
}
