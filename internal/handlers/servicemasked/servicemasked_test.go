package servicemasked_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/servicemasked"
)

// @spec handler-service-masked
// @ac AC-01
func TestApply_AC01_RunsMaskNow(t *testing.T) {
	t.Log("// @spec handler-service-masked")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := servicemasked.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"name": "cups"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "systemctl mask --now 'cups'") {
		t.Errorf("got cmd %q, want systemctl mask --now", tp.Runs[0])
	}
}

// @spec handler-service-masked
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	t.Log("// @spec handler-service-masked")
	t.Log("// @ac AC-02")
	tp := engine.NewFakeTransport()
	h := servicemasked.New()
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, api.Params{"name": "avahi-daemon"}, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d failed: err=%v success=%v", i+1, err, res.Success)
		}
	}
	if len(tp.Runs) != 3 {
		t.Errorf("got %d Run calls, want 3", len(tp.Runs))
	}
}

// @spec handler-service-masked
// @ac AC-03
func TestCapture_AC03_RecordsBothFields(t *testing.T) {
	t.Log("// @spec handler-service-masked")
	t.Log("// @ac AC-03")
	tp := engine.NewFakeTransport()
	tp.Results["systemctl show -p UnitFileState -p ActiveState --value 'cups'"] =
		&api.CommandResult{Stdout: "enabled\nactive\n"}

	h := servicemasked.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "cups"})
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

// @spec handler-service-masked
// @ac AC-04
func TestRollback_AC04_UnmasksEnablesAndStartsWhenPriorWasEnabledActive(t *testing.T) {
	t.Log("// @spec handler-service-masked")
	t.Log("// @ac AC-04")
	tp := engine.NewFakeTransport()
	h := servicemasked.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "cups",
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
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "systemctl unmask") {
		t.Errorf("expected unmask in rollback cmd; got %q", cmd)
	}
	if !strings.Contains(cmd, "enable --now") {
		t.Errorf("expected enable --now in rollback cmd; got %q", cmd)
	}
}

// @spec handler-service-masked
// @ac AC-05
func TestRollback_AC05_UnmasksOnlyWhenPriorWasMaskedAndInactive(t *testing.T) {
	t.Log("// @spec handler-service-masked")
	t.Log("// @ac AC-05")
	tp := engine.NewFakeTransport()
	h := servicemasked.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "cups",
			"prior_enabled": "masked",
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
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1 (unmask only)", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "unmask") {
		t.Errorf("expected unmask; got %q", cmd)
	}
	if strings.Contains(cmd, "enable") || strings.Contains(cmd, "start") {
		t.Errorf("should not enable or start when prior was masked/inactive; got %q", cmd)
	}
}

// @spec handler-service-masked
// @ac AC-06
func TestApply_AC06_FailsCleanlyOnNonexistentUnit(t *testing.T) {
	t.Log("// @spec handler-service-masked")
	t.Log("// @ac AC-06")
	tp := engine.NewFakeTransport()
	tp.Results["systemctl mask --now 'nonexistent-unit'"] = &api.CommandResult{
		ExitCode: 5,
		Stderr:   "Failed to mask unit: Unit file nonexistent-unit.service does not exist.",
	}
	h := servicemasked.New()
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

// Rollback when prior was disabled but active: unmask + start.
func TestRollback_DisabledButActive_UnmasksAndStarts(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := servicemasked.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "avahi-daemon",
			"prior_enabled": "disabled",
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
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "unmask") {
		t.Errorf("expected unmask; got %q", cmd)
	}
	if !strings.Contains(cmd, "start") {
		t.Errorf("expected start (prior was active); got %q", cmd)
	}
	if strings.Contains(cmd, "enable") {
		t.Errorf("should not enable when prior_enabled=disabled; got %q", cmd)
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = servicemasked.New()
}
