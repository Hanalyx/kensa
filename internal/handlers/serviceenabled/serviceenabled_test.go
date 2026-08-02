package serviceenabled_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/serviceenabled"
)

// @spec handler-service-enabled
// @ac AC-01
func TestApply_AC01_RunsEnableNow(t *testing.T) {
	t.Log("// @spec handler-service-enabled")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := serviceenabled.New()
	res, err := h.Apply(context.Background(), tp, api.Params{"name": "auditd"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "systemctl enable --now 'auditd'") {
		t.Errorf("got cmd %q, want systemctl enable --now", tp.Runs[0])
	}
}

// @spec handler-service-enabled
// @ac AC-02
func TestApply_AC02_IsIdempotent(t *testing.T) {
	t.Log("// @spec handler-service-enabled")
	t.Log("// @ac AC-02")
	tp := engine.NewFakeTransport()
	h := serviceenabled.New()
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, api.Params{"name": "sshd"}, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d failed: err=%v success=%v", i+1, err, res.Success)
		}
	}
	if len(tp.Runs) != 3 {
		t.Errorf("got %d Run calls, want 3", len(tp.Runs))
	}
}

// @spec handler-service-enabled
// @ac AC-03
func TestCapture_AC03_RecordsEnabledAndActive(t *testing.T) {
	t.Log("// @spec handler-service-enabled")
	t.Log("// @ac AC-03")
	tp := engine.NewFakeTransport()
	tp.Results["systemctl show -p UnitFileState -p ActiveState 'auditd'"] =
		// REAL systemd output: ActiveState prints first, in key=value form.
		// A fixture in the requested order hid an inverted capture for three
		// releases — see servicedbus.ParseUnitState.
		&api.CommandResult{Stdout: "ActiveState=active\nUnitFileState=enabled\n"}

	h := serviceenabled.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "auditd"})
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

// @spec handler-service-enabled
// @ac AC-04
func TestRollback_AC04_DisablesAndStopsWhenPriorWasInactive(t *testing.T) {
	t.Log("// @spec handler-service-enabled")
	t.Log("// @ac AC-04")
	tp := engine.NewFakeTransport()
	h := serviceenabled.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "kdump",
			"prior_enabled": "disabled",
			"prior_active":  "inactive",
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
	if !strings.Contains(cmd, "systemctl disable 'kdump'") {
		t.Errorf("expected disable; got %q", cmd)
	}
	if !strings.Contains(cmd, "systemctl stop 'kdump'") {
		t.Errorf("expected stop; got %q", cmd)
	}
}

// @spec handler-service-enabled
// @ac AC-05
func TestRollback_AC05_NoOpWhenAlreadyEnabledAndActive(t *testing.T) {
	t.Log("// @spec handler-service-enabled")
	t.Log("// @ac AC-05")
	tp := engine.NewFakeTransport()
	h := serviceenabled.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "auditd",
			"prior_enabled": "enabled",
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
	if len(tp.Runs) != 0 {
		t.Errorf("got %d Run calls, want 0 (no-op rollback)", len(tp.Runs))
	}
}

// @spec handler-service-enabled
// @ac AC-06
func TestApply_AC06_FailsCleanlyOnNonexistentUnit(t *testing.T) {
	t.Log("// @spec handler-service-enabled")
	t.Log("// @ac AC-06")
	tp := engine.NewFakeTransport()
	tp.Results["systemctl enable --now 'nonexistent-unit'"] = &api.CommandResult{
		ExitCode: 5,
		Stderr:   "Failed to enable unit: Unit file nonexistent-unit.service does not exist.",
	}
	h := serviceenabled.New()
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

// Static units (e.g. systemd-tmpfiles-setup.service) cannot be
// enable-disabled, so rollback skips the enable layer for them.
func TestRollback_StaticUnit_OnlyHandlesActiveLayer(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := serviceenabled.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "systemd-tmpfiles-setup",
			"prior_enabled": "static",
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
		t.Fatalf("got %d Run calls, want 1 (stop only)", len(tp.Runs))
	}
	if strings.Contains(tp.Runs[0], "disable") {
		t.Errorf("static unit should not be disabled; got %q", tp.Runs[0])
	}
	if !strings.Contains(tp.Runs[0], "stop") {
		t.Errorf("expected stop for inactive prior_active; got %q", tp.Runs[0])
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = serviceenabled.New()
}

// TestRollbackDoesNotDisableAHealthyUnit is the end-to-end regression for
// the inverted shell-path capture, and it fails against the previous
// implementation.
//
// Real `systemctl show` output puts ActiveState first. The old positional
// parser therefore recorded prior_enabled="active" and prior_active=
// "enabled" for a unit that was enabled and running. On rollback,
// "active" matched no known enable state and fell through to the disable
// branch, and "enabled" was not "active" so the stop branch fired too:
// rolling back a no-op remediation ran `systemctl disable && systemctl
// stop` against a healthy unit and reported Success. On sshd that is a
// remote lockout; on auditd or firewalld it is a silent security
// regression.
//
// The assertion is on the COMMANDS actually issued, not on the pre-state
// keys, so it stays honest if the capture shape changes again.
//
// @spec service-unit-state-parse
// @ac AC-04
func TestRollbackDoesNotDisableAHealthyUnit(t *testing.T) {
	t.Run("service-unit-state-parse/AC-04", func(t *testing.T) {})

	tp := engine.NewFakeTransport()
	// Real systemd output for an enabled, running unit.
	tp.Results["systemctl show -p UnitFileState -p ActiveState 'auditd'"] =
		&api.CommandResult{Stdout: "ActiveState=active\nUnitFileState=enabled\n"}

	h := serviceenabled.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "auditd"})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if got := pre.Data["prior_enabled"]; got != "enabled" {
		t.Errorf("prior_enabled = %v, want enabled (values read positionally?)", got)
	}
	if got := pre.Data["prior_active"]; got != "active" {
		t.Errorf("prior_active = %v, want active (values read positionally?)", got)
	}

	before := len(tp.Runs)
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Rollback reported failure: %s", res.Detail)
	}
	// Restoring an enabled+active unit may legitimately enable, start, or
	// unmask it. It must never disable, stop, or mask it — those are the
	// commands the inverted capture produced.
	for _, cmd := range tp.Runs[before:] {
		for _, destructive := range []string{"systemctl disable", "systemctl stop", "systemctl mask"} {
			if strings.Contains(cmd, destructive) {
				t.Errorf("rollback of an enabled+active unit ran %q: %q", destructive, cmd)
			}
		}
	}
}
