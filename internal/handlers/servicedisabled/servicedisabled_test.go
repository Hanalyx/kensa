package servicedisabled_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/servicedisabled"
)

// @spec handler-service-disabled
// @ac AC-01
func TestApply_AC01_RunsDisableNow(t *testing.T) {
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-01")
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
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-02")
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
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-03")
	tp := engine.NewFakeTransport()
	tp.Results["systemctl show -p UnitFileState -p ActiveState 'bluetooth'"] =
		// REAL systemd output: ActiveState prints first, in key=value form.
		// A fixture in the requested order hid an inverted capture for three
		// releases — see servicedbus.ParseUnitState.
		&api.CommandResult{Stdout: "ActiveState=active\nUnitFileState=enabled\n"}

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
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-04")
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
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-05")
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
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-06")
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

// Rollback of a unit that was enabled but NOT running must re-enable it and
// leave it stopped.
//
// The test previously asserted `enable --now` here, with a comment
// explaining that --now "starts as well; no separate start command needed" —
// which is exactly the defect: --now starts a unit whose captured state was
// inactive, so rolling back a disable left a daemon running that the host
// was not running, while the RollbackResult reported active=inactive. The
// test asserted the implementation's assumption rather than the restoration
// contract, so it passed while the handler over-restored.
//
// @spec handler-service-disabled
// @ac AC-05
func TestRollback_EnabledButInactive_OnlyEnables(t *testing.T) {
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-05")

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
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1: %v", len(tp.Runs), tp.Runs)
	}
	if !strings.Contains(tp.Runs[0], "systemctl enable ") {
		t.Errorf("expected a plain enable; got %q", tp.Runs[0])
	}
	// The unit was not running when Kensa captured it. Starting it would
	// restore a state the host was never in.
	if strings.Contains(tp.Runs[0], "--now") || strings.Contains(tp.Runs[0], "start") {
		t.Errorf("rollback started a unit captured as inactive: %q", tp.Runs[0])
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
	tp.Results["systemctl show -p UnitFileState -p ActiveState 'bluetooth'"] =
		&api.CommandResult{Stdout: "ActiveState=active\nUnitFileState=enabled\n"}

	h := servicedisabled.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "bluetooth"})
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

// TestRollback_AC07_EnabledButInactiveIsNotStarted is the case that requires
// the enable and active layers to be restored independently.
//
// A unit recorded as enabled but NOT running must come back enabled and still
// stopped. Collapsing both layers onto `systemctl enable --now` — which the
// handler did, and which AC-04 asserted unqualified — starts a service the host
// had stopped, and reports it as restored.
//
// @spec handler-service-disabled
// @ac AC-07
func TestRollback_AC07_EnabledButInactiveIsNotStarted(t *testing.T) {
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-07")
	tp := engine.NewFakeTransport()
	h := servicedisabled.New()
	res, err := h.Rollback(context.Background(), tp, &api.PreState{
		Data: map[string]interface{}{
			"name":          "cups",
			"prior_enabled": "enabled",
			"prior_active":  "inactive",
		},
	})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	joined := strings.Join(tp.Runs, " ; ")
	if !strings.Contains(joined, "enable") {
		t.Errorf("the enable layer was not restored: %q", joined)
	}
	if strings.Contains(joined, "--now") || strings.Contains(joined, "start") {
		t.Errorf("started a unit that was captured as stopped: %q", joined)
	}
}
