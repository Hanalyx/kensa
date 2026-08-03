package servicemasked_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/servicemasked"
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
	tp.Results["systemctl show -p UnitFileState -p ActiveState 'cups'"] =
		// REAL systemd output: ActiveState prints first, in key=value form.
		// A fixture in the requested order hid an inverted capture for three
		// releases — see servicedbus.ParseUnitState.
		&api.CommandResult{Stdout: "ActiveState=active\nUnitFileState=enabled\n"}

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

// TestRollback_AC05_AlreadyMaskedRestoresNothing
//
// This test previously asserted the opposite, under the name
// "UnmasksOnlyWhenPriorWasMaskedAndInactive": prior_enabled=masked was
// expected to produce `systemctl unmask`. That codified a defect. Apply is
// `mask --now`, so a unit that was ALREADY masked when Kensa captured it was
// not changed by us on the mask layer, and unmasking it during rollback leaves
// the host in a state it was never in -- a restore that mutates. The handler
// reported that as a successful restoration.
//
// It is reachable rather than theoretical. "masked" and "masked-runtime" are
// capturable UnitFileState values, 28 shipped rules use this mechanism, and a
// re-run against an already-hardened host captures exactly this.
//
// @spec handler-service-masked
// @ac AC-05
func TestRollback_AC05_AlreadyMaskedRestoresNothing(t *testing.T) {
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
	if len(tp.Runs) != 0 {
		t.Fatalf("got %d Run calls, want 0: the unit was already masked and inactive, "+
			"so it is exactly where it started; ran %v", len(tp.Runs), tp.Runs)
	}
}

// TestRollback_AC05_AlreadyMaskedButRunningRestartsWithoutUnmasking covers the
// third layer the matrix omitted. `mask --now` also STOPS the unit, so a unit
// that was masked-but-running has one layer to restore (active) and one that
// must be left alone (mask).
//
// @spec handler-service-masked
// @ac AC-05
func TestRollback_AC05_AlreadyMaskedButRunningRestartsWithoutUnmasking(t *testing.T) {
	t.Log("// @spec handler-service-masked")
	t.Log("// @ac AC-05")
	tp := engine.NewFakeTransport()
	h := servicemasked.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"name":          "cups",
			"prior_enabled": "masked",
			"prior_active":  "active",
		},
	}
	if _, err := h.Rollback(context.Background(), tp, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	joined := strings.Join(tp.Runs, " ; ")
	if strings.Contains(joined, "unmask") {
		t.Errorf("unmasked a unit that was already masked at capture: %q", joined)
	}
	if !strings.Contains(joined, "start") {
		t.Errorf("did not restore the running state of a masked-but-active unit: %q", joined)
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
	tp.Results["systemctl show -p UnitFileState -p ActiveState 'cups'"] =
		&api.CommandResult{Stdout: "ActiveState=active\nUnitFileState=enabled\n"}

	h := servicemasked.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{"name": "cups"})
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
