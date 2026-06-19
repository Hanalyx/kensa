package serviceenabled_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
	"github.com/Hanalyx/kensa/internal/handlers/servicedbus"
	"github.com/Hanalyx/kensa/internal/handlers/serviceenabled"
)

// D-Bus path: Apply issues enable then start.
//
// @spec service-dbus-consumption
// @ac AC-03
func TestApply_DBus_EnableThenStart(t *testing.T) {
	t.Run("service-dbus-consumption/AC-03", func(t *testing.T) {})
	f := servicedbus.NewFake()
	res, err := serviceenabled.New().Apply(context.Background(), f, api.Params{"name": "auditd"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	if want := []string{"enable", "start"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}

// D-Bus path: a HelperError on enable → failed StepResult, no Go error.
//
// @spec service-dbus-consumption
// @ac AC-03
func TestApply_DBus_HelperErrorIsFailedStep(t *testing.T) {
	t.Run("service-dbus-consumption/AC-03", func(t *testing.T) {})
	f := servicedbus.NewFake()
	f.Err["enable"] = &systemd.HelperError{Op: "enable", Code: "access_denied"}
	res, err := serviceenabled.New().Apply(context.Background(), f, api.Params{"name": "auditd"}, nil)
	if err != nil {
		t.Fatalf("HelperError must not return a Go error; got %v", err)
	}
	if res.Success {
		t.Error("want Success:false on helper refusal")
	}
	// start must not be attempted after enable failed.
	if want := []string{"enable"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v (no start after failed enable)", f.Calls, want)
	}
}

// D-Bus path: Rollback restores prior (disabled, inactive) via disable + stop.
//
// @spec service-dbus-consumption
// @ac AC-03
func TestRollback_DBus_RestoresDisabledInactive(t *testing.T) {
	t.Run("service-dbus-consumption/AC-03", func(t *testing.T) {})
	f := servicedbus.NewFake()
	pre := servicedbus.PreState("service_enabled", "auditd", "disabled", "inactive")
	res, err := serviceenabled.New().Rollback(context.Background(), f, pre)
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, res.Success)
	}
	if want := []string{"disable", "stop"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}

// D-Bus path: a prior masked state rolls back via mask.
//
// @spec service-dbus-consumption
// @ac AC-03
func TestRollback_DBus_RestoresMasked(t *testing.T) {
	t.Run("service-dbus-consumption/AC-03", func(t *testing.T) {})
	f := servicedbus.NewFake()
	pre := servicedbus.PreState("service_enabled", "cups", "masked", "active")
	res, err := serviceenabled.New().Rollback(context.Background(), f, pre)
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, res.Success)
	}
	// masked enable-layer → mask; prior active → no stop.
	if want := []string{"mask"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}

// Fallback: ErrHelperNotFound on the D-Bus path → shell-out.
//
// @spec service-dbus-consumption
// @ac AC-06
func TestApply_DBus_FallsBackWhenHelperMissing(t *testing.T) {
	t.Run("service-dbus-consumption/AC-06", func(t *testing.T) {})
	f := servicedbus.NewFake()
	f.Err["enable"] = fmt.Errorf("%w at /usr/libexec/kensa-systemd-helper", systemd.ErrHelperNotFound)
	res, err := serviceenabled.New().Apply(context.Background(), f, api.Params{"name": "auditd"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("fallback Apply: err=%v success=%v", err, res.Success)
	}
	if len(f.Runs) != 1 || !strings.Contains(f.Runs[0], "systemctl enable --now 'auditd'") {
		t.Errorf("expected shell fallback; Runs=%v", f.Runs)
	}
}

// Fallback: Capture falls back to shell when the helper is missing.
//
// @spec service-dbus-consumption
// @ac AC-06
func TestCapture_DBus_FallsBackWhenHelperMissing(t *testing.T) {
	t.Run("service-dbus-consumption/AC-06", func(t *testing.T) {})
	f := servicedbus.NewFake()
	f.Err["unit-state"] = fmt.Errorf("%w at /x", systemd.ErrHelperNotFound)
	f.RunResults["systemctl show -p UnitFileState -p ActiveState --value 'auditd'"] =
		&api.CommandResult{Stdout: "enabled\nactive\n"}
	pre, err := serviceenabled.New().Capture(context.Background(), f, api.Params{"name": "auditd"})
	if err != nil {
		t.Fatalf("fallback Capture: %v", err)
	}
	if pre.Data["prior_enabled"] != "enabled" || pre.Data["prior_active"] != "active" {
		t.Errorf("fallback capture data = %+v", pre.Data)
	}
}
