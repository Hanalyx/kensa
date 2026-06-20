package servicedbus_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
	"github.com/Hanalyx/kensa/internal/handlers/servicedbus"
)

// TestStep_Outcomes covers the four Step mappings.
//
// @spec service-dbus-consumption
// @ac AC-01
func TestStep_Outcomes(t *testing.T) {
	t.Run("service-dbus-consumption/AC-01", func(t *testing.T) {})

	// success → (nil, nil): caller continues.
	step, err := servicedbus.Step("m", "u", "enable", func() (*systemd.Response, error) {
		return &systemd.Response{Success: true}, nil
	})
	if step != nil || err != nil {
		t.Errorf("success: got (%v, %v), want (nil, nil)", step, err)
	}

	// HelperError → (failed StepResult, nil): terminal, non-error.
	he := &systemd.HelperError{Op: "enable", Unit: "u", Code: "access_denied", Detail: "denied"}
	step, err = servicedbus.Step("m", "u", "enable", func() (*systemd.Response, error) {
		return nil, he
	})
	if err != nil {
		t.Errorf("HelperError must not return a Go error; got %v", err)
	}
	if step == nil || step.Success {
		t.Fatalf("HelperError: want failed StepResult, got %+v", step)
	}
	if step.Detail == "" {
		t.Error("failed StepResult should carry a detail")
	}

	// ErrHelperUnavailable → (nil, err) with errors.Is true: signals fallback.
	step, err = servicedbus.Step("m", "u", "enable", func() (*systemd.Response, error) {
		return nil, fmt.Errorf("%w at /x", systemd.ErrHelperUnavailable)
	})
	if step != nil {
		t.Errorf("ErrHelperUnavailable: step should be nil, got %+v", step)
	}
	if !errors.Is(err, systemd.ErrHelperUnavailable) {
		t.Errorf("ErrHelperUnavailable must propagate for fallback; got %v", err)
	}

	// raw error (not wrapped Unavailable) → terminal, NOT a fallback.
	sentinel := errors.New("exec boom")
	step, err = servicedbus.Step("m", "u", "enable", func() (*systemd.Response, error) {
		return nil, sentinel
	})
	if step != nil {
		t.Errorf("exec error: step should be nil, got %+v", step)
	}
	if err == nil || errors.Is(err, systemd.ErrHelperUnavailable) {
		t.Errorf("raw error should be a non-ErrHelperUnavailable terminal error; got %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("exec error should wrap the underlying error; got %v", err)
	}
}

// TestRollbackFrom covers the propagate-vs-fail mapping.
//
// @spec service-dbus-consumption
// @ac AC-01
func TestRollbackFrom(t *testing.T) {
	t.Run("service-dbus-consumption/AC-01", func(t *testing.T) {})

	// err propagates unchanged (fallback or real error).
	if rr, err := servicedbus.RollbackFrom(nil, systemd.ErrHelperUnavailable); rr != nil || !errors.Is(err, systemd.ErrHelperUnavailable) {
		t.Errorf("RollbackFrom(err): got (%v, %v), want (nil, ErrHelperUnavailable)", rr, err)
	}
	// failed step → Success:false RollbackResult, no error.
	step := &api.StepResult{Success: false, Detail: "mask u failed"}
	rr, err := servicedbus.RollbackFrom(step, nil)
	if err != nil {
		t.Fatalf("RollbackFrom(step): unexpected err %v", err)
	}
	if rr == nil || rr.Success {
		t.Errorf("want failed RollbackResult, got %+v", rr)
	}
	if rr.Detail != step.Detail {
		t.Errorf("detail = %q, want %q", rr.Detail, step.Detail)
	}
}

// TestCapture covers the unit-state projection and its error paths.
//
// @spec service-dbus-consumption
// @ac AC-02
func TestCapture(t *testing.T) {
	t.Run("service-dbus-consumption/AC-02", func(t *testing.T) {})

	// Happy path: UnitFileState/ActiveState → prior_enabled/prior_active.
	f := servicedbus.NewFake()
	f.Resp["unit-state"] = &systemd.Response{
		Success:   true,
		UnitState: &systemd.UnitState{UnitFileState: "enabled", ActiveState: "active"},
	}
	pre, err := servicedbus.Capture(context.Background(), f, "service_enabled", "auditd")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["name"] != "auditd" || pre.Data["prior_enabled"] != "enabled" || pre.Data["prior_active"] != "active" {
		t.Errorf("PreState data = %+v", pre.Data)
	}
	if pre.Mechanism != "service_enabled" || !pre.Capturable {
		t.Errorf("PreState meta = %+v", pre)
	}

	// nil unit_state → ErrCaptureIncomplete.
	f2 := servicedbus.NewFake()
	f2.Resp["unit-state"] = &systemd.Response{Success: true, UnitState: nil}
	if _, err := servicedbus.Capture(context.Background(), f2, "service_enabled", "u"); !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Errorf("nil unit_state: want ErrCaptureIncomplete, got %v", err)
	}

	// HelperError on the unit-state read → ErrCaptureIncomplete.
	f3 := servicedbus.NewFake()
	f3.Err["unit-state"] = &systemd.HelperError{Op: "unit-state", Code: "no_such_unit"}
	if _, err := servicedbus.Capture(context.Background(), f3, "service_enabled", "u"); !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Errorf("HelperError: want ErrCaptureIncomplete, got %v", err)
	}

	// ErrHelperUnavailable propagates for fallback.
	f4 := servicedbus.NewFake()
	f4.Err["unit-state"] = fmt.Errorf("%w at /x", systemd.ErrHelperUnavailable)
	if _, err := servicedbus.Capture(context.Background(), f4, "service_enabled", "u"); !errors.Is(err, systemd.ErrHelperUnavailable) {
		t.Errorf("ErrHelperUnavailable must propagate; got %v", err)
	}
}
