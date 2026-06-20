// Package servicedbus holds the small set of helpers the three systemd
// service handlers (service_enabled, service_disabled, service_masked)
// share for their D-Bus path: the per-op error mapping, the Capture
// projection, and the standard PreState shape. Centralizing these keeps
// the D-Bus/shell fallback contract identical across the three handlers
// — a divergence here would mean one handler silently behaving
// differently from its siblings.
package servicedbus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
)

// Step runs one D-Bus op and maps the outcome onto the handlers' inline
// idiom `if step, err := Step(...); err != nil || step != nil { return step, err }`:
//
//   - (nil, nil)                  success — the caller continues to the next op.
//   - (nil, ErrHelperUnavailable) the helper could not be invoked (binary
//     absent OR execve denied, e.g. fapolicyd) — the caller propagates this
//     so its public method falls back to the shell path.
//   - (failedStep, nil)        systemd ran but refused (a structured
//     HelperError, e.g. access_denied / no_such_unit / dbus_unreachable)
//     — a terminal, non-error failure, mirroring the shell path's
//     non-zero-exit handling.
//   - (nil, wrappedErr)        an exec/transport-level failure launching
//     the helper — a terminal error.
func Step(mech, name, op string, call func() (*systemd.Response, error)) (*api.StepResult, error) {
	if _, err := call(); err != nil {
		if errors.Is(err, systemd.ErrHelperUnavailable) {
			return nil, err
		}
		var he *systemd.HelperError
		if errors.As(err, &he) {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("%s: %s %s failed: %s", mech, op, name, he),
			}, nil
		}
		return nil, fmt.Errorf("%s: dbus %s %s: %w", mech, op, name, err)
	}
	return nil, nil
}

// RollbackFrom converts a terminal Step outcome encountered mid-rollback
// into the handler's RollbackResult/error pair. err (ErrHelperUnavailable
// or a real exec error) propagates unchanged so the caller can fall back;
// otherwise step is a failed op and becomes a Success:false result.
func RollbackFrom(step *api.StepResult, err error) (*api.RollbackResult, error) {
	if err != nil {
		return nil, err
	}
	return &api.RollbackResult{
		Success:    false,
		Detail:     step.Detail,
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// Capture reads the unit's rich state via the helper's unit-state op and
// projects it onto the standard PreState shape. The captured keys
// (name / prior_enabled / prior_active) are identical to the shell
// path's, so Rollback is path-agnostic. ErrHelperUnavailable propagates so
// the caller falls back to shell capture; a HelperError (the unit-state
// read itself failed) surfaces as ErrCaptureIncomplete.
func Capture(ctx context.Context, sd systemd.Transport, mech, name string) (*api.PreState, error) {
	resp, err := sd.UnitState(ctx, name)
	if err != nil {
		if errors.Is(err, systemd.ErrHelperUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("%s: dbus capture failed for %s: %w (%v)",
			mech, name, api.ErrCaptureIncomplete, err)
	}
	if resp == nil || resp.UnitState == nil {
		return nil, fmt.Errorf("%s: dbus capture for %s: %w (no unit_state in helper response)",
			mech, name, api.ErrCaptureIncomplete)
	}
	return PreState(mech, name, resp.UnitState.UnitFileState, resp.UnitState.ActiveState), nil
}

// PreState builds the canonical service-handler PreState. Both the D-Bus
// and shell capture paths construct it through here so the recorded
// shape never diverges.
func PreState(mech, name, enabled, active string) *api.PreState {
	return &api.PreState{
		Mechanism:  mech,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"name":          name,
			"prior_enabled": enabled,
			"prior_active":  active,
		},
	}
}
