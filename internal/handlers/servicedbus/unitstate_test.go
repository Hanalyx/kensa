package servicedbus_test

import (
	"testing"

	"github.com/Hanalyx/kensa/internal/handlers/servicedbus"
)

// TestParseUnitStateReadsByPropertyName locks the fix for the inverted
// shell-path capture. The first case is the one that matters: it is real
// output from `systemctl show -p UnitFileState -p ActiveState`, in
// systemd's own property order, and it fails against a positional parser.
//
// @spec service-unit-state-parse
// @ac AC-01
func TestParseUnitStateReadsByPropertyName(t *testing.T) {
	t.Run("service-unit-state-parse/AC-01", func(t *testing.T) {})

	for _, tc := range []struct {
		name        string
		stdout      string
		wantEnabled string
		wantActive  string
	}{{
		// Verified against systemd 249/252/257: ActiveState is printed
		// FIRST, whatever order the properties were requested in.
		name:        "real systemd order",
		stdout:      "ActiveState=active\nUnitFileState=enabled\n",
		wantEnabled: "enabled",
		wantActive:  "active",
	}, {
		name:        "requested order, should read identically",
		stdout:      "UnitFileState=enabled\nActiveState=active\n",
		wantEnabled: "enabled",
		wantActive:  "active",
	}, {
		// The values are each other's plausible neighbors, so a
		// positional parser produces a result that looks valid. This case
		// is why the defect survived review.
		name:        "disabled and inactive",
		stdout:      "ActiveState=inactive\nUnitFileState=disabled\n",
		wantEnabled: "disabled",
		wantActive:  "inactive",
	}, {
		// A unit that does not exist: systemd exits 0 with an empty
		// UnitFileState. Must stay empty, not inherit ActiveState.
		name:        "unknown unit",
		stdout:      "ActiveState=inactive\nUnitFileState=\n",
		wantEnabled: "",
		wantActive:  "inactive",
	}, {
		name:        "static unit",
		stdout:      "ActiveState=active\nUnitFileState=static\n",
		wantEnabled: "static",
		wantActive:  "active",
	}, {
		name:        "masked unit",
		stdout:      "ActiveState=inactive\nUnitFileState=masked\n",
		wantEnabled: "masked",
		wantActive:  "inactive",
	}, {
		// Adding a property to the command later must not shift anything.
		name:        "extra properties present",
		stdout:      "Id=sshd.service\nActiveState=active\nLoadState=loaded\nUnitFileState=enabled\n",
		wantEnabled: "enabled",
		wantActive:  "active",
	}, {
		name:        "only one property returned",
		stdout:      "ActiveState=active\n",
		wantEnabled: "",
		wantActive:  "active",
	}, {
		name:        "empty output",
		stdout:      "",
		wantEnabled: "",
		wantActive:  "",
	}, {
		name:        "no trailing newline",
		stdout:      "ActiveState=active\nUnitFileState=enabled",
		wantEnabled: "enabled",
		wantActive:  "active",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			enabled, active := servicedbus.ParseUnitState(tc.stdout)
			if enabled != tc.wantEnabled {
				t.Errorf("enabled = %q, want %q", enabled, tc.wantEnabled)
			}
			if active != tc.wantActive {
				t.Errorf("active = %q, want %q", active, tc.wantActive)
			}
		})
	}
}

// TestShowUnitStateCmdOmitsValueFlag pins the command shape itself. --value
// is what makes the output positional and unnamed; re-adding it would
// reintroduce the swap without changing the parser, and the parser's own
// tests would still pass.
//
// @spec service-unit-state-parse
// @ac AC-03
func TestShowUnitStateCmdOmitsValueFlag(t *testing.T) {
	t.Run("service-unit-state-parse/AC-03", func(t *testing.T) {})

	got := servicedbus.ShowUnitStateCmd("sshd")
	if want := "systemctl show -p UnitFileState -p ActiveState 'sshd'"; got != want {
		t.Errorf("ShowUnitStateCmd = %q, want %q", got, want)
	}
	if quoted := servicedbus.ShowUnitStateCmd("evil'; rm -rf /"); quoted != `systemctl show -p UnitFileState -p ActiveState 'evil'\''; rm -rf /'` {
		t.Errorf("unit name not shell-escaped: %q", quoted)
	}
}

// TestParseUnitStateToleratesMissingProperties covers what the parser must
// do when the output is not the happy two-property case: a unit that does
// not exist (systemd exits 0 with an empty UnitFileState), a command that
// grew an extra property, and empty output. The requirement that matters is
// negative — a missing property must never inherit a neighboring value,
// which is the failure mode positional reading produced.
//
// @spec service-unit-state-parse
// @ac AC-02
func TestParseUnitStateToleratesMissingProperties(t *testing.T) {
	t.Run("service-unit-state-parse/AC-02", func(t *testing.T) {})

	for _, tc := range []struct {
		name        string
		stdout      string
		wantEnabled string
		wantActive  string
	}{{
		name:        "unknown unit: empty UnitFileState must not inherit ActiveState",
		stdout:      "ActiveState=inactive\nUnitFileState=\n",
		wantEnabled: "",
		wantActive:  "inactive",
	}, {
		name:        "only one property returned",
		stdout:      "ActiveState=active\n",
		wantEnabled: "",
		wantActive:  "active",
	}, {
		name:        "extra properties present",
		stdout:      "Id=sshd.service\nActiveState=active\nLoadState=loaded\nUnitFileState=enabled\n",
		wantEnabled: "enabled",
		wantActive:  "active",
	}, {
		name:        "empty output",
		stdout:      "",
		wantEnabled: "",
		wantActive:  "",
	}, {
		name:        "garbage lines are ignored",
		stdout:      "Failed to get properties\nActiveState=active\nUnitFileState=enabled\n",
		wantEnabled: "enabled",
		wantActive:  "active",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			enabled, active := servicedbus.ParseUnitState(tc.stdout)
			if enabled != tc.wantEnabled {
				t.Errorf("enabled = %q, want %q", enabled, tc.wantEnabled)
			}
			if active != tc.wantActive {
				t.Errorf("active = %q, want %q", active, tc.wantActive)
			}
		})
	}
}
