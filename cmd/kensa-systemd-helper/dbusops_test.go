// Tests for the helper's D-Bus operations. Uses a fake
// systemdConn so the test path runs without a real dbus socket
// or systemd. D-008 deliverable.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

// fakeConn is a recordable in-memory systemdConn. Tests stuff
// canned responses into the per-method fields and assert on the
// captured argv after dispatch().
type fakeConn struct {
	mu sync.Mutex

	// EnableUnitFiles
	enableUnits   []string
	enableRuntime bool
	enableForce   bool
	enableInstall bool
	enableChanges []dbus.EnableUnitFileChange
	enableErr     error
	enableCalls   int

	// DisableUnitFiles
	disableUnits   []string
	disableRuntime bool
	disableChanges []dbus.DisableUnitFileChange
	disableErr     error
	disableCalls   int

	// MaskUnitFiles
	maskUnits   []string
	maskRuntime bool
	maskForce   bool
	maskChanges []dbus.MaskUnitFileChange
	maskErr     error
	maskCalls   int

	// GetUnitPropertyContext
	propResponses map[string]*dbus.Property
	propErr       error
	propCalls     []propCall

	// GetUnitPropertiesContext
	allProps      map[string]any
	allPropsErr   error
	allPropsCalls int

	closed bool
}

type propCall struct {
	Unit string
	Name string
}

// dbusErrFixture wraps a D-Bus wire-format error string as a
// Go error. Used by tests that need the fixture string to match
// the format coreos/go-systemd produces byte-for-byte. The
// stdlib errors.New constructor would trip revive's
// error-strings lint (no capital letter, no trailing period),
// but those properties are exactly what makes the fixture
// realistic — D-Bus error strings DO start with "Error " and
// DO end with a period.
type dbusFixtureErr struct{ msg string }

func (e *dbusFixtureErr) Error() string { return e.msg }

func dbusErrFixture(msg string) error { return &dbusFixtureErr{msg: msg} }

func (f *fakeConn) EnableUnitFilesContext(_ context.Context, files []string, runtime, force bool) (bool, []dbus.EnableUnitFileChange, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableCalls++
	f.enableUnits = append([]string(nil), files...)
	f.enableRuntime = runtime
	f.enableForce = force
	return f.enableInstall, f.enableChanges, f.enableErr
}

func (f *fakeConn) DisableUnitFilesContext(_ context.Context, files []string, runtime bool) ([]dbus.DisableUnitFileChange, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disableCalls++
	f.disableUnits = append([]string(nil), files...)
	f.disableRuntime = runtime
	return f.disableChanges, f.disableErr
}

func (f *fakeConn) MaskUnitFilesContext(_ context.Context, files []string, runtime, force bool) ([]dbus.MaskUnitFileChange, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maskCalls++
	f.maskUnits = append([]string(nil), files...)
	f.maskRuntime = runtime
	f.maskForce = force
	return f.maskChanges, f.maskErr
}

func (f *fakeConn) GetUnitPropertyContext(_ context.Context, unit, name string) (*dbus.Property, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.propCalls = append(f.propCalls, propCall{Unit: unit, Name: name})
	if f.propErr != nil {
		return nil, f.propErr
	}
	return f.propResponses[name], nil
}

func (f *fakeConn) GetUnitPropertiesContext(_ context.Context, _ string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allPropsCalls++
	if f.allPropsErr != nil {
		return nil, f.allPropsErr
	}
	return f.allProps, nil
}

func (f *fakeConn) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

// withFakeConn installs a fake conn for the duration of the
// test. Restores the production factory in cleanup so other
// tests in this package aren't poisoned.
func withFakeConn(t *testing.T, fc *fakeConn, openErr error) {
	t.Helper()
	prev := connFactoryHook
	connFactoryHook = func(_ context.Context) (systemdConn, error) {
		if openErr != nil {
			return nil, openErr
		}
		return fc, nil
	}
	t.Cleanup(func() { connFactoryHook = prev })
}

// makeStringProp builds a *dbus.Property carrying a string
// value. The systemd D-Bus library exposes properties as
// godbus.Variant-wrapped values; this helper constructs the
// shape the production code reads.
func makeStringProp(s string) *dbus.Property {
	return &dbus.Property{
		Name:  "UnitFileState",
		Value: godbus.MakeVariant(s),
	}
}

// dispatchHelper is the test driver: runs realDispatch with the
// supplied op + unit, captures stdout/stderr, returns the parsed
// NDJSON response + exit code.
func dispatchHelper(t *testing.T, op, unit string) (int, *response, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := realDispatch(context.Background(), op, unit, 5*time.Second, &stdout, &stderr)
	resp := parseSingleNDJSON(t, stdout.String())
	return exit, resp, stderr.String()
}

func parseSingleNDJSON(t *testing.T, s string) *response {
	t.Helper()
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected exactly one NDJSON line; got %d:\n%s", len(lines), s)
	}
	var r response
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatalf("unmarshal %q: %v", lines[0], err)
	}
	return &r
}

// ─── enable ───────────────────────────────────────────────────────

// TestEnable_HappyPath: EnableUnitFiles succeeds + UnitFileState
// reads back "enabled" → exit 0, success:true, populated changes.
//
// @spec agent-systemd-helper
// @ac AC-03
func TestEnable_HappyPath(t *testing.T) {
	t.Run("agent-systemd-helper/AC-03", func(t *testing.T) {})
	fc := &fakeConn{
		enableChanges: []dbus.EnableUnitFileChange{
			{Type: "symlink", Filename: "/etc/systemd/system/multi-user.target.wants/sshd.service", Destination: "/usr/lib/systemd/system/sshd.service"},
		},
		propResponses: map[string]*dbus.Property{
			"UnitFileState": makeStringProp("enabled"),
		},
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "enable", "sshd.service")
	if exit != 0 {
		t.Errorf("exit got %d, want 0", exit)
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.SettledState != "enabled" {
		t.Errorf("SettledState got %q, want enabled", resp.SettledState)
	}
	if len(resp.Changes) != 1 {
		t.Fatalf("Changes len got %d, want 1", len(resp.Changes))
	}
	if resp.Changes[0].Type != "symlink" {
		t.Errorf("Changes[0].Type got %q, want symlink", resp.Changes[0].Type)
	}
	if fc.enableUnits[0] != "sshd.service" {
		t.Errorf("enable called with %q, want sshd.service", fc.enableUnits[0])
	}
	if fc.enableRuntime {
		t.Error("runtime should be false (persistent enable, not /run)")
	}
	if !fc.enableForce {
		t.Error("force should be true")
	}
	if !fc.closed {
		t.Error("conn.Close should have been called")
	}
}

// TestEnable_DBusError: EnableUnitFiles fails → exit 1 with
// typed error code.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestEnable_DBusError(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	fc := &fakeConn{
		// The literal string mirrors the format coreos/go-systemd
		// produces when systemd D-Bus returns an error. We're
		// testing the parser that handles this format, so the
		// fixture must match the wire format byte-for-byte —
		// revive's error-strings rule (no capital letters, no
		// trailing period) doesn't apply to wire-format fixtures.
		enableErr: dbusErrFixture(`Error org.freedesktop.systemd1.NoSuchUnit: Unit foo.service not found.`),
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "enable", "foo.service")
	if exit != 1 {
		t.Errorf("exit got %d, want 1", exit)
	}
	if resp.Success {
		t.Error("Success should be false")
	}
	if resp.Error == nil {
		t.Fatal("Error block should be set")
	}
	if resp.Error.Code != "no_such_unit" {
		t.Errorf("error.code got %q, want no_such_unit", resp.Error.Code)
	}
	if resp.Error.DBusName != "org.freedesktop.systemd1.NoSuchUnit" {
		t.Errorf("error.dbus_name got %q", resp.Error.DBusName)
	}
}

// ─── is-enabled ───────────────────────────────────────────────────

// TestIsEnabled_AllValidStates walks the systemd UnitFileState
// enumeration. Non-bad / non-not-found states should exit 0.
//
// @spec agent-systemd-helper
// @ac AC-07
func TestIsEnabled_AllValidStates(t *testing.T) {
	t.Run("agent-systemd-helper/AC-07", func(t *testing.T) {})
	for _, state := range []string{"enabled", "disabled", "masked", "static", "linked", "generated", "enabled-runtime", "transient"} {
		t.Run(state, func(t *testing.T) {
			fc := &fakeConn{
				propResponses: map[string]*dbus.Property{
					"UnitFileState": makeStringProp(state),
				},
			}
			withFakeConn(t, fc, nil)
			exit, resp, _ := dispatchHelper(t, "is-enabled", "x.service")
			if exit != 0 {
				t.Errorf("%s: exit got %d, want 0", state, exit)
			}
			if !resp.Success {
				t.Errorf("%s: Success should be true", state)
			}
			if resp.SettledState != state {
				t.Errorf("%s: SettledState got %q", state, resp.SettledState)
			}
		})
	}
}

// TestIsEnabled_BadAndNotFound: spec AC-07 — bad / not-found
// → exit 1.
//
// @spec agent-systemd-helper
// @ac AC-07
func TestIsEnabled_BadAndNotFound(t *testing.T) {
	t.Run("agent-systemd-helper/AC-07", func(t *testing.T) {})
	for _, state := range []string{"bad", "not-found"} {
		t.Run(state, func(t *testing.T) {
			fc := &fakeConn{
				propResponses: map[string]*dbus.Property{
					"UnitFileState": makeStringProp(state),
				},
			}
			withFakeConn(t, fc, nil)
			exit, resp, _ := dispatchHelper(t, "is-enabled", "x.service")
			if exit != 1 {
				t.Errorf("%s: exit got %d, want 1", state, exit)
			}
			if resp.Success {
				t.Errorf("%s: Success should be false", state)
			}
			if resp.SettledState != state {
				t.Errorf("%s: SettledState got %q", state, resp.SettledState)
			}
		})
	}
}

// TestIsEnabled_EmptyState: GetUnitPropertyContext returns
// nothing useful → treat as not-found (exit 1).
//
// @spec agent-systemd-helper
// @ac AC-07
func TestIsEnabled_EmptyState(t *testing.T) {
	t.Run("agent-systemd-helper/AC-07", func(t *testing.T) {})
	fc := &fakeConn{
		propResponses: map[string]*dbus.Property{}, // no UnitFileState entry
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "is-enabled", "x.service")
	if exit != 1 {
		t.Errorf("exit got %d, want 1", exit)
	}
	if resp.Success {
		t.Error("Success should be false")
	}
	if resp.Error == nil || resp.Error.Code != "unit_state_unknown" {
		t.Errorf("expected unit_state_unknown error; got %+v", resp.Error)
	}
}

// ─── unit-state ───────────────────────────────────────────────────

// TestUnitState_HappyPath: GetUnitPropertiesContext returns a
// rich property map → response carries the full UnitState struct.
//
// @spec agent-systemd-helper
// @ac AC-08
func TestUnitState_HappyPath(t *testing.T) {
	t.Run("agent-systemd-helper/AC-08", func(t *testing.T) {})
	fc := &fakeConn{
		allProps: map[string]any{
			"UnitFileState": "enabled",
			"ActiveState":   "active",
			"SubState":      "running",
			"LoadState":     "loaded",
			"FragmentPath":  "/usr/lib/systemd/system/sshd.service",
			"Wants":         []string{"network.target", "sshd-keygen.target"},
			"Requires":      []string{"basic.target"},
		},
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "unit-state", "sshd.service")
	if exit != 0 {
		t.Errorf("exit got %d, want 0", exit)
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.UnitState == nil {
		t.Fatal("UnitState should be populated")
	}
	if resp.UnitState.UnitFileState != "enabled" {
		t.Errorf("UnitFileState got %q", resp.UnitState.UnitFileState)
	}
	if resp.UnitState.ActiveState != "active" {
		t.Errorf("ActiveState got %q", resp.UnitState.ActiveState)
	}
	if resp.UnitState.SubState != "running" {
		t.Errorf("SubState got %q", resp.UnitState.SubState)
	}
	if resp.UnitState.LoadState != "loaded" {
		t.Errorf("LoadState got %q", resp.UnitState.LoadState)
	}
	if resp.UnitState.FragmentPath != "/usr/lib/systemd/system/sshd.service" {
		t.Errorf("FragmentPath got %q", resp.UnitState.FragmentPath)
	}
	if len(resp.UnitState.UnitFileLinks) != 3 {
		t.Errorf("UnitFileLinks len got %d, want 3 (2 Wants + 1 Requires)", len(resp.UnitState.UnitFileLinks))
	}
	// SettledState mirrors UnitFileState for convenience.
	if resp.SettledState != "enabled" {
		t.Errorf("SettledState got %q (should mirror UnitFileState)", resp.SettledState)
	}
}

// TestUnitState_DBusError: properties fetch fails → exit 1.
//
// @spec agent-systemd-helper
// @ac AC-08
func TestUnitState_DBusError(t *testing.T) {
	t.Run("agent-systemd-helper/AC-08", func(t *testing.T) {})
	fc := &fakeConn{
		allPropsErr: dbusErrFixture(`Error org.freedesktop.systemd1.NoSuchUnit: Unit foo.service not found.`),
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "unit-state", "foo.service")
	if exit != 1 {
		t.Errorf("exit got %d, want 1", exit)
	}
	if resp.Success {
		t.Error("Success should be false")
	}
	if resp.Error == nil || resp.Error.Code != "no_such_unit" {
		t.Errorf("expected no_such_unit error; got %+v", resp.Error)
	}
}

// ─── dbus_unreachable ─────────────────────────────────────────────

// TestDBusUnreachable: connFactoryHook returns an error →
// every subcommand surfaces dbus_unreachable.
//
// @spec agent-systemd-helper
// @ac AC-11
func TestDBusUnreachable(t *testing.T) {
	t.Run("agent-systemd-helper/AC-11", func(t *testing.T) {})
	openErr := errors.New("dial unix /run/dbus/system_bus_socket: no such file or directory")
	for _, op := range []string{"enable", "disable", "mask", "is-enabled", "unit-state"} {
		t.Run(op, func(t *testing.T) {
			withFakeConn(t, nil, openErr)
			exit, resp, _ := dispatchHelper(t, op, "x.service")
			if exit != 1 {
				t.Errorf("%s: exit got %d, want 1", op, exit)
			}
			if resp.Success {
				t.Errorf("%s: Success should be false", op)
			}
			if resp.Error == nil || resp.Error.Code != "dbus_unreachable" {
				t.Errorf("%s: expected dbus_unreachable; got %+v", op, resp.Error)
			}
		})
	}
}

// ─── disable (D-009) ──────────────────────────────────────────────

// TestDisable_HappyPath: DisableUnitFiles succeeds + UnitFileState
// reads back "disabled" → exit 0, success:true, populated changes.
//
// @spec agent-systemd-helper
// @ac AC-03
func TestDisable_HappyPath(t *testing.T) {
	t.Run("agent-systemd-helper/AC-03", func(t *testing.T) {})
	fc := &fakeConn{
		disableChanges: []dbus.DisableUnitFileChange{
			{Type: "unlink", Filename: "/etc/systemd/system/multi-user.target.wants/sshd.service", Destination: "/usr/lib/systemd/system/sshd.service"},
		},
		propResponses: map[string]*dbus.Property{
			"UnitFileState": makeStringProp("disabled"),
		},
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "disable", "sshd.service")
	if exit != 0 {
		t.Errorf("exit got %d, want 0", exit)
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.Op != "disable" {
		t.Errorf("Op got %q, want disable", resp.Op)
	}
	if resp.SettledState != "disabled" {
		t.Errorf("SettledState got %q, want disabled", resp.SettledState)
	}
	if len(resp.Changes) != 1 {
		t.Fatalf("Changes len got %d, want 1", len(resp.Changes))
	}
	if resp.Changes[0].Type != "unlink" {
		t.Errorf("Changes[0].Type got %q, want unlink", resp.Changes[0].Type)
	}
	if fc.disableUnits[0] != "sshd.service" {
		t.Errorf("disable called with %q", fc.disableUnits[0])
	}
	if fc.disableRuntime {
		t.Error("runtime should be false (persistent disable)")
	}
	if fc.disableCalls != 1 {
		t.Errorf("disable should be called once; got %d", fc.disableCalls)
	}
	if !fc.closed {
		t.Error("conn.Close should have been called")
	}
}

// TestDisable_DBusError: DisableUnitFiles fails → exit 1 with
// typed error code.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestDisable_DBusError(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	fc := &fakeConn{
		disableErr: dbusErrFixture(`Error org.freedesktop.systemd1.NoSuchUnit: Unit foo.service not found.`),
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "disable", "foo.service")
	if exit != 1 {
		t.Errorf("exit got %d, want 1", exit)
	}
	if resp.Success {
		t.Error("Success should be false")
	}
	if resp.Error == nil || resp.Error.Code != "no_such_unit" {
		t.Errorf("expected no_such_unit; got %+v", resp.Error)
	}
	if resp.Error.DBusName != "org.freedesktop.systemd1.NoSuchUnit" {
		t.Errorf("dbus_name got %q", resp.Error.DBusName)
	}
}

// ─── mask (D-010) ─────────────────────────────────────────────────

// TestMask_HappyPath: MaskUnitFiles succeeds + UnitFileState
// reads back "masked" → exit 0, success:true, change to
// /dev/null target captured.
//
// @spec agent-systemd-helper
// @ac AC-03
func TestMask_HappyPath(t *testing.T) {
	t.Run("agent-systemd-helper/AC-03", func(t *testing.T) {})
	fc := &fakeConn{
		maskChanges: []dbus.MaskUnitFileChange{
			{Type: "symlink", Filename: "/etc/systemd/system/sshd.service", Destination: "/dev/null"},
		},
		propResponses: map[string]*dbus.Property{
			"UnitFileState": makeStringProp("masked"),
		},
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "mask", "sshd.service")
	if exit != 0 {
		t.Errorf("exit got %d, want 0", exit)
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.Op != "mask" {
		t.Errorf("Op got %q, want mask", resp.Op)
	}
	if resp.SettledState != "masked" {
		t.Errorf("SettledState got %q, want masked", resp.SettledState)
	}
	if len(resp.Changes) != 1 {
		t.Fatalf("Changes len got %d, want 1", len(resp.Changes))
	}
	if resp.Changes[0].Destination != "/dev/null" {
		t.Errorf("mask should point at /dev/null; got %q", resp.Changes[0].Destination)
	}
	if fc.maskUnits[0] != "sshd.service" {
		t.Errorf("mask called with %q", fc.maskUnits[0])
	}
	if !fc.maskForce {
		t.Error("force should be true")
	}
	if fc.maskCalls != 1 {
		t.Errorf("mask should be called once; got %d", fc.maskCalls)
	}
}

// TestMask_DBusError: MaskUnitFiles fails → exit 1 with typed
// error code.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestMask_DBusError(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	fc := &fakeConn{
		maskErr: dbusErrFixture(`Error org.freedesktop.systemd1.AccessDenied: permission denied`),
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "mask", "sshd.service")
	if exit != 1 {
		t.Errorf("exit got %d, want 1", exit)
	}
	if resp.Error == nil || resp.Error.Code != "access_denied" {
		t.Errorf("expected access_denied; got %+v", resp.Error)
	}
}
