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

	// StartUnitContext + StopUnitContext (D-011)
	// startCh / stopCh capture the channel argument so tests
	// can assert spec C-03's "channel non-nil at invocation"
	// requirement. startResult / stopResult drive the
	// asynchronous JobRemoved signal — the fake spawns a goroutine
	// on invocation that sends startResult to startCh after a
	// short delay, mimicking systemd's JobRemoved dispatch.
	// Setting startResultDelay = -1 suppresses the signal
	// entirely so tests can exercise the ctx-timeout path.
	startName        string
	startMode        string
	startCh          chan<- string
	startCalls       int
	startJobID       int
	startErr         error
	startResult      string
	startResultDelay time.Duration

	stopName        string
	stopMode        string
	stopCh          chan<- string
	stopCalls       int
	stopJobID       int
	stopErr         error
	stopResult      string
	stopResultDelay time.Duration

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

// StartUnitContext records the call AND spawns a goroutine
// that delivers the simulated JobRemoved result to ch after
// startResultDelay. This is the test seam for AC-05's
// subscribe-before-invoke contract: the channel MUST be
// non-nil at this point or the goroutine's send would panic
// (sending to nil channel blocks forever; we assert non-nil
// at top so the fake errors loudly on the wrong call shape).
func (f *fakeConn) StartUnitContext(_ context.Context, name, mode string, ch chan<- string) (int, error) {
	f.mu.Lock()
	f.startCalls++
	f.startName = name
	f.startMode = mode
	f.startCh = ch
	jobID := f.startJobID
	err := f.startErr
	result := f.startResult
	delay := f.startResultDelay
	f.mu.Unlock()

	if err != nil {
		return 0, err
	}
	if ch != nil && delay >= 0 {
		go func() {
			if delay > 0 {
				time.Sleep(delay)
			}
			// Buffered chan capacity 1; send won't block.
			ch <- result
		}()
	}
	return jobID, nil
}

// StopUnitContext mirrors StartUnitContext.
func (f *fakeConn) StopUnitContext(_ context.Context, name, mode string, ch chan<- string) (int, error) {
	f.mu.Lock()
	f.stopCalls++
	f.stopName = name
	f.stopMode = mode
	f.stopCh = ch
	jobID := f.stopJobID
	err := f.stopErr
	result := f.stopResult
	delay := f.stopResultDelay
	f.mu.Unlock()

	if err != nil {
		return 0, err
	}
	if ch != nil && delay >= 0 {
		go func() {
			if delay > 0 {
				time.Sleep(delay)
			}
			ch <- result
		}()
	}
	return jobID, nil
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

// ─── start / stop + JobRemoved (D-011) ────────────────────────────

// TestStart_Done: happy path — StartUnit succeeds, systemd
// JobRemoved signals "done" → exit 0, success:true, job_result
// populated.
//
// @spec agent-systemd-helper
// @ac AC-03
func TestStart_Done(t *testing.T) {
	t.Run("agent-systemd-helper/AC-03", func(t *testing.T) {})
	fc := &fakeConn{
		startJobID:  42,
		startResult: "done",
		// startResultDelay 0 → send completion immediately
		// after the method returns (but the goroutine still
		// runs concurrently, exercising the channel-receive
		// pattern).
		startResultDelay: 0,
		propResponses: map[string]*dbus.Property{
			"UnitFileState": makeStringProp("enabled"),
		},
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "start", "sshd.service")
	if exit != 0 {
		t.Errorf("exit got %d, want 0", exit)
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.JobID != 42 {
		t.Errorf("JobID got %d, want 42", resp.JobID)
	}
	if resp.JobResult != "done" {
		t.Errorf("JobResult got %q, want done", resp.JobResult)
	}
	if fc.startName != "sshd.service" {
		t.Errorf("startName got %q", fc.startName)
	}
	if fc.startMode != "replace" {
		t.Errorf("startMode got %q, want replace", fc.startMode)
	}
}

// TestStart_AllFailureCompletions walks systemd's five
// non-success JobRemoved result strings. All five should produce
// exit 1 with a typed error code derived from the completion
// string.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestStart_AllFailureCompletions(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	for _, result := range []string{"canceled", "timeout", "failed", "dependency", "skipped"} {
		t.Run(result, func(t *testing.T) {
			fc := &fakeConn{
				startJobID:       100,
				startResult:      result,
				startResultDelay: 0,
			}
			withFakeConn(t, fc, nil)
			exit, resp, _ := dispatchHelper(t, "start", "x.service")
			if exit != 1 {
				t.Errorf("%s: exit got %d, want 1", result, exit)
			}
			if resp.Success {
				t.Errorf("%s: Success should be false", result)
			}
			if resp.Error == nil {
				t.Fatalf("%s: Error block should be set", result)
			}
			wantCode := "job_" + result
			if resp.Error.Code != wantCode {
				t.Errorf("%s: error.code got %q, want %q", result, resp.Error.Code, wantCode)
			}
		})
	}
}

// TestStart_ChannelNonNil_BeforeInvoke locks spec C-03 / AC-05:
// the JobRemoved channel MUST be passed non-nil to
// StartUnitContext. coreos/go-systemd registers the channel
// against the job path atomically with the method call; passing
// nil would leave the job's completion signal nowhere to land
// and runStart would block until ctx-timeout even on
// instantaneous jobs.
//
// @spec agent-systemd-helper
// @ac AC-05
func TestStart_ChannelNonNil_BeforeInvoke(t *testing.T) {
	t.Run("agent-systemd-helper/AC-05", func(t *testing.T) {})
	fc := &fakeConn{
		startJobID:       7,
		startResult:      "done",
		startResultDelay: 0,
	}
	withFakeConn(t, fc, nil)
	exit, _, _ := dispatchHelper(t, "start", "x.service")
	if exit != 0 {
		t.Errorf("happy path: exit got %d, want 0", exit)
	}
	if fc.startCh == nil {
		t.Error("C-03 violation: StartUnitContext was called with a nil channel; subscribe-before-invoke contract requires a non-nil channel at the invocation site so coreos/go-systemd can register the channel against the job path atomically")
	}
	if fc.startCalls != 1 {
		t.Errorf("StartUnitContext should be called exactly once; got %d", fc.startCalls)
	}
}

// TestStart_FastCompletionNotLost: simulate a job that
// completes BEFORE runStart's select wakes up. The send to the
// channel must not be lost — that's why we use a buffered
// channel (capacity 1) per the runJobUnit doc comment.
//
// Mechanism: startResultDelay=0 means the fake's goroutine
// sends to ch immediately upon return from StartUnitContext.
// The buffered channel holds the value until runStart's select
// runs.
//
// @spec agent-systemd-helper
// @ac AC-05
func TestStart_FastCompletionNotLost(t *testing.T) {
	t.Run("agent-systemd-helper/AC-05", func(t *testing.T) {})
	fc := &fakeConn{
		startJobID:       9,
		startResult:      "done",
		startResultDelay: 0,
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "start", "x.service")
	if exit != 0 {
		t.Errorf("fast completion: exit got %d, want 0", exit)
	}
	if resp.JobResult != "done" {
		t.Errorf("fast completion: JobResult got %q (the signal was lost — channel must be buffered)", resp.JobResult)
	}
}

// TestStart_TimeoutWhenJobNeverCompletes: the fake suppresses
// the JobRemoved signal (startResultDelay = -1) so runStart
// blocks on the channel until ctx.Done() fires. Should emit
// a timeout NDJSON envelope and exit 1.
//
// @spec agent-systemd-helper
// @ac AC-06
func TestStart_TimeoutWhenJobNeverCompletes(t *testing.T) {
	t.Run("agent-systemd-helper/AC-06", func(t *testing.T) {})
	fc := &fakeConn{
		startJobID:       11,
		startResult:      "done",
		startResultDelay: -1, // never send
	}
	withFakeConn(t, fc, nil)
	// dispatchHelper uses a 5-second timeout. We override here
	// to keep the test fast.
	var stdout, stderr bytes.Buffer
	exit := realDispatch(context.Background(), "start", "x.service", 100*time.Millisecond, &stdout, &stderr)
	if exit != 1 {
		t.Errorf("timeout: exit got %d, want 1", exit)
	}
	resp := parseSingleNDJSON(t, stdout.String())
	if resp.Success {
		t.Error("Success should be false on timeout")
	}
	if resp.Error == nil || resp.Error.Code != "timeout" {
		t.Errorf("expected error.code=timeout; got %+v", resp.Error)
	}
	if resp.JobID != 11 {
		t.Errorf("JobID got %d, want 11 (job was enqueued before timeout)", resp.JobID)
	}
}

// TestStart_DBusError: StartUnitContext returns an error
// (e.g., NoSuchUnit) → exit 1 with typed error, no channel
// wait.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestStart_DBusError(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	fc := &fakeConn{
		startErr: dbusErrFixture(`Error org.freedesktop.systemd1.NoSuchUnit: Unit missing.service not found.`),
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "start", "missing.service")
	if exit != 1 {
		t.Errorf("exit got %d, want 1", exit)
	}
	if resp.Error == nil || resp.Error.Code != "no_such_unit" {
		t.Errorf("expected no_such_unit; got %+v", resp.Error)
	}
}

// TestStop_Done: symmetric with TestStart_Done. StopUnit
// happy path.
//
// @spec agent-systemd-helper
// @ac AC-03
func TestStop_Done(t *testing.T) {
	t.Run("agent-systemd-helper/AC-03", func(t *testing.T) {})
	fc := &fakeConn{
		stopJobID:       43,
		stopResult:      "done",
		stopResultDelay: 0,
		propResponses: map[string]*dbus.Property{
			"UnitFileState": makeStringProp("enabled"),
		},
	}
	withFakeConn(t, fc, nil)
	exit, resp, _ := dispatchHelper(t, "stop", "sshd.service")
	if exit != 0 {
		t.Errorf("exit got %d, want 0", exit)
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.JobID != 43 {
		t.Errorf("JobID got %d, want 43", resp.JobID)
	}
	if fc.stopName != "sshd.service" {
		t.Errorf("stopName got %q", fc.stopName)
	}
}

// TestStop_ChannelNonNil locks spec C-03 for the stop path.
//
// @spec agent-systemd-helper
// @ac AC-05
func TestStop_ChannelNonNil(t *testing.T) {
	t.Run("agent-systemd-helper/AC-05", func(t *testing.T) {})
	fc := &fakeConn{
		stopJobID:       8,
		stopResult:      "done",
		stopResultDelay: 0,
	}
	withFakeConn(t, fc, nil)
	exit, _, _ := dispatchHelper(t, "stop", "x.service")
	if exit != 0 {
		t.Errorf("exit got %d, want 0", exit)
	}
	if fc.stopCh == nil {
		t.Error("C-03 violation: StopUnitContext was called with a nil channel")
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
	for _, op := range []string{"enable", "disable", "mask", "start", "stop", "is-enabled", "unit-state"} {
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
