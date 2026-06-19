// D-Bus operations for the systemd helper. Split from main.go
// so the unit-test path can inject a fake systemdConn without
// pulling in the whole helper binary's flag-parsing surface.
//
// D-008 deliverable: lands the real EnableUnitFiles +
// is-enabled (UnitFileState property read) + unit-state (rich
// property bundle for Capture) implementations. AC-05 / C-03
// (JobRemoved subscribe-before-invoke ordering) stays deferred
// — none of these operations create a systemd job, all three
// are synchronous in systemd's D-Bus API.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
)

// systemdConn is the subset of dbus.Conn this helper uses.
// Defined as an interface so unit tests can inject a fake and
// assert on argv passing / response handling without requiring
// a running systemd.
type systemdConn interface {
	EnableUnitFilesContext(ctx context.Context, files []string, runtime, force bool) (bool, []dbus.EnableUnitFileChange, error)
	DisableUnitFilesContext(ctx context.Context, files []string, runtime bool) ([]dbus.DisableUnitFileChange, error)
	MaskUnitFilesContext(ctx context.Context, files []string, runtime, force bool) ([]dbus.MaskUnitFileChange, error)
	UnmaskUnitFilesContext(ctx context.Context, files []string, runtime bool) ([]dbus.UnmaskUnitFileChange, error)
	StartUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	StopUnitContext(ctx context.Context, name, mode string, ch chan<- string) (int, error)
	GetUnitPropertyContext(ctx context.Context, unit, propertyName string) (*dbus.Property, error)
	GetUnitPropertiesContext(ctx context.Context, unit string) (map[string]any, error)
	Close()
}

// connFactory opens a D-Bus connection. Tests swap this out via
// the package-level `connFactoryHook` to avoid spawning a real
// dbus connection during unit tests.
type connFactory func(ctx context.Context) (systemdConn, error)

// connFactoryHook is the test seam. Production runs use
// defaultConnFactory, which calls dbus.NewSystemConnectionContext.
// Tests assign a fake before calling dispatch().
var connFactoryHook connFactory = defaultConnFactory

// defaultConnFactory is the production D-Bus opener. Surfaces
// connection failures as ErrDBusUnreachable so callers can map
// them to the AC-11 NDJSON error code without sniffing strings.
func defaultConnFactory(ctx context.Context) (systemdConn, error) {
	c, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDBusUnreachable, err)
	}
	return c, nil
}

// errDBusUnreachable is the sentinel for "couldn't open the
// system bus." Matches spec AC-11: the most likely development
// failure mode (container without host's bus mounted) surfaces
// as a typed error rather than as a panic or vague string.
var errDBusUnreachable = errors.New("dbus_unreachable")

// realDispatch replaces the D-007 stub. Routes each subcommand
// to its real D-Bus implementation; emits the NDJSON envelope.
// Called from main.go's dispatch().
func realDispatch(ctx context.Context, op, unit string, timeout time.Duration, stdout, stderr io.Writer) int {
	// Route the still-stubbed subcommands BEFORE opening D-Bus
	// so the D-008 scope cut preserves the D-007 behavior for
	// disable / mask (they emit not_yet_implemented regardless
	// of bus availability — opening the bus just to fail later
	// would surface a misleading dbus_unreachable for callers
	// exercising those subcommands).
	// Bound every D-Bus call by the operator's --timeout.
	// systemd's D-Bus methods used here (Enable/Disable/Mask
	// UnitFiles + property reads) are all SYNCHRONOUS, so the
	// timeout is the upper bound on a single round trip. The
	// JobRemoved dance applies only to job-producing methods
	// (Start/Stop/Restart) introduced in D-011.
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := connFactoryHook(callCtx)
	if err != nil {
		emitDBusUnreachable(op, unit, err, stdout)
		return 1
	}
	defer conn.Close()

	switch op {
	case "enable":
		return runEnable(callCtx, conn, unit, stdout)
	case "disable":
		return runDisable(callCtx, conn, unit, stdout)
	case "mask":
		return runMask(callCtx, conn, unit, stdout)
	case "unmask":
		return runUnmask(callCtx, conn, unit, stdout)
	case "start":
		return runStart(callCtx, conn, unit, stdout)
	case "stop":
		return runStop(callCtx, conn, unit, stdout)
	case "is-enabled":
		return runIsEnabled(callCtx, conn, unit, stdout)
	case "unit-state":
		return runUnitState(callCtx, conn, unit, stdout)
	default:
		fmt.Fprintf(stderr,
			"kensa-systemd-helper: dispatch missing case for %q (build bug)\n", op)
		return 1
	}
}

// runEnable invokes EnableUnitFilesContext + reads back the
// post-call UnitFileState. The EnableUnitFiles D-Bus method is
// SYNCHRONOUS — it returns when the symlinks are committed to
// disk, so no JobRemoved subscription is needed (AC-05 deferred
// per the spec rationale).
func runEnable(ctx context.Context, conn systemdConn, unit string, stdout io.Writer) int {
	start := time.Now()
	// EnableUnitFiles args:
	//   files=[unit]   single-unit operation
	//   runtime=false  persistent (write to /etc, not /run)
	//   force=true     replace conflicting symlinks
	_, changes, err := conn.EnableUnitFilesContext(ctx, []string{unit}, false, true)
	if err != nil {
		emitDBusOpError("enable", unit, err, stdout)
		return 1
	}

	settled := readUnitFileState(ctx, conn, unit)

	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            "enable",
		Unit:          unit,
		Success:       true,
		SettledState:  settled,
		Changes:       convertChanges(changes),
		DurationMs:    time.Since(start).Milliseconds(),
	}
	writeNDJSON(stdout, &resp)
	return 0
}

// runDisable invokes DisableUnitFilesContext + reads back the
// post-call UnitFileState. D-009 deliverable. Same synchronous
// semantics as EnableUnitFiles — no JobRemoved subscription
// required. Note the absence of a `force` parameter (the
// underlying systemd method doesn't accept one) and the bool
// return that EnableUnitFiles carries (DisableUnitFiles doesn't
// produce install info).
func runDisable(ctx context.Context, conn systemdConn, unit string, stdout io.Writer) int {
	start := time.Now()
	changes, err := conn.DisableUnitFilesContext(ctx, []string{unit}, false)
	if err != nil {
		emitDBusOpError("disable", unit, err, stdout)
		return 1
	}

	settled := readUnitFileState(ctx, conn, unit)

	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            "disable",
		Unit:          unit,
		Success:       true,
		SettledState:  settled,
		Changes:       convertDisableChanges(changes),
		DurationMs:    time.Since(start).Milliseconds(),
	}
	writeNDJSON(stdout, &resp)
	return 0
}

// runMask invokes MaskUnitFilesContext + reads back the
// post-call UnitFileState. D-010 deliverable. Same shape as
// EnableUnitFiles (takes force, returns Change list). Mask
// creates a symlink to /dev/null rather than to /usr/lib;
// the helper's Change list captures both directions.
func runMask(ctx context.Context, conn systemdConn, unit string, stdout io.Writer) int {
	start := time.Now()
	changes, err := conn.MaskUnitFilesContext(ctx, []string{unit}, false, true)
	if err != nil {
		emitDBusOpError("mask", unit, err, stdout)
		return 1
	}

	settled := readUnitFileState(ctx, conn, unit)

	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            "mask",
		Unit:          unit,
		Success:       true,
		SettledState:  settled,
		Changes:       convertMaskChanges(changes),
		DurationMs:    time.Since(start).Milliseconds(),
	}
	writeNDJSON(stdout, &resp)
	return 0
}

// runUnmask invokes UnmaskUnitFilesContext + reads back the
// post-call UnitFileState. The inverse of runMask: it removes the
// symlink-to-/dev/null that mask created, returning the unit to its
// prior enable/disable state. Same synchronous semantics as
// DisableUnitFiles — no JobRemoved subscription required, and (like
// disable) UnmaskUnitFiles takes no `force` parameter. Needed by
// service_masked's rollback when the captured prior state was not
// masked.
func runUnmask(ctx context.Context, conn systemdConn, unit string, stdout io.Writer) int {
	start := time.Now()
	changes, err := conn.UnmaskUnitFilesContext(ctx, []string{unit}, false)
	if err != nil {
		emitDBusOpError("unmask", unit, err, stdout)
		return 1
	}

	settled := readUnitFileState(ctx, conn, unit)

	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            "unmask",
		Unit:          unit,
		Success:       true,
		SettledState:  settled,
		Changes:       convertUnmaskChanges(changes),
		DurationMs:    time.Since(start).Milliseconds(),
	}
	writeNDJSON(stdout, &resp)
	return 0
}

// runStart invokes StartUnitContext using the channel-based
// JobRemoved synchronization that coreos/go-systemd provides
// natively. D-011 deliverable; first job-producing operation
// in the helper (un-defers spec AC-05 / C-03).
//
// **JobRemoved synchronization (spec C-03).** Per the
// coreos/go-systemd contract, the channel passed to
// StartUnitContext is registered against the resulting job
// path BEFORE the D-Bus method returns. The library holds the
// jobListener mutex across the method call + channel
// registration, and the signal handler that dispatches
// JobRemoved to channels acquires the same mutex; this gives
// "subscribe before signal delivery" atomically. Test fixtures
// verify the channel is non-nil at the method invocation site
// (the structural shape that locks the contract).
//
// Mode is "replace": start the unit and its dependencies,
// possibly replacing queued conflicting jobs. Matches the
// historical `systemctl start <unit>` behavior.
//
// Result string is one of: done, canceled, timeout, failed,
// dependency, skipped. Only "done" is treated as Apply success.
func runStart(ctx context.Context, conn systemdConn, unit string, stdout io.Writer) int {
	return runJobUnit(ctx, conn, "start", unit, conn.StartUnitContext, stdout)
}

// runStop invokes StopUnitContext with the same JobRemoved
// synchronization pattern as runStart. Symmetric apart from the
// underlying D-Bus method.
func runStop(ctx context.Context, conn systemdConn, unit string, stdout io.Writer) int {
	return runJobUnit(ctx, conn, "stop", unit, conn.StopUnitContext, stdout)
}

// jobMethod is the function-pointer shape shared by
// StartUnitContext and StopUnitContext. Used by runJobUnit to
// avoid duplicating the channel-creation + select logic.
type jobMethod func(ctx context.Context, name, mode string, ch chan<- string) (int, error)

// runJobUnit is the shared job-producing-D-Bus-op routine. Both
// runStart and runStop call this with their respective method
// references. Centralizes the channel lifecycle so the AC-05
// "channel created before invocation" contract is implemented
// in exactly one place — no two-implementation drift risk.
func runJobUnit(ctx context.Context, conn systemdConn, op, unit string, method jobMethod, stdout io.Writer) int {
	start := time.Now()

	// Create the JobRemoved channel BEFORE invoking the method
	// (spec C-03). The channel must exist at the method
	// invocation site so coreos/go-systemd can register it
	// against the resulting job path atomically — passing nil
	// here would mean the job's completion signal has nowhere
	// to land, so the wait below would block until ctx-timeout
	// even on instantaneous jobs.
	//
	// Buffered to 1 so a fast-completing job (signal arrives
	// while we're still constructing the response above) is
	// not dropped — if the channel were unbuffered, the signal
	// handler might send and discard before we read.
	jobCh := make(chan string, 1)

	jobID, err := method(ctx, unit, "replace", jobCh)
	if err != nil {
		emitDBusOpError(op, unit, err, stdout)
		return 1
	}

	// Wait for JobRemoved or context timeout. The helper's
	// --timeout flag (default 60s) is applied via the WithTimeout
	// context wrapper in realDispatch; ctx.Done() fires when the
	// deadline passes.
	var result string
	select {
	case result = <-jobCh:
		// got the completion signal
	case <-ctx.Done():
		emitJobTimeout(op, unit, jobID, time.Since(start), stdout)
		return 1
	}

	settled := readUnitFileState(ctx, conn, unit)

	// Apply success is conditional on "done". The other five
	// completion strings (canceled, timeout, failed, dependency,
	// skipped) all indicate the job did not finish cleanly; the
	// kensa engine should treat any of these as Apply failure
	// and trigger rollback.
	success := result == "done"
	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            op,
		Unit:          unit,
		Success:       success,
		JobID:         uint32(jobID),
		SettledState:  settled,
		DurationMs:    time.Since(start).Milliseconds(),
	}
	if success {
		resp.JobResult = result
	} else {
		resp.Error = &errorBlock{
			Code:   "job_" + result,
			Detail: fmt.Sprintf("systemd %s job for %s completed with result %q", op, unit, result),
		}
	}
	writeNDJSON(stdout, &resp)
	if success {
		return 0
	}
	return 1
}

// emitJobTimeout writes the AC-05 timeout NDJSON envelope:
// the helper waited for JobRemoved but ctx.Done() fired first.
// Spec C-05's timeout semantics: a stuck systemd job MUST
// surface as a typed failure within bounded time rather than
// hang the agent indefinitely.
func emitJobTimeout(op, unit string, jobID int, elapsed time.Duration, stdout io.Writer) {
	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            op,
		Unit:          unit,
		Success:       false,
		JobID:         uint32(jobID),
		DurationMs:    elapsed.Milliseconds(),
		Error: &errorBlock{
			Code:   "timeout",
			Detail: fmt.Sprintf("waited %dms for JobRemoved signal on job %d; --timeout exceeded", elapsed.Milliseconds(), jobID),
		},
	}
	writeNDJSON(stdout, &resp)
}

// runIsEnabled reads the unit's UnitFileState property. Per
// AC-07, the helper exits 0 on any non-bad/not-found state and
// 1 on bad/not-found.
func runIsEnabled(ctx context.Context, conn systemdConn, unit string, stdout io.Writer) int {
	state := readUnitFileState(ctx, conn, unit)
	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            "is-enabled",
		Unit:          unit,
		SettledState:  state,
	}
	// "bad" and "not-found" are systemd's signals that the unit
	// doesn't exist OR its unit file is malformed. Both are
	// failure conditions for the kensa contract.
	if state == "" || state == "bad" || state == "not-found" {
		resp.Success = false
		resp.Error = &errorBlock{
			Code:   "unit_state_unknown",
			Detail: fmt.Sprintf("UnitFileState for %q is %q", unit, state),
		}
		writeNDJSON(stdout, &resp)
		return 1
	}
	resp.Success = true
	writeNDJSON(stdout, &resp)
	return 0
}

// runUnitState fetches the rich Capture payload. Reads
// UnitFileState + ActiveState + SubState + LoadState +
// FragmentPath + the .wants / .requires symlink lists.
func runUnitState(ctx context.Context, conn systemdConn, unit string, stdout io.Writer) int {
	props, err := conn.GetUnitPropertiesContext(ctx, unit)
	if err != nil {
		emitDBusOpError("unit-state", unit, err, stdout)
		return 1
	}
	state := &unitState{
		UnitFileState: stringProp(props, "UnitFileState"),
		ActiveState:   stringProp(props, "ActiveState"),
		SubState:      stringProp(props, "SubState"),
		LoadState:     stringProp(props, "LoadState"),
		FragmentPath:  stringProp(props, "FragmentPath"),
		UnitFileLinks: stringSliceProp(props, "Wants", "Requires"),
	}
	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            "unit-state",
		Unit:          unit,
		Success:       true,
		SettledState:  state.UnitFileState,
		UnitState:     state,
	}
	writeNDJSON(stdout, &resp)
	return 0
}

// readUnitFileState reads the UnitFileState property. Returns
// the string value, or "" if the property is missing / the
// read fails. Caller decides how to map the empty result.
func readUnitFileState(ctx context.Context, conn systemdConn, unit string) string {
	prop, err := conn.GetUnitPropertyContext(ctx, unit, "UnitFileState")
	if err != nil {
		return ""
	}
	if prop == nil {
		return ""
	}
	s, ok := prop.Value.Value().(string)
	if !ok {
		return ""
	}
	return s
}

// stringProp pulls a string property from a property map. Empty
// string when missing or the wrong type — callers tolerate this
// since systemd versions vary in which properties they expose.
func stringProp(props map[string]any, name string) string {
	v, ok := props[name]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// stringSliceProp concatenates one or more []string properties
// from a property map. Used to combine Wants + Requires into the
// AC-08 UnitFileLinks field.
func stringSliceProp(props map[string]any, names ...string) []string {
	var out []string
	for _, name := range names {
		v, ok := props[name]
		if !ok {
			continue
		}
		s, ok := v.([]string)
		if !ok {
			continue
		}
		out = append(out, s...)
	}
	return out
}

// convertChanges maps coreos/go-systemd's EnableUnitFileChange
// to the helper's NDJSON `change` shape.
func convertChanges(raw []dbus.EnableUnitFileChange) []change {
	if len(raw) == 0 {
		return nil
	}
	out := make([]change, 0, len(raw))
	for _, r := range raw {
		out = append(out, change{
			Type:        r.Type,
			Source:      r.Filename,
			Destination: r.Destination,
		})
	}
	return out
}

// convertDisableChanges maps DisableUnitFileChange list to the
// helper's `change` shape. The coreos/go-systemd library
// unfortunately declares three separate types (Enable / Disable
// / Mask) with identical fields; we convert each explicitly
// rather than risk a generic any-typed converter.
func convertDisableChanges(raw []dbus.DisableUnitFileChange) []change {
	if len(raw) == 0 {
		return nil
	}
	out := make([]change, 0, len(raw))
	for _, r := range raw {
		out = append(out, change{
			Type:        r.Type,
			Source:      r.Filename,
			Destination: r.Destination,
		})
	}
	return out
}

// convertMaskChanges maps MaskUnitFileChange list to the
// helper's `change` shape.
func convertMaskChanges(raw []dbus.MaskUnitFileChange) []change {
	if len(raw) == 0 {
		return nil
	}
	out := make([]change, 0, len(raw))
	for _, r := range raw {
		out = append(out, change{
			Type:        r.Type,
			Source:      r.Filename,
			Destination: r.Destination,
		})
	}
	return out
}

// convertUnmaskChanges maps the D-Bus UnmaskUnitFiles change list
// into the helper's NDJSON change shape. UnmaskUnitFileChange carries
// the same Type/Filename/Destination fields as the mask/disable
// variants.
func convertUnmaskChanges(raw []dbus.UnmaskUnitFileChange) []change {
	if len(raw) == 0 {
		return nil
	}
	out := make([]change, 0, len(raw))
	for _, r := range raw {
		out = append(out, change{
			Type:        r.Type,
			Source:      r.Filename,
			Destination: r.Destination,
		})
	}
	return out
}

// emitDBusUnreachable writes the AC-11 NDJSON error envelope.
// Called when connFactoryHook() returns an unwrappable
// errDBusUnreachable — the bus socket couldn't be opened at all.
func emitDBusUnreachable(op, unit string, err error, stdout io.Writer) {
	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            op,
		Unit:          unit,
		Success:       false,
		Error: &errorBlock{
			Code:   "dbus_unreachable",
			Detail: trimErrDetail(err),
		},
	}
	writeNDJSON(stdout, &resp)
}

// emitDBusOpError writes a generic NDJSON error envelope for
// in-call D-Bus failures (the connection opened fine but the
// method call itself failed: unit not found, permission denied,
// etc.). Distinguishes from emitDBusUnreachable so operators
// can tell "bus down" from "operation rejected".
func emitDBusOpError(op, unit string, err error, stdout io.Writer) {
	code := classifyDBusError(err)
	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            op,
		Unit:          unit,
		Success:       false,
		Error: &errorBlock{
			Code:     code,
			DBusName: extractDBusName(err),
			Detail:   trimErrDetail(err),
		},
	}
	writeNDJSON(stdout, &resp)
}

// classifyDBusError maps an arbitrary D-Bus error string to a
// stable kensa error code. The "code" field in our NDJSON is
// what handlers switch on to route the failure (e.g.,
// `no_such_unit` should fail the Apply but not the whole scan).
// The DBus error name (`org.freedesktop.systemd1.NoSuchUnit`)
// is preserved separately for operator diagnosis.
func classifyDBusError(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "NoSuchUnit"), strings.Contains(s, "no such unit"):
		return "no_such_unit"
	case strings.Contains(s, "AccessDenied"), strings.Contains(s, "access denied"):
		return "access_denied"
	case strings.Contains(s, "Permission"):
		return "access_denied"
	case strings.Contains(s, "UnitMasked"):
		return "unit_masked"
	default:
		return "dbus_error"
	}
}

// extractDBusName pulls the `org.freedesktop.systemd1.<Name>`
// portion out of a D-Bus error string. The coreos/go-systemd
// library formats errors as `Error org.freedesktop.X.Y: detail`
// so we extract the X.Y portion when present.
func extractDBusName(err error) string {
	s := err.Error()
	// Heuristic: look for the first dot-separated token starting
	// with "org.freedesktop." since that's the systemd error
	// namespace coreos/go-systemd uses.
	idx := strings.Index(s, "org.freedesktop.")
	if idx < 0 {
		return ""
	}
	tail := s[idx:]
	// End at the first space, colon, or quote.
	for i, r := range tail {
		if r == ' ' || r == ':' || r == '"' {
			return tail[:i]
		}
	}
	return tail
}

// trimErrDetail trims the error string to a reasonable length
// for the NDJSON detail field. Long systemd errors otherwise
// dominate the line; the cap keeps the JSON readable.
func trimErrDetail(err error) string {
	const maxDetail = 512
	s := err.Error()
	if len(s) <= maxDetail {
		return s
	}
	return s[:maxDetail] + "..."
}
