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
	switch op {
	case "disable", "mask":
		return emitNotYetImplemented(op, unit, stdout)
	}

	// Bound every D-Bus call by the operator's --timeout.
	// systemd's D-Bus methods are synchronous (no JobRemoved
	// dance for enable/disable/mask), so the timeout is the
	// upper bound on a single round trip + property read.
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
// can tell "bus down" from "operation rejected."
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
// portion out of a D-Bus error string. coreos/go-systemd
// formats errors as "Error org.freedesktop.X.Y: detail" so we
// extract the X.Y portion when present.
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
