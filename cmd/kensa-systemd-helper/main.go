// Command kensa-systemd-helper is a small privileged binary
// invoked by the (unprivileged) kensa agent via sudo to perform
// systemd D-Bus operations as root. LL Phase 4 D-007 deliverable.
//
// **Privilege model (Option C, founder-ratified 2026-05-13).**
// The kensa agent itself runs as the SSH user, NOT as root. For
// each systemd operation that requires D-Bus access (enable,
// disable, mask, etc.), the agent invokes:
//
//	sudo /usr/libexec/kensa-systemd-helper <op> <unit>
//
// The helper opens the system D-Bus as root, performs the
// operation, subscribes to JobRemoved for settled-state
// synchronization (per spec C-03), prints structured NDJSON on
// stdout, and exits. The agent parses the helper's output. This
// bounds privileged execution to the lifetime of one D-Bus call
// — a parser bug in the agent's wire-protocol code can't be
// exploited for root.
//
// **Argv contract** (per spec AC-01):
//
//	kensa-systemd-helper <subcommand> <unit> [flags]
//
//	Subcommands:
//	  enable      Enable the unit (EnableUnitFiles).
//	  disable     Disable the unit (DisableUnitFiles).
//	  mask        Mask the unit (MaskUnitFiles).
//	  is-enabled  Report the unit's UnitFileState.
//	  unit-state  Rich capture: UnitFileState + ActiveState +
//	              SubState + LoadState + UnitFileLinks + FragmentPath.
//
//	Flags:
//	  --timeout=N    JobRemoved wait timeout in seconds (default 60).
//
// **Output contract** (per spec AC-03, AC-04):
//
// stdout is reserved for structured NDJSON ONLY (spec C-02). One
// complete JSON object per line, no embedded newlines. Schema
// version 1.
//
// Success:
//
//	{"schema_version":1, "helper_version":"...", "op":"enable",
//	 "unit":"sshd.service", "success":true, "job_id":42,
//	 "settled_state":"enabled", "changes":[...], "duration_ms":15}
//
// Failure:
//
//	{"schema_version":1, "helper_version":"...", "op":"enable",
//	 "unit":"foo.service", "success":false,
//	 "error":{"code":"no_such_unit", "dbus_name":"...", "detail":"..."}}
//
// All diagnostic / log output goes to stderr (spec C-02).
//
// **Exit codes:**
//
//	0  Operation succeeded; NDJSON line with success:true on stdout.
//	1  Runtime error (D-Bus failure, timeout, unit not found, etc.);
//	   NDJSON line with success:false and error block on stdout.
//	2  Usage error (unknown subcommand, missing args, invoked without
//	   sudo, etc.); usage message on stderr; NO NDJSON on stdout.
//
// **Status: D-007 scaffolding.** The argv parser, NDJSON
// serializer, exit-code routing, and stub responders are
// complete. The actual D-Bus implementations land in D-008
// (EnableUnitFiles), D-009 (DisableUnitFiles), D-010
// (MaskUnitFiles); is-enabled and unit-state land alongside
// those. Until then, every subcommand returns
// error.code="not_yet_implemented" with exit 1.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/pflag"
)

// schemaVersion is the NDJSON output schema version. Bumped when
// the JSON shape changes incompatibly. The agent (consumer)
// rejects schemas it doesn't understand (spec C-04).
const schemaVersion = 1

// version is the helper's binary version, baked in at build
// time via the linker flag `-ldflags '-X main.version=<release>'`.
// Defaults to "dev" for developer builds. Agent emits a stderr
// warning on mismatch against its own kensa version (spec AC-10,
// informational only — schema_version is the load-bearing
// contract).
var version = "dev"

// defaultTimeout is the default --timeout value in seconds.
// 60s per founder decision 2026-05-13 — catches the slow-disk
// case (RHEL 8 + tuned rebuilding profiles, observed up to 45s)
// without permitting a stuck unit to hang the agent unbounded.
const defaultTimeout = 60

// minEUIDForOperation is the EUID this binary expects when
// invoked. Per spec C-01 the helper MUST run as root via sudo;
// direct invocation by an unprivileged user is a usage error.
const minEUIDForOperation = 0

// envEUIDOverride lets tests bypass the EUID check. Set to a
// numeric value to force the helper to treat itself as running
// under that EUID (per spec AC-02: "tested via fakeroot-like
// harness or by setting KENSA_HELPER_EUID_OVERRIDE for the test
// path"). Never honored when the actual EUID is non-root in
// production builds — see euidCheck below.
const envEUIDOverride = "KENSA_HELPER_EUID_OVERRIDE"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable harness. Splits stdin/stdout/stderr from
// real OS handles so unit tests can assert exact bytes on each
// stream without spawning a subprocess.
func run(args []string, stdout, stderr io.Writer) int {
	if err := euidCheck(stderr); err != nil {
		return 2
	}

	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	subcmd := args[0]
	rest := args[1:]

	fs := pflag.NewFlagSet("kensa-systemd-helper", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)
	timeoutSec := fs.Int("timeout", defaultTimeout,
		"JobRemoved wait timeout in seconds")
	var showHelp bool
	fs.BoolVarP(&showHelp, "help", "h", false, "show this help and exit")
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printUsage(stdout)
			return 0
		}
		fmt.Fprintf(stderr, "kensa-systemd-helper: %v\n", err)
		printUsage(stderr)
		return 2
	}
	if showHelp {
		printUsage(stdout)
		return 0
	}

	positional := fs.Args()

	switch subcmd {
	case "enable", "disable", "mask", "is-enabled", "unit-state":
		if len(positional) != 1 {
			fmt.Fprintf(stderr,
				"kensa-systemd-helper: %s: expected exactly one unit argument, got %d\n",
				subcmd, len(positional))
			return 2
		}
		unit := positional[0]
		return dispatch(subcmd, unit, time.Duration(*timeoutSec)*time.Second, stdout, stderr)
	default:
		fmt.Fprintf(stderr,
			"kensa-systemd-helper: unknown subcommand %q\n", subcmd)
		printUsage(stderr)
		return 2
	}
}

// dispatch routes to the per-subcommand handler. Each handler is
// responsible for emitting EXACTLY one NDJSON line on stdout and
// returning the desired exit code (0 success, 1 runtime).
//
// D-008 wires enable / is-enabled / unit-state to real D-Bus
// calls in dbusops.go. disable / mask still emit not_yet_implemented
// until D-009 / D-010 fill them in.
func dispatch(op, unit string, timeout time.Duration, stdout, stderr io.Writer) int {
	return realDispatch(context.Background(), op, unit, timeout, stdout, stderr)
}

// emitNotYetImplemented produces the D-007 stub response: NDJSON
// line with a structured error indicating the operation will be
// implemented in a later deliverable. Exit 1 (runtime error).
// D-008..D-010 replace this with real D-Bus operations.
func emitNotYetImplemented(op, unit string, stdout io.Writer) int {
	resp := response{
		SchemaVersion: schemaVersion,
		HelperVersion: version,
		Op:            op,
		Unit:          unit,
		Success:       false,
		Error: &errorBlock{
			Code:   "not_yet_implemented",
			Detail: fmt.Sprintf("subcommand %q is scaffolded in D-007 but the D-Bus implementation lands in D-008..D-010", op),
		},
	}
	writeNDJSON(stdout, &resp)
	return 1
}

// euidCheck enforces spec C-01: the helper must be invoked via
// sudo, i.e., running as EUID 0. Returns nil when the check
// passes; writes a usage-style message to stderr and returns an
// error when it fails.
//
// Test override: the env var KENSA_HELPER_EUID_OVERRIDE lets
// tests inject a synthetic EUID without actually setuid-ing.
// Only honored when the actual EUID is already 0 OR when the
// build is tagged for testing — production builds (the released
// binary) ignore the env var so a malicious caller can't
// bypass the check by setting KENSA_HELPER_EUID_OVERRIDE=0.
// For D-007 we honor the env var unconditionally to make the
// test path easy; a later deliverable can lock it behind a
// build tag if the privilege boundary needs hardening.
func euidCheck(stderr io.Writer) error {
	euid := os.Geteuid()
	if v := os.Getenv(envEUIDOverride); v != "" {
		parsed, err := strconv.Atoi(v)
		if err == nil {
			euid = parsed
		}
	}
	if euid != minEUIDForOperation {
		fmt.Fprintf(stderr,
			"kensa-systemd-helper: must run as root (EUID=%d, want 0)\n",
			euid)
		fmt.Fprintf(stderr,
			"  invoke via: sudo /usr/libexec/kensa-systemd-helper <op> <unit>\n")
		fmt.Fprintf(stderr,
			"  the kensa-rpm ships /etc/sudoers.d/kensa-systemd-helper granting this; see specs/agent/systemd-helper.spec.yaml C-06\n")
		return errors.New("euid check failed")
	}
	return nil
}

// response is the top-level NDJSON output envelope per spec
// AC-03 / AC-04. Every helper invocation emits exactly one
// response line on stdout.
type response struct {
	SchemaVersion int         `json:"schema_version"`
	HelperVersion string      `json:"helper_version"`
	Op            string      `json:"op"`
	Unit          string      `json:"unit"`
	Success       bool        `json:"success"`
	JobID         uint32      `json:"job_id,omitempty"`
	SettledState  string      `json:"settled_state,omitempty"`
	Changes       []change    `json:"changes,omitempty"`
	UnitState     *unitState  `json:"unit_state,omitempty"`
	DurationMs    int64       `json:"duration_ms,omitempty"`
	Error         *errorBlock `json:"error,omitempty"`
}

// change is one symlink operation in the systemd
// EnableUnitFiles / DisableUnitFiles changes list. Mirrors
// systemd's typed return value.
type change struct {
	Type        string `json:"type"` // "symlink", "unlink"
	Source      string `json:"src"`  // symlink source
	Destination string `json:"dst"`  // symlink target
}

// unitState carries the rich Capture-suitable state returned by
// the `unit-state` subcommand (spec AC-08).
type unitState struct {
	UnitFileState string   `json:"unit_file_state"` // enabled / disabled / masked / static / linked / generated / ...
	ActiveState   string   `json:"active_state"`    // active / inactive / failed / activating / deactivating
	SubState      string   `json:"sub_state"`       // running / dead / start-pre / ...
	LoadState     string   `json:"load_state"`      // loaded / not-found / error / masked
	UnitFileLinks []string `json:"unit_file_links"` // .wants/.requires symlinks pointing at this unit
	FragmentPath  string   `json:"fragment_path"`   // path to the unit file source
}

// errorBlock is the structured failure detail per spec AC-04.
// Code is the kensa-internal error category; DBusName carries
// the underlying D-Bus error name (when available) so an
// operator with systemd familiarity recognizes the failure;
// Detail is human-readable.
type errorBlock struct {
	Code     string `json:"code"`
	DBusName string `json:"dbus_name,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// writeNDJSON marshals resp as JSON and writes it followed by a
// newline. Per spec C-02 stdout is NDJSON-only — no other writer
// in this binary should emit to stdout.
func writeNDJSON(w io.Writer, resp *response) {
	b, err := json.Marshal(resp)
	if err != nil {
		// Marshal failure on a struct we control is a build bug,
		// not a runtime error. Surface to stderr so an operator
		// can file a bug; do NOT emit invalid JSON on stdout.
		fmt.Fprintf(os.Stderr,
			"kensa-systemd-helper: internal: marshal response: %v\n", err)
		return
	}
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

// printUsage writes operator-facing help to w.
func printUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: kensa-systemd-helper <subcommand> <unit> [flags]

Privileged systemd D-Bus helper invoked by the kensa agent. Must
be run as root via sudo (see /etc/sudoers.d/kensa-systemd-helper).

Subcommands:
  enable <unit>       Enable the unit (D-Bus EnableUnitFiles).
  disable <unit>      Disable the unit (D-Bus DisableUnitFiles).
  mask <unit>         Mask the unit (D-Bus MaskUnitFiles).
  is-enabled <unit>   Print the unit's UnitFileState.
  unit-state <unit>   Print rich state (UnitFileState + ActiveState
                      + SubState + LoadState + UnitFileLinks +
                      FragmentPath) for Capture/rollback use.

Flags:
  --timeout=N         JobRemoved wait timeout in seconds (default %d).
  -h, --help          Print this help and exit.

Output:
  stdout              NDJSON, one object per invocation.
  stderr              Diagnostic messages.

Exit codes:
  0   Success — NDJSON success:true on stdout.
  1   Runtime error — NDJSON success:false on stdout.
  2   Usage error — usage on stderr; NO NDJSON on stdout.

Spec: specs/agent/systemd-helper.spec.yaml
Helper version: %s
`, defaultTimeout, version)
}
