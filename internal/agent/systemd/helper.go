// Package systemd is the agent-side wrapper around the
// privileged kensa-systemd-helper subprocess. It runs under the sudo-not-setuid privilege model — the agent itself runs as the unprivileged SSH
// user; this package builds and invokes `sudo
// /usr/libexec/kensa-systemd-helper ...` to perform systemd
// D-Bus operations as root for the duration of one call, parses
// the helper's NDJSON output, and returns a typed Go struct to
// the handler.
//
// **D-007 scope.** This file ships the subprocess invocation +
// NDJSON parser + version-skew detection. The helper itself
// returns `not_yet_implemented` for every subcommand until
// D-008..D-010 fill in the D-Bus calls — but the wrapper is
// fully wired so that those deliverables only need to change
// the helper, not the agent-side surface.
//
// **Helper-interface contract.** Source of truth is
// `specs/agent/systemd-helper.spec.yaml`. The agent and helper
// MUST agree on the NDJSON schema; mismatch on `schema_version`
// (spec AC-10) fails closed with `ErrSchemaUnsupported`.
package systemd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// geteuid is os.Geteuid, indirected so a test can drive both the
// already-root (direct invocation) and non-root (sudo) argv branches.
var geteuid = os.Geteuid

// HelperPath is the absolute path the kensa-rpm installs the
// helper to. Operators with non-standard packaging override via
// the constructor; the default matches the FHS convention for
// privileged helper binaries (per /usr/libexec policy).
const HelperPath = "/usr/libexec/kensa-systemd-helper"

// SchemaVersion is the NDJSON envelope version this wrapper
// understands. Must match the helper's `schemaVersion` constant.
// When the helper bumps the schema, this constant follows and
// the agent rejects helpers reporting any other value.
const SchemaVersion = 1

// AgentVersion is the agent's reported kensa version, baked in
// at build time via -ldflags. Used for the binary-version-skew
// warning (spec AC-10, informational). Defaults to "dev" for
// developer builds. Cmd/kensa-* binaries set this from their
// own version var when constructing the Client.
var AgentVersion = "dev"

// Sentinel errors callers can match via errors.Is.
var (
	// ErrSchemaUnsupported fires when the helper reports a
	// schema_version this agent doesn't understand. Per spec
	// AC-10 this fails closed — the engine treats the operation
	// as failed and surfaces the skew to the operator.
	ErrSchemaUnsupported = errors.New("systemd: helper reported unsupported schema_version")

	// ErrHelperFailed fires when the helper exits non-zero with
	// a parseable NDJSON error block. The caller unwraps via
	// errors.As(&HelperError{}) to extract the structured detail.
	ErrHelperFailed = errors.New("systemd: helper reported failure")

	// ErrHelperOutputMalformed fires when the helper's stdout
	// is not valid NDJSON or doesn't include the required
	// envelope fields. This indicates either a broken helper
	// binary (build bug) or sudo writing to stdout (sudo
	// asking for a password — should never happen with the
	// NOPASSWD sudoers fragment, but we surface it loudly).
	ErrHelperOutputMalformed = errors.New("systemd: helper stdout not parseable as NDJSON")

	// ErrHelperNotFound fires when /usr/libexec/kensa-systemd-helper
	// doesn't exist on the target. The kensa-rpm installs it; a
	// missing binary indicates incomplete packaging or a
	// developer running the agent outside an installed kensa.
	ErrHelperNotFound = errors.New("systemd: kensa-systemd-helper binary not found")

	// ErrHelperUnavailable is the umbrella for "the helper could not be
	// INVOKED at all" — the binary is missing (ErrHelperNotFound wraps
	// this) OR the agent could not exec it (e.g. fapolicyd on a
	// STIG-hardened host denies execve of a non-rpm-trusted binary →
	// EPERM). It is distinct from a HelperError, which means the helper
	// RAN and systemd refused. Service handlers fall back to the
	// `systemctl` shell path on ErrHelperUnavailable — systemctl is a
	// distro binary fapolicyd already trusts, so the fallback works where
	// the un-trusted helper cannot run. Live-caught on the STIG fleet.
	ErrHelperUnavailable = errors.New("systemd: helper could not be invoked")
)

// HelperError is the typed failure detail emitted in the
// helper's NDJSON `error` block. Callers extract via
// errors.As(err, &helperErr).
type HelperError struct {
	Op       string
	Unit     string
	Code     string
	DBusName string
	Detail   string
}

func (e *HelperError) Error() string {
	if e.DBusName != "" {
		return fmt.Sprintf("systemd: %s %s: %s (%s: %s)",
			e.Op, e.Unit, e.Code, e.DBusName, e.Detail)
	}
	return fmt.Sprintf("systemd: %s %s: %s: %s",
		e.Op, e.Unit, e.Code, e.Detail)
}

// Unwrap lets errors.Is(err, ErrHelperFailed) succeed.
func (e *HelperError) Unwrap() error { return ErrHelperFailed }

// Response mirrors the helper's NDJSON output envelope. Every
// field maps 1:1 to the helper's `response` struct in
// cmd/kensa-systemd-helper/main.go. Kept in sync with the spec.
type Response struct {
	SchemaVersion int        `json:"schema_version"`
	HelperVersion string     `json:"helper_version"`
	Op            string     `json:"op"`
	Unit          string     `json:"unit"`
	Success       bool       `json:"success"`
	JobID         uint32     `json:"job_id,omitempty"`
	JobResult     string     `json:"job_result,omitempty"` // D-011: "done" on Start/Stop success
	SettledState  string     `json:"settled_state,omitempty"`
	Changes       []Change   `json:"changes,omitempty"`
	UnitState     *UnitState `json:"unit_state,omitempty"`
	DurationMs    int64      `json:"duration_ms,omitempty"`
	Error         *struct {
		Code     string `json:"code"`
		DBusName string `json:"dbus_name,omitempty"`
		Detail   string `json:"detail,omitempty"`
	} `json:"error,omitempty"`
}

// Change is one symlink operation in the EnableUnitFiles /
// DisableUnitFiles return list.
type Change struct {
	Type        string `json:"type"`
	Source      string `json:"src"`
	Destination string `json:"dst"`
}

// UnitState is the rich Capture-suitable state returned by the
// helper's `unit-state` subcommand.
type UnitState struct {
	UnitFileState string   `json:"unit_file_state"`
	ActiveState   string   `json:"active_state"`
	SubState      string   `json:"sub_state"`
	LoadState     string   `json:"load_state"`
	UnitFileLinks []string `json:"unit_file_links"`
	FragmentPath  string   `json:"fragment_path"`
}

// Client is the agent-side wrapper. Construct via New() or
// NewWithPath() for tests that need to point at an alternate
// helper binary.
type Client struct {
	helperPath string

	// runner is the subprocess invocation hook. Tests inject a
	// fake to assert on argv + supply canned NDJSON without
	// spawning a real subprocess. Production callers leave nil
	// — execHelper runs the actual `sudo helperPath ...` command.
	runner func(ctx context.Context, argv []string) (stdout []byte, stderr []byte, exitCode int, err error)
}

// New returns a Client invoking the default helper path via sudo.
// Production callers (the agent) use this constructor.
func New() *Client {
	return &Client{helperPath: HelperPath}
}

// NewWithPath returns a Client invoking the helper at a non-
// default path. Used in tests that build a stub helper in a
// temp dir.
func NewWithPath(path string) *Client {
	return &Client{helperPath: path}
}

// withRunner is the test-only constructor that swaps the
// subprocess invocation for a fake. Returns a fresh Client so
// the production New() / NewWithPath() callers can't accidentally
// share a runner.
func withRunner(path string, r func(ctx context.Context, argv []string) ([]byte, []byte, int, error)) *Client {
	return &Client{helperPath: path, runner: r}
}

// Enable runs `sudo helper enable <unit>` and returns the typed
// response. D-008 fills in the D-Bus implementation; D-007 wires
// this method through so callers can already integrate against
// the surface.
func (c *Client) Enable(ctx context.Context, unit string) (*Response, error) {
	return c.invoke(ctx, "enable", unit)
}

// Disable runs `sudo helper disable <unit>`. D-009.
func (c *Client) Disable(ctx context.Context, unit string) (*Response, error) {
	return c.invoke(ctx, "disable", unit)
}

// Mask runs `sudo helper mask <unit>`. D-010.
func (c *Client) Mask(ctx context.Context, unit string) (*Response, error) {
	return c.invoke(ctx, "mask", unit)
}

// Unmask runs `sudo helper unmask <unit>`. The inverse of Mask;
// needed so service_masked's rollback can restore a unit whose
// captured prior state was not masked without shelling out to
// `systemctl unmask`.
func (c *Client) Unmask(ctx context.Context, unit string) (*Response, error) {
	return c.invoke(ctx, "unmask", unit)
}

// Start runs `sudo helper start <unit>`. D-011 — first
// job-producing op; the helper waits on JobRemoved before
// returning. The returned Response carries JobResult — the
// systemd completion string ("done" on success; "canceled",
// "timeout", "failed", "dependency", "skipped" on failure).
func (c *Client) Start(ctx context.Context, unit string) (*Response, error) {
	return c.invoke(ctx, "start", unit)
}

// Stop runs `sudo helper stop <unit>`. D-011, symmetric with Start.
func (c *Client) Stop(ctx context.Context, unit string) (*Response, error) {
	return c.invoke(ctx, "stop", unit)
}

// IsEnabled runs `sudo helper is-enabled <unit>` and returns the
// UnitFileState in resp.SettledState. D-008.
func (c *Client) IsEnabled(ctx context.Context, unit string) (*Response, error) {
	return c.invoke(ctx, "is-enabled", unit)
}

// UnitState runs `sudo helper unit-state <unit>` and returns the
// rich Capture payload in resp.UnitState. D-008.
func (c *Client) UnitState(ctx context.Context, unit string) (*Response, error) {
	return c.invoke(ctx, "unit-state", unit)
}

// invoke is the shared subprocess + parse path. Builds argv,
// runs (via runner if injected, else execHelper), parses the
// last non-empty stdout line as NDJSON, applies schema-version
// + binary-version checks, and constructs the typed error or
// success response.
func (c *Client) invoke(ctx context.Context, op, unit string) (*Response, error) {
	// The helper only requires EUID 0 (it exits 2 for non-root). When the
	// agent ALREADY runs as root — the normal agent-mode case, since
	// `kensa remediate --sudo` spawns the agent under sudo — invoke the
	// helper directly: a redundant `sudo helper` re-enters PAM for root,
	// which on hardened hosts (root password "never changed" → flagged
	// expired, or requiretty) fails with "Account or password is expired"
	// / "a terminal is required". sudo is needed only to ESCALATE from a
	// non-root agent (via the %kensa NOPASSWD sudoers fragment). Live-caught
	// on RHEL 9.6/9.7.
	var argv []string
	if geteuid() == 0 {
		argv = []string{c.helperPath, op, unit}
	} else {
		argv = []string{"sudo", c.helperPath, op, unit}
	}

	var stdout, stderr []byte
	var exitCode int
	var err error
	if c.runner != nil {
		stdout, stderr, exitCode, err = c.runner(ctx, argv)
	} else {
		stdout, stderr, exitCode, err = execHelper(ctx, argv)
	}
	if err != nil {
		// Subprocess spawn / exec error (binary not found,
		// permission denied launching sudo, etc.). Distinguish
		// the "helper not installed" case for operator clarity.
		if errors.Is(err, exec.ErrNotFound) || strings.Contains(err.Error(), "no such file") {
			return nil, fmt.Errorf("%w: %w at %s", ErrHelperUnavailable, ErrHelperNotFound, c.helperPath)
		}
		// Any other spawn/exec failure (e.g. fapolicyd denying execve of a
		// non-trusted helper → EPERM) is also "couldn't invoke it" → the
		// caller falls back to the shell path.
		return nil, fmt.Errorf("%w: helper exec %s %s: %w (stderr: %s)",
			ErrHelperUnavailable, op, unit, err, strings.TrimSpace(string(stderr)))
	}

	// Exit codes:
	//   0 — success with NDJSON success:true
	//   1 — runtime error with NDJSON success:false + error block
	//   2 — usage error; NO NDJSON on stdout
	if exitCode == 2 {
		return nil, fmt.Errorf("systemd: helper rejected invocation (exit 2): %s",
			strings.TrimSpace(string(stderr)))
	}

	resp, parseErr := parseLastNDJSONLine(stdout)
	if parseErr != nil {
		return nil, fmt.Errorf("%w: %s %s: %v (stderr: %s)",
			ErrHelperOutputMalformed, op, unit, parseErr,
			strings.TrimSpace(string(stderr)))
	}

	if resp.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: got %d, want %d (helper version %q)",
			ErrSchemaUnsupported,
			resp.SchemaVersion, SchemaVersion, resp.HelperVersion)
	}

	// Spec AC-10: binary version skew is INFORMATIONAL. Emit a
	// single stderr warning on mismatch and continue. The
	// load-bearing check is schema_version (above).
	if resp.HelperVersion != AgentVersion {
		// We don't have a logger plumbed yet; the agent will pipe
		// stderr through to the controller in a future deliverable.
		// For now, callers can inspect resp.HelperVersion themselves
		// — the warning is documented as side-channel and best-effort.
		// TODO(phase-4): wire structured logging when the agent
		// gains a log surface.
		_ = stderr // reserved
	}

	if resp.Success {
		return resp, nil
	}

	// Helper reported a structured failure (exit 1 with NDJSON
	// error block). Construct a typed HelperError.
	herr := &HelperError{Op: op, Unit: unit}
	if resp.Error != nil {
		herr.Code = resp.Error.Code
		herr.DBusName = resp.Error.DBusName
		herr.Detail = resp.Error.Detail
	}
	return resp, herr
}

// parseLastNDJSONLine reads buf as bytes (the helper's stdout),
// splits on newline, and returns the last non-empty line parsed
// as a Response. Robust against trailing newlines, blank lines,
// and (defense-in-depth) stray junk before the final NDJSON
// payload — spec C-02 forbids non-JSON on stdout but a defensive
// parse means a misbehaving helper produces ErrHelperOutputMalformed
// rather than a silent wrong-result.
func parseLastNDJSONLine(buf []byte) (*Response, error) {
	if len(buf) == 0 {
		return nil, errors.New("empty stdout")
	}
	scanner := bufio.NewScanner(bytes.NewReader(buf))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lastLine []byte
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		lastLine = append([]byte(nil), line...)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan stdout: %w", err)
	}
	if len(lastLine) == 0 {
		return nil, errors.New("no non-empty lines in stdout")
	}
	var resp Response
	if err := json.Unmarshal(lastLine, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal %q: %w", string(lastLine), err)
	}
	if resp.SchemaVersion == 0 {
		return nil, errors.New("schema_version missing from response")
	}
	return &resp, nil
}

// execHelper is the production subprocess runner. Spawns the
// helper via sudo, captures stdout + stderr + exit code.
//
// **Why sudo and not setuid.** The helper is NOT
// setuid (would re-introduce the "any unprivileged caller can
// invoke" risk). Sudo with the kensa-rpm-shipped sudoers
// fragment is the auditable invocation path.
func execHelper(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	if len(argv) < 2 {
		return nil, nil, 0, fmt.Errorf("execHelper: argv too short: %v", argv)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = nil // No password prompt; sudoers fragment uses NOPASSWD.
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			// ExitError isn't a "real" error from our perspective
			// — the helper ran, exited with a code, and produced
			// NDJSON. Clear the err so invoke() proceeds to parsing.
			err = nil
		}
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, err
}
