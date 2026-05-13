// Tests for kensa-systemd-helper. D-007 scope: argv + NDJSON
// + exit codes + EUID check + version envelope. The D-Bus
// implementation (and its tests) lands in D-008..D-010.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// withEUIDOverride temporarily sets the KENSA_HELPER_EUID_OVERRIDE
// env var, returning a cleanup the caller defers. EUID 0 is the
// "running as root via sudo" path; nonzero exercises the C-01
// check. The override mechanism is documented in main.go's
// euidCheck — production builds may eventually lock it behind a
// build tag, but D-007 honors it unconditionally for ease of
// testing.
func withEUIDOverride(t *testing.T, euid string) {
	t.Helper()
	prev, hadPrev := os.LookupEnv(envEUIDOverride)
	if err := os.Setenv(envEUIDOverride, euid); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(envEUIDOverride, prev)
		} else {
			_ = os.Unsetenv(envEUIDOverride)
		}
	})
}

// runHelper is the canonical test driver: forces EUID=0 via the
// override (so all "expected-success" tests don't trip C-01),
// installs a default-failing fake conn so tests are deterministic
// regardless of whether the local environment happens to have a
// reachable system bus, then invokes run() with the given argv.
//
// Individual tests that need a SUCCESSFUL D-Bus call install
// their own fake via withFakeConn() — t.Cleanup ordering means
// the later install wins for the duration of the test.
func runHelper(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	withEUIDOverride(t, "0")
	withFakeConn(t, nil, errors.New("test: no fake conn installed; default unreachable"))
	var stdout, stderr bytes.Buffer
	exit := run(args, &stdout, &stderr)
	return exit, stdout.String(), stderr.String()
}

// parseNDJSON parses a single-line NDJSON payload. Fails the
// test if stdout has zero or more than one line.
func parseNDJSON(t *testing.T, stdout string) *response {
	t.Helper()
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected exactly one NDJSON line; got %d:\n%s",
			len(lines), stdout)
	}
	var resp response
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("unmarshal NDJSON %q: %v", lines[0], err)
	}
	return &resp
}

// ─── AC-01: subcommand + positional argument parsing ─────────────

// TestSubcommand_AcceptsKnownWithOneUnit locks the happy-path
// argv contract: each known subcommand accepts exactly one
// positional unit and produces an NDJSON response carrying the
// right op + unit fields. The default-fake-conn forces every
// subcommand into its error path (exit 1) so the test runs the
// same way in any environment.
//
// @spec agent-systemd-helper
// @ac AC-01
func TestSubcommand_AcceptsKnownWithOneUnit(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	for _, sub := range []string{"enable", "disable", "mask", "is-enabled", "unit-state"} {
		t.Run(sub, func(t *testing.T) {
			exit, stdout, _ := runHelper(t, sub, "sshd.service")
			if exit != 1 {
				t.Errorf("%s: exit got %d, want 1", sub, exit)
			}
			resp := parseNDJSON(t, stdout)
			if resp.Op != sub {
				t.Errorf("%s: op got %q, want %q", sub, resp.Op, sub)
			}
			if resp.Unit != "sshd.service" {
				t.Errorf("%s: unit got %q, want sshd.service", sub, resp.Unit)
			}
		})
	}
}

// TestSubcommand_UnknownExits2 locks the unknown-subcommand path:
// usage error on stderr, no NDJSON on stdout, exit 2.
//
// @spec agent-systemd-helper
// @ac AC-01
func TestSubcommand_UnknownExits2(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	exit, stdout, stderr := runHelper(t, "frobnicate", "sshd.service")
	if exit != 2 {
		t.Errorf("exit got %d, want 2", exit)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty for usage error; got %q", stdout)
	}
	if !strings.Contains(stderr, "unknown subcommand") {
		t.Errorf("stderr should mention 'unknown subcommand'; got %q", stderr)
	}
}

// TestSubcommand_MissingUnitExits2 locks the missing-positional
// path: every subcommand requires exactly one unit name.
//
// @spec agent-systemd-helper
// @ac AC-01
func TestSubcommand_MissingUnitExits2(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	exit, stdout, stderr := runHelper(t, "enable")
	if exit != 2 {
		t.Errorf("exit got %d, want 2", exit)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty for usage error; got %q", stdout)
	}
	if !strings.Contains(stderr, "expected exactly one unit") {
		t.Errorf("stderr should explain the missing arg; got %q", stderr)
	}
}

// TestSubcommand_ExtraPositionalExits2 locks the no-extra-args
// path: a second unit argument is a usage error.
//
// @spec agent-systemd-helper
// @ac AC-01
func TestSubcommand_ExtraPositionalExits2(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	exit, _, stderr := runHelper(t, "enable", "sshd.service", "extra")
	if exit != 2 {
		t.Errorf("exit got %d, want 2", exit)
	}
	if !strings.Contains(stderr, "expected exactly one") {
		t.Errorf("stderr should reject extra args; got %q", stderr)
	}
}

// TestNoArgs_ExitsUsageWithHelp locks bare invocation: no
// subcommand → usage on stderr → exit 2.
//
// @spec agent-systemd-helper
// @ac AC-01
func TestNoArgs_ExitsUsageWithHelp(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	exit, stdout, stderr := runHelper(t)
	if exit != 2 {
		t.Errorf("exit got %d, want 2", exit)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty for usage error; got %q", stdout)
	}
	if !strings.Contains(stderr, "Subcommands:") {
		t.Errorf("stderr should print usage; got %q", stderr)
	}
}

// TestHelpFlagExitsZero locks --help: stdout gets usage, exit 0.
//
// @spec agent-systemd-helper
// @ac AC-01
func TestHelpFlagExitsZero(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	for _, flag := range []string{"--help", "-h"} {
		t.Run(flag, func(t *testing.T) {
			exit, stdout, _ := runHelper(t, "enable", "sshd.service", flag)
			if exit != 0 {
				t.Errorf("%s: exit got %d, want 0", flag, exit)
			}
			if !strings.Contains(stdout, "Subcommands:") {
				t.Errorf("%s: stdout should contain usage; got %q", flag, stdout)
			}
		})
	}
}

// ─── AC-02: non-root invocation rejected ─────────────────────────

// TestNonRoot_ExitsUsageError locks spec C-01 / AC-02: invocation
// with a non-root EUID is a usage error, exit 2, with a stderr
// message pointing at the sudoers fragment.
//
// @spec agent-systemd-helper
// @ac AC-02
func TestNonRoot_ExitsUsageError(t *testing.T) {
	t.Run("agent-systemd-helper/AC-02", func(t *testing.T) {})
	withEUIDOverride(t, "1000")
	var stdout, stderr bytes.Buffer
	exit := run([]string{"enable", "sshd.service"}, &stdout, &stderr)
	if exit != 2 {
		t.Errorf("non-root invocation: exit got %d, want 2", exit)
	}
	if stdout.Len() != 0 {
		t.Errorf("non-root invocation: stdout should be empty; got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "must run as root") {
		t.Errorf("non-root invocation: stderr should mention root requirement; got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "sudo") {
		t.Errorf("non-root invocation: stderr should direct operator to sudo; got %q", stderr.String())
	}
}

// ─── AC-03 / AC-04: NDJSON output shape ──────────────────────────

// TestStubResponse_HasRequiredEnvelopeFields locks the NDJSON
// envelope shape per spec AC-04 (failure block). Uses the
// `disable` subcommand which still emits the not_yet_implemented
// stub in D-008 (D-009 / D-010 land disable / mask), so the
// envelope-shape assertion is independent of the D-Bus
// implementation.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestStubResponse_HasRequiredEnvelopeFields(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	exit, stdout, _ := runHelper(t, "disable", "sshd.service")
	if exit != 1 {
		t.Errorf("disable stub: exit got %d, want 1 (runtime error path)", exit)
	}
	resp := parseNDJSON(t, stdout)
	if resp.SchemaVersion != 1 {
		t.Errorf("schema_version got %d, want 1", resp.SchemaVersion)
	}
	if resp.HelperVersion == "" {
		t.Error("helper_version should be set on every line (AC-10)")
	}
	if resp.Op != "disable" {
		t.Errorf("op got %q, want disable", resp.Op)
	}
	if resp.Unit != "sshd.service" {
		t.Errorf("unit got %q, want sshd.service", resp.Unit)
	}
	if resp.Success {
		t.Error("stub should report success:false")
	}
	if resp.Error == nil {
		t.Fatal("stub should include an error block")
	}
	if resp.Error.Code != "not_yet_implemented" {
		t.Errorf("error.code got %q, want not_yet_implemented", resp.Error.Code)
	}
	if resp.Error.Detail == "" {
		t.Error("error.detail should be non-empty")
	}
}

// TestStdoutIsExactlyOneNDJSONLine locks spec C-02: stdout
// carries EXACTLY one NDJSON line per invocation. No leading
// blank lines, no trailing junk, no log lines, no embedded
// newlines inside the JSON object. Critical because the agent
// parses stdout as NDJSON; extra bytes corrupt parsing.
//
// @spec agent-systemd-helper
// @ac AC-03
func TestStdoutIsExactlyOneNDJSONLine(t *testing.T) {
	t.Run("agent-systemd-helper/AC-03", func(t *testing.T) {})
	_, stdout, _ := runHelper(t, "enable", "sshd.service")
	if !strings.HasSuffix(stdout, "\n") {
		t.Errorf("stdout should end with newline; got %q", stdout)
	}
	if strings.Count(stdout, "\n") != 1 {
		t.Errorf("stdout should contain exactly one newline; got %d (%q)",
			strings.Count(stdout, "\n"), stdout)
	}
	// JSON object must not contain a raw newline inside it.
	withoutTrailing := strings.TrimSuffix(stdout, "\n")
	if strings.Contains(withoutTrailing, "\n") {
		t.Errorf("NDJSON object must not contain embedded newlines; got %q", stdout)
	}
}

// ─── AC-06: --timeout flag parsing ───────────────────────────────

// TestTimeoutFlag_DefaultIs60 locks the default-timeout contract
// (60s per founder decision 2026-05-13). Since the D-007 stub
// doesn't actually wait, this test only verifies that
// `--timeout` parses without error using the default.
//
// @spec agent-systemd-helper
// @ac AC-06
func TestTimeoutFlag_DefaultIs60(t *testing.T) {
	t.Run("agent-systemd-helper/AC-06", func(t *testing.T) {})
	if defaultTimeout != 60 {
		t.Errorf("defaultTimeout got %d, want 60 (per founder decision 2026-05-13)", defaultTimeout)
	}
	// Default invocation (no --timeout) should parse cleanly.
	exit, stdout, _ := runHelper(t, "enable", "sshd.service")
	if exit != 1 {
		t.Errorf("default-timeout invocation: exit got %d, want 1 (stub)", exit)
	}
	if !strings.Contains(stdout, `"op":"enable"`) {
		t.Errorf("default-timeout invocation: expected enable response; got %q", stdout)
	}
}

// TestTimeoutFlag_AcceptsExplicit locks the --timeout override.
//
// @spec agent-systemd-helper
// @ac AC-06
func TestTimeoutFlag_AcceptsExplicit(t *testing.T) {
	t.Run("agent-systemd-helper/AC-06", func(t *testing.T) {})
	exit, stdout, _ := runHelper(t, "enable", "sshd.service", "--timeout=15")
	if exit != 1 {
		t.Errorf("--timeout=15: exit got %d, want 1 (stub)", exit)
	}
	if !strings.Contains(stdout, `"op":"enable"`) {
		t.Errorf("--timeout=15: expected enable response; got %q", stdout)
	}
}

// TestTimeoutFlag_RejectsNonNumeric locks pflag-level type
// validation: --timeout=abc is a usage error.
//
// @spec agent-systemd-helper
// @ac AC-06
func TestTimeoutFlag_RejectsNonNumeric(t *testing.T) {
	t.Run("agent-systemd-helper/AC-06", func(t *testing.T) {})
	exit, stdout, stderr := runHelper(t, "enable", "sshd.service", "--timeout=abc")
	if exit != 2 {
		t.Errorf("--timeout=abc: exit got %d, want 2", exit)
	}
	if stdout != "" {
		t.Errorf("--timeout=abc: stdout should be empty for usage error; got %q", stdout)
	}
	if !strings.Contains(stderr, "timeout") && !strings.Contains(stderr, "invalid") {
		t.Errorf("--timeout=abc: stderr should reject the value; got %q", stderr)
	}
}

// ─── AC-10: version envelope ─────────────────────────────────────

// TestHelperVersion_PresentInEveryLine locks AC-10: every NDJSON
// line carries `helper_version` so the agent can detect skew.
//
// @spec agent-systemd-helper
// @ac AC-10
func TestHelperVersion_PresentInEveryLine(t *testing.T) {
	t.Run("agent-systemd-helper/AC-10", func(t *testing.T) {})
	for _, sub := range []string{"enable", "disable", "mask", "is-enabled", "unit-state"} {
		t.Run(sub, func(t *testing.T) {
			_, stdout, _ := runHelper(t, sub, "sshd.service")
			resp := parseNDJSON(t, stdout)
			if resp.HelperVersion == "" {
				t.Errorf("%s: helper_version missing from NDJSON line", sub)
			}
			if resp.SchemaVersion != 1 {
				t.Errorf("%s: schema_version got %d, want 1", sub, resp.SchemaVersion)
			}
		})
	}
}

// TestHelperVersion_DefaultIsDev locks the developer-build default
// "dev" so unit tests don't need to inject a version via ldflags.
// Production builds override via -X main.version=<release>.
//
// @spec agent-systemd-helper
// @ac AC-10
func TestHelperVersion_DefaultIsDev(t *testing.T) {
	t.Run("agent-systemd-helper/AC-10", func(t *testing.T) {})
	if version != "dev" {
		t.Errorf("default version got %q, want \"dev\"", version)
	}
}
