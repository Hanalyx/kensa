// Tests for the agent-side systemd helper wrapper. D-007
// scope: subprocess invocation, NDJSON parse, schema-version
// check, error typing. Tests inject a fake runner instead of
// spawning a real subprocess so they run identically in CI on
// any host (no sudo, no systemd).
package systemd

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// fakeRunner returns a runner that captures the argv it was
// called with and returns the supplied stdout/stderr/exitCode/err.
// The captured argv lets tests assert that the wrapper builds
// the right subprocess invocation.
func fakeRunner(stdout, stderr []byte, exitCode int, runErr error) (*[]string, func(ctx context.Context, argv []string) ([]byte, []byte, int, error)) {
	captured := &[]string{}
	return captured, func(_ context.Context, argv []string) ([]byte, []byte, int, error) {
		*captured = append([]string(nil), argv...)
		return stdout, stderr, exitCode, runErr
	}
}

// ─── Argv contract ──────────────────────────────────────────────

// TestInvoke_BuildsSudoArgv locks the subprocess-invocation
// contract: agent invokes `sudo <helperPath> <op> <unit>`. The helper is NEVER invoked directly (no setuid;
// sudo is the auditable path per the kensa-rpm sudoers fragment).
//
// @spec agent-systemd-helper
// @ac AC-01
func TestInvoke_BuildsSudoArgv(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	stdout := []byte(`{"schema_version":1,"helper_version":"dev","op":"enable","unit":"sshd.service","success":true,"settled_state":"enabled"}` + "\n")
	captured, runner := fakeRunner(stdout, nil, 0, nil)
	c := withRunner("/opt/kensa/bin/kensa-systemd-helper", runner)

	_, err := c.Enable(context.Background(), "sshd.service")
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	want := []string{"sudo", "/opt/kensa/bin/kensa-systemd-helper", "enable", "sshd.service"}
	if len(*captured) != len(want) {
		t.Fatalf("argv length: got %d, want %d (%v)", len(*captured), len(want), *captured)
	}
	for i := range want {
		if (*captured)[i] != want[i] {
			t.Errorf("argv[%d]: got %q, want %q", i, (*captured)[i], want[i])
		}
	}
}

// TestAllOps_BuildCorrectSubcommand walks the five subcommands
// and confirms each lands the right argv[2].
//
// @spec agent-systemd-helper
// @ac AC-01
func TestAllOps_BuildCorrectSubcommand(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	cases := []struct {
		name   string
		invoke func(c *Client) (*Response, error)
		want   string
	}{
		{"Enable", func(c *Client) (*Response, error) { return c.Enable(context.Background(), "x.service") }, "enable"},
		{"Disable", func(c *Client) (*Response, error) { return c.Disable(context.Background(), "x.service") }, "disable"},
		{"Mask", func(c *Client) (*Response, error) { return c.Mask(context.Background(), "x.service") }, "mask"},
		{"Unmask", func(c *Client) (*Response, error) { return c.Unmask(context.Background(), "x.service") }, "unmask"},
		{"IsEnabled", func(c *Client) (*Response, error) { return c.IsEnabled(context.Background(), "x.service") }, "is-enabled"},
		{"UnitState", func(c *Client) (*Response, error) { return c.UnitState(context.Background(), "x.service") }, "unit-state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout := []byte(fmt.Sprintf(`{"schema_version":1,"helper_version":"dev","op":%q,"unit":"x.service","success":true}`+"\n", tc.want))
			captured, runner := fakeRunner(stdout, nil, 0, nil)
			c := withRunner(HelperPath, runner)
			if _, err := tc.invoke(c); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if (*captured)[2] != tc.want {
				t.Errorf("argv[2] got %q, want %q", (*captured)[2], tc.want)
			}
		})
	}
}

// ─── NDJSON parsing ─────────────────────────────────────────────

// TestParse_SuccessResponse locks the happy-path parse: helper
// emits success:true NDJSON; wrapper returns Response with no
// error.
//
// @spec agent-systemd-helper
// @ac AC-03
func TestParse_SuccessResponse(t *testing.T) {
	t.Run("agent-systemd-helper/AC-03", func(t *testing.T) {})
	stdout := []byte(`{"schema_version":1,"helper_version":"dev","op":"enable","unit":"sshd.service","success":true,"job_id":42,"settled_state":"enabled","duration_ms":15,"changes":[{"type":"symlink","src":"/etc/systemd/system/multi-user.target.wants/sshd.service","dst":"/usr/lib/systemd/system/sshd.service"}]}` + "\n")
	_, runner := fakeRunner(stdout, nil, 0, nil)
	c := withRunner(HelperPath, runner)
	resp, err := c.Enable(context.Background(), "sshd.service")
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
	if resp.JobID != 42 {
		t.Errorf("JobID got %d, want 42", resp.JobID)
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
}

// TestParse_FailureResponse locks the helper-reported-failure
// path: helper exits 1 with success:false + error block; wrapper
// returns a typed HelperError that errors.Is matches
// ErrHelperFailed and errors.As extracts to *HelperError.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestParse_FailureResponse(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	stdout := []byte(`{"schema_version":1,"helper_version":"dev","op":"enable","unit":"missing.service","success":false,"error":{"code":"no_such_unit","dbus_name":"org.freedesktop.systemd1.NoSuchUnit","detail":"Unit missing.service not found."}}` + "\n")
	_, runner := fakeRunner(stdout, nil, 1, nil)
	c := withRunner(HelperPath, runner)
	resp, err := c.Enable(context.Background(), "missing.service")
	if err == nil {
		t.Fatal("Enable should return an error for failure response")
	}
	if !errors.Is(err, ErrHelperFailed) {
		t.Errorf("errors.Is(err, ErrHelperFailed) should be true; err=%v", err)
	}
	var herr *HelperError
	if !errors.As(err, &herr) {
		t.Fatalf("errors.As(err, *HelperError) should succeed; err=%v", err)
	}
	if herr.Code != "no_such_unit" {
		t.Errorf("HelperError.Code got %q, want no_such_unit", herr.Code)
	}
	if herr.DBusName != "org.freedesktop.systemd1.NoSuchUnit" {
		t.Errorf("HelperError.DBusName got %q", herr.DBusName)
	}
	// Response struct is still returned alongside the error so
	// callers can inspect partial-state fields if useful.
	if resp == nil {
		t.Fatal("Response should be non-nil even on failure path")
	}
	if resp.Success {
		t.Error("Response.Success should be false")
	}
}

// TestParse_RejectsMalformedJSON locks the defensive-parse path
// per spec C-02: non-NDJSON stdout fails closed with
// ErrHelperOutputMalformed rather than a silent wrong-result.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestParse_RejectsMalformedJSON(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	stdout := []byte("this is not JSON\n")
	_, runner := fakeRunner(stdout, nil, 1, nil)
	c := withRunner(HelperPath, runner)
	_, err := c.Enable(context.Background(), "x.service")
	if !errors.Is(err, ErrHelperOutputMalformed) {
		t.Errorf("err should be ErrHelperOutputMalformed; got %v", err)
	}
}

// TestParse_RejectsEmptyStdout locks the empty-output edge case.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestParse_RejectsEmptyStdout(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	_, runner := fakeRunner(nil, []byte("crashed"), 1, nil)
	c := withRunner(HelperPath, runner)
	_, err := c.Enable(context.Background(), "x.service")
	if !errors.Is(err, ErrHelperOutputMalformed) {
		t.Errorf("err should be ErrHelperOutputMalformed; got %v", err)
	}
}

// TestParse_RejectsMissingSchemaVersion locks the schema-version
// envelope requirement (spec C-04): a JSON line without
// schema_version is treated as malformed.
//
// @spec agent-systemd-helper
// @ac AC-04
func TestParse_RejectsMissingSchemaVersion(t *testing.T) {
	t.Run("agent-systemd-helper/AC-04", func(t *testing.T) {})
	stdout := []byte(`{"helper_version":"dev","op":"enable","unit":"x","success":true}` + "\n")
	_, runner := fakeRunner(stdout, nil, 0, nil)
	c := withRunner(HelperPath, runner)
	_, err := c.Enable(context.Background(), "x")
	if !errors.Is(err, ErrHelperOutputMalformed) {
		t.Errorf("err should be ErrHelperOutputMalformed; got %v", err)
	}
}

// TestParse_TolerantOfTrailingBlankLines accepts NDJSON streams
// where the helper happens to emit a trailing blank line (e.g.,
// shell pipeline appending `\n\n`). Per spec C-02 the helper
// shouldn't, but defense-in-depth: trailing whitespace doesn't
// corrupt the parse.
//
// @spec agent-systemd-helper
// @ac AC-03
func TestParse_TolerantOfTrailingBlankLines(t *testing.T) {
	t.Run("agent-systemd-helper/AC-03", func(t *testing.T) {})
	stdout := []byte(`{"schema_version":1,"helper_version":"dev","op":"enable","unit":"x","success":true}` + "\n\n\n")
	_, runner := fakeRunner(stdout, nil, 0, nil)
	c := withRunner(HelperPath, runner)
	resp, err := c.Enable(context.Background(), "x")
	if err != nil {
		t.Fatalf("trailing blanks: %v", err)
	}
	if !resp.Success {
		t.Error("Success should be true")
	}
}

// ─── Schema-version skew (load-bearing check per AC-10) ──────────

// TestSchemaVersion_RejectsUnknown locks the fail-closed path
// per spec C-04 / AC-10: helper reports schema_version we don't
// understand → ErrSchemaUnsupported, operation fails.
//
// @spec agent-systemd-helper
// @ac AC-10
func TestSchemaVersion_RejectsUnknown(t *testing.T) {
	t.Run("agent-systemd-helper/AC-10", func(t *testing.T) {})
	stdout := []byte(`{"schema_version":99,"helper_version":"dev","op":"enable","unit":"x","success":true}` + "\n")
	_, runner := fakeRunner(stdout, nil, 0, nil)
	c := withRunner(HelperPath, runner)
	_, err := c.Enable(context.Background(), "x")
	if !errors.Is(err, ErrSchemaUnsupported) {
		t.Errorf("err should be ErrSchemaUnsupported; got %v", err)
	}
	// Error message should mention both versions so the operator
	// can diagnose the skew.
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("error should mention got schema 99; got %v", err)
	}
	if !strings.Contains(err.Error(), "1") {
		t.Errorf("error should mention want schema 1; got %v", err)
	}
}

// TestBinaryVersionSkew_IsWarningOnly locks the founder-ratified
// decision that binary-version mismatch is INFORMATIONAL only —
// the operation must succeed, not fail, when the helper's binary
// version differs from the agent's. Schema version (above) is
// what the contract rides on.
//
// @spec agent-systemd-helper
// @ac AC-10
func TestBinaryVersionSkew_IsWarningOnly(t *testing.T) {
	t.Run("agent-systemd-helper/AC-10", func(t *testing.T) {})
	stdout := []byte(`{"schema_version":1,"helper_version":"v0.99.0-old","op":"enable","unit":"x","success":true}` + "\n")
	_, runner := fakeRunner(stdout, nil, 0, nil)
	c := withRunner(HelperPath, runner)
	resp, err := c.Enable(context.Background(), "x")
	if err != nil {
		t.Fatalf("binary version skew should NOT fail; got %v", err)
	}
	if !resp.Success {
		t.Error("Response.Success should be true (skew is informational only)")
	}
	if resp.HelperVersion != "v0.99.0-old" {
		t.Errorf("HelperVersion got %q, want v0.99.0-old", resp.HelperVersion)
	}
}

// ─── Subprocess exit code routing ───────────────────────────────

// TestExit2_FromHelper_IsUsageError locks the helper's exit-2
// path: helper rejected the invocation (e.g., non-root,
// unknown subcommand). No NDJSON to parse; wrapper returns a
// plain error with the stderr message.
//
// @spec agent-systemd-helper
// @ac AC-01
func TestExit2_FromHelper_IsUsageError(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	stderr := []byte("kensa-systemd-helper: must run as root (EUID=1000)\n")
	_, runner := fakeRunner(nil, stderr, 2, nil)
	c := withRunner(HelperPath, runner)
	_, err := c.Enable(context.Background(), "x")
	if err == nil {
		t.Fatal("exit 2 should produce an error")
	}
	if !strings.Contains(err.Error(), "must run as root") {
		t.Errorf("error should include helper stderr; got %v", err)
	}
}

// TestExecError_HelperNotFound surfaces the
// "binary missing" path with a typed error so packaging bugs are
// distinguishable from runtime failures.
//
// @spec agent-systemd-helper
// @ac AC-01
func TestExecError_HelperNotFound(t *testing.T) {
	t.Run("agent-systemd-helper/AC-01", func(t *testing.T) {})
	_, runner := fakeRunner(nil, nil, 0, fmt.Errorf("exec: %w", exec.ErrNotFound))
	c := withRunner("/nonexistent/kensa-systemd-helper", runner)
	_, err := c.Enable(context.Background(), "x")
	if !errors.Is(err, ErrHelperNotFound) {
		t.Errorf("err should be ErrHelperNotFound; got %v", err)
	}
}
