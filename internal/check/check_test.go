package check

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// fakeTransport is a test double for [api.Transport]. Each call to Run
// records the command and returns the configured [api.CommandResult].
// If the command matches a key in errOn, a transport-level error is
// returned instead.
type fakeTransport struct {
	// cmdResult maps a command string to the result to return.
	cmdResult map[string]api.CommandResult
	// errOn maps a command string to the error to return.
	errOn map[string]error
}

func (f *fakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	if err, ok := f.errOn[cmd]; ok {
		return nil, err
	}
	if r, ok := f.cmdResult[cmd]; ok {
		return &r, nil
	}
	// Default: non-zero exit.
	return &api.CommandResult{ExitCode: 1, Duration: time.Millisecond}, nil
}

func (f *fakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (f *fakeTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (f *fakeTransport) ControlChannelSensitive() bool                           { return false }
func (f *fakeTransport) Close() error                                            { return nil }

// result is a helper to build [api.CommandResult] values concisely.
func result(exitCode int, stdout string) api.CommandResult {
	return api.CommandResult{ExitCode: exitCode, Stdout: stdout, Duration: time.Millisecond}
}

// TestCheckConfigValue_Pass verifies that config_value passes when the
// grep returns a matching key=value line.
func TestCheckConfigValue_Pass(t *testing.T) {
	cmd := "grep -E '\\^\\\\s\\*PermitRootLogin\\\\s\\*[=:]\\\\s\\*' '/etc/ssh/sshd_config' 2>/dev/null"
	_ = cmd
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"grep -E '^\\s*PermitRootLogin\\s*[=:]\\s*' '/etc/ssh/sshd_config' 2>/dev/null": result(0, "PermitRootLogin = no"),
		},
	}
	chk := api.Check{
		Method: "config_value",
		Params: api.Params{
			"path":     "/etc/ssh/sshd_config",
			"key":      "PermitRootLogin",
			"expected": "no",
		},
	}
	passed, detail, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Errorf("expected pass, got fail; detail: %s", detail)
	}
}

// TestCheckConfigValue_Fail verifies that config_value fails when the
// value does not match.
func TestCheckConfigValue_Fail(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"grep -E '^\\s*PermitRootLogin\\s*[=:]\\s*' '/etc/ssh/sshd_config' 2>/dev/null": result(0, "PermitRootLogin = yes"),
		},
	}
	chk := api.Check{
		Method: "config_value",
		Params: api.Params{
			"path":     "/etc/ssh/sshd_config",
			"key":      "PermitRootLogin",
			"expected": "no",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckConfigValue_KeyNotFound verifies that config_value fails
// when grep returns exit 1 (key absent).
func TestCheckConfigValue_KeyNotFound(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}} // default exit 1
	chk := api.Check{
		Method: "config_value",
		Params: api.Params{
			"path":     "/etc/ssh/sshd_config",
			"key":      "PermitRootLogin",
			"expected": "no",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail for missing key, got pass")
	}
}

// TestCheckSysctlValue_Pass verifies that sysctl_value passes when the
// kernel reports the expected value.
func TestCheckSysctlValue_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"sysctl -n 'net.ipv4.ip_forward'": result(0, "0\n"),
		},
	}
	chk := api.Check{
		Method: "sysctl_value",
		Params: api.Params{"key": "net.ipv4.ip_forward", "expected": "0"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckSysctlValue_Fail verifies that sysctl_value fails when the
// value does not match.
func TestCheckSysctlValue_Fail(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"sysctl -n 'net.ipv4.ip_forward'": result(0, "1\n"),
		},
	}
	chk := api.Check{
		Method: "sysctl_value",
		Params: api.Params{"key": "net.ipv4.ip_forward", "expected": "0"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckPackageInstalled_Pass verifies that package_installed passes
// when the composite rpm-or-dpkg probe exits 0.
func TestCheckPackageInstalled_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"rpm -q 'aide' >/dev/null 2>&1 || (command -v dpkg >/dev/null 2>&1 && dpkg -l 'aide' 2>/dev/null | grep -q '^ii')": result(0, ""),
		},
	}
	chk := api.Check{
		Method: "package_installed",
		Params: api.Params{"name": "aide"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckPackageInstalled_Fail verifies that package_installed fails
// when rpm exits non-zero.
func TestCheckPackageInstalled_Fail(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}}
	chk := api.Check{
		Method: "package_installed",
		Params: api.Params{"name": "aide"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckPackageAbsent_Pass verifies that package_absent passes when
// the composite absent probe exits 0 (absent from both rpm and dpkg).
func TestCheckPackageAbsent_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"! rpm -q 'telnet' >/dev/null 2>&1 && ! (command -v dpkg >/dev/null 2>&1 && dpkg -l 'telnet' 2>/dev/null | grep -q '^ii')": result(0, ""),
		},
	}
	chk := api.Check{
		Method: "package_absent",
		Params: api.Params{"name": "telnet"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckPackageAbsent_Fail verifies that package_absent fails when
// the composite absent probe exits non-zero (package is present).
func TestCheckPackageAbsent_Fail(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"! rpm -q 'telnet' >/dev/null 2>&1 && ! (command -v dpkg >/dev/null 2>&1 && dpkg -l 'telnet' 2>/dev/null | grep -q '^ii')": result(1, ""),
		},
	}
	chk := api.Check{
		Method: "package_absent",
		Params: api.Params{"name": "telnet"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckFileExists_Pass verifies that file_exists passes when the
// test command exits 0.
func TestCheckFileExists_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"[ -e '/etc/passwd' ]": result(0, ""),
		},
	}
	chk := api.Check{
		Method: "file_exists",
		Params: api.Params{"path": "/etc/passwd"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckFileExists_Fail verifies that file_exists fails when the
// test command exits non-zero.
func TestCheckFileExists_Fail(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}}
	chk := api.Check{
		Method: "file_exists",
		Params: api.Params{"path": "/etc/passwd"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckFileAbsent_Pass verifies that file_absent passes when the
// negated test exits 0 (file does not exist).
func TestCheckFileAbsent_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"[ ! -e '/tmp/gone' ]": result(0, ""),
		},
	}
	chk := api.Check{
		Method: "file_absent",
		Params: api.Params{"path": "/tmp/gone"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckFileAbsent_Fail verifies that file_absent fails when the
// negated test exits non-zero (file exists).
func TestCheckFileAbsent_Fail(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}}
	chk := api.Check{
		Method: "file_absent",
		Params: api.Params{"path": "/tmp/gone"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckFilePermissions_Pass verifies that file_permissions passes
// when mode, owner, and group all match.
func TestCheckFilePermissions_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"stat -c '%a %U %G' '/etc/shadow'": result(0, "640 root shadow\n"),
		},
	}
	chk := api.Check{
		Method: "file_permissions",
		Params: api.Params{
			"path":  "/etc/shadow",
			"mode":  "640",
			"owner": "root",
			"group": "shadow",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckFilePermissions_WrongMode verifies that file_permissions
// fails when the mode does not match.
func TestCheckFilePermissions_WrongMode(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"stat -c '%a %U %G' '/etc/shadow'": result(0, "644 root shadow\n"),
		},
	}
	chk := api.Check{
		Method: "file_permissions",
		Params: api.Params{
			"path":  "/etc/shadow",
			"mode":  "640",
			"owner": "root",
			"group": "shadow",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail for wrong mode, got pass")
	}
}

// TestCheckFilePermissions_WrongOwner verifies that file_permissions
// fails when the owner does not match.
func TestCheckFilePermissions_WrongOwner(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"stat -c '%a %U %G' '/etc/shadow'": result(0, "640 nobody shadow\n"),
		},
	}
	chk := api.Check{
		Method: "file_permissions",
		Params: api.Params{
			"path":  "/etc/shadow",
			"mode":  "640",
			"owner": "root",
			"group": "shadow",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail for wrong owner, got pass")
	}
}

// TestCheckFileContentMatch_Pass verifies that file_content_match
// passes when grep exits 0.
func TestCheckFileContentMatch_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"grep -qE 'PermitRootLogin\\s+no' '/etc/ssh/sshd_config'": result(0, ""),
		},
	}
	chk := api.Check{
		Method: "file_content_match",
		Params: api.Params{
			"path":    "/etc/ssh/sshd_config",
			"pattern": "PermitRootLogin\\s+no",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckFileContentMatch_Fail verifies that file_content_match
// fails when grep exits non-zero (pattern absent).
func TestCheckFileContentMatch_Fail(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}}
	chk := api.Check{
		Method: "file_content_match",
		Params: api.Params{
			"path":    "/etc/ssh/sshd_config",
			"pattern": "PermitRootLogin\\s+no",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckServiceEnabled_Pass verifies that service_enabled passes
// when systemctl reports "enabled".
func TestCheckServiceEnabled_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"systemctl is-enabled 'auditd'": result(0, "enabled\n"),
		},
	}
	chk := api.Check{
		Method: "service_enabled",
		Params: api.Params{"name": "auditd"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckServiceEnabled_Fail verifies that service_enabled fails
// when systemctl reports "disabled".
func TestCheckServiceEnabled_Fail(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"systemctl is-enabled 'auditd'": result(1, "disabled\n"),
		},
	}
	chk := api.Check{
		Method: "service_enabled",
		Params: api.Params{"name": "auditd"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckServiceActive_Pass verifies that service_active passes when
// systemctl is-active exits 0.
func TestCheckServiceActive_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"systemctl is-active 'sshd'": result(0, "active\n"),
		},
	}
	chk := api.Check{
		Method: "service_active",
		Params: api.Params{"name": "sshd"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckServiceActive_Fail verifies that service_active fails when
// systemctl is-active exits non-zero.
func TestCheckServiceActive_Fail(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}}
	chk := api.Check{
		Method: "service_active",
		Params: api.Params{"name": "sshd"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckCommand_Pass verifies that command passes when the command
// exits 0.
func TestCheckCommand_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"id -u": result(0, "0\n"),
		},
	}
	chk := api.Check{
		Method: "command",
		Params: api.Params{"cmd": "id -u"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckCommand_Fail verifies that command fails when the command
// exits non-zero.
func TestCheckCommand_Fail(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}}
	chk := api.Check{
		Method: "command",
		Params: api.Params{"cmd": "false"},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail, got pass")
	}
}

// TestCheckCommand_ExpectedOutput_Pass verifies that command passes
// when expected_output is found in stdout.
func TestCheckCommand_ExpectedOutput_Pass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"fips-mode-setup --check": result(0, "FIPS mode is enabled\n"),
		},
	}
	chk := api.Check{
		Method: "command",
		Params: api.Params{
			"cmd":             "fips-mode-setup --check",
			"expected_output": "FIPS mode is enabled",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Error("expected pass, got fail")
	}
}

// TestCheckCommand_ExpectedOutput_Fail verifies that command fails
// when expected_output is not present in stdout.
func TestCheckCommand_ExpectedOutput_Fail(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"fips-mode-setup --check": result(0, "FIPS mode is not enabled\n"),
		},
	}
	chk := api.Check{
		Method: "command",
		Params: api.Params{
			"cmd":             "fips-mode-setup --check",
			"expected_output": "FIPS mode is enabled",
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected fail when expected_output not found, got pass")
	}
}

// TestCheckUnknownMethod verifies that an unknown check method returns
// an error.
func TestCheckUnknownMethod(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}}
	chk := api.Check{Method: "no_such_method", Params: api.Params{}}
	_, _, err := Run(context.Background(), ft, chk)
	if err == nil {
		t.Error("expected error for unknown method, got nil")
	}
}

// TestCheckMulti_AllPass verifies that multi-check AND composition
// passes when every child check passes.
func TestCheckMulti_AllPass(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"[ -e '/etc/passwd' ]": result(0, ""),
			"[ -e '/etc/shadow' ]": result(0, ""),
			"[ -e '/etc/hosts' ]":  result(0, ""),
		},
	}
	chk := api.Check{
		Checks: []api.Check{
			{Method: "file_exists", Params: api.Params{"path": "/etc/passwd"}},
			{Method: "file_exists", Params: api.Params{"path": "/etc/shadow"}},
			{Method: "file_exists", Params: api.Params{"path": "/etc/hosts"}},
		},
	}
	passed, detail, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !passed {
		t.Errorf("expected all-pass multi-check to pass; detail: %s", detail)
	}
}

// TestCheckMulti_OneFails verifies that multi-check AND composition
// fails when any single child check fails.
func TestCheckMulti_OneFails(t *testing.T) {
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"[ -e '/etc/passwd' ]": result(0, ""),
			// /etc/missing returns default exit 1
		},
	}
	chk := api.Check{
		Checks: []api.Check{
			{Method: "file_exists", Params: api.Params{"path": "/etc/passwd"}},
			{Method: "file_exists", Params: api.Params{"path": "/etc/missing"}},
		},
	}
	passed, detail, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Errorf("expected multi-check to fail when one child fails; detail: %s", detail)
	}
}

// TestCheckMulti_AllFail verifies that multi-check AND composition
// fails when every child fails.
func TestCheckMulti_AllFail(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{}}
	chk := api.Check{
		Checks: []api.Check{
			{Method: "file_exists", Params: api.Params{"path": "/nonexistent/a"}},
			{Method: "file_exists", Params: api.Params{"path": "/nonexistent/b"}},
		},
	}
	passed, _, err := Run(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected multi-check to fail when all children fail")
	}
}
