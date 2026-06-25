package check

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// runForTest adapts the structured [Run] to the legacy (passed, detail, err)
// triple the per-method check tests assert against. The structured Result and
// its evidence are exercised separately in evidence_test.go.
func runForTest(ctx context.Context, t api.Transport, chk api.Check) (bool, string, error) {
	res, err := Run(ctx, t, chk)
	return res.Passed, res.Detail, err
}

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

// TestCheckCommand_EmptyStdoutAsserts locks the fix for the empty-output false
// pass: a command check with expected_stdout/expected_output set to "" asserts
// the command produced NO output (the "find ... | head -1 → no violations"
// idiom). Previously an empty value was treated as "no assertion", so such a
// check passed on any exit-0 command regardless of output — the ~41-rule false
// pass (incl. accounts-no-empty-passwords) this guards against.
func TestCheckCommand_EmptyStdoutAsserts(t *testing.T) {
	const cmd = "find /var/log/journal ! -user root -type f 2>/dev/null | head -1"
	chk := func(key string) api.Check {
		return api.Check{Method: "command", Params: api.Params{"run": cmd, key: ""}}
	}
	for _, key := range []string{"expected_stdout", "expected_output"} {
		// Compliant host: command exits 0 with no output -> PASS.
		clean := &fakeTransport{cmdResult: map[string]api.CommandResult{cmd: result(0, "")}}
		if passed, detail, err := runForTest(context.Background(), clean, chk(key)); err != nil || !passed {
			t.Fatalf("%s: empty output should pass; passed=%v detail=%q err=%v", key, passed, detail, err)
		}
		// Violation present: command exits 0 BUT prints an offending path -> FAIL.
		dirty := &fakeTransport{cmdResult: map[string]api.CommandResult{
			cmd: result(0, "/var/log/journal/abcd/system.journal\n"),
		}}
		passed, detail, err := runForTest(context.Background(), dirty, chk(key))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", key, err)
		}
		if passed {
			t.Errorf("%s: non-empty output must fail the empty assertion (false pass): %s", key, detail)
		}
	}
}

// TestCheckCommand_NoOutputAssertionExitOnly confirms a command check with
// neither expected_stdout nor expected_output still checks only the exit code,
// so the empty-assertion fix does not change exit-only command rules.
func TestCheckCommand_NoOutputAssertionExitOnly(t *testing.T) {
	const cmd = "systemctl is-enabled ufw"
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{cmd: result(0, "enabled\n")}}
	chk := api.Check{Method: "command", Params: api.Params{"run": cmd}}
	if passed, detail, err := runForTest(context.Background(), ft, chk); err != nil || !passed {
		t.Fatalf("exit-only command with output should still pass; passed=%v detail=%q err=%v", passed, detail, err)
	}
}

// TestCheckAuditRuleExists_WatchFullMatch locks the fix for the key-only
// false pass: a watch rule must match the full path+perms+key, not merely
// the presence of its -k key. Several per-file watches can share one key
// (the Ubuntu usergroup_modification cluster), so loading one must NOT
// satisfy the checks for the others.
func TestCheckAuditRuleExists_WatchFullMatch(t *testing.T) {
	// Only /etc/group is loaded; its key usergroup_modification is present.
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{
			"auditctl -l 2>/dev/null": result(0, "-w /etc/group -p wa -k usergroup_modification"),
		},
	}
	watch := func(path string) api.Check {
		return api.Check{Method: "audit_rule_exists", Params: api.Params{
			"rule": "-w " + path + " -p wa -k usergroup_modification",
		}}
	}
	// The loaded watch matches itself.
	if passed, _, err := runForTest(context.Background(), ft, watch("/etc/group")); err != nil || !passed {
		t.Fatalf("loaded /etc/group watch should pass; passed=%v err=%v", passed, err)
	}
	// A different file sharing the same key must NOT pass (the old bug).
	for _, p := range []string{"/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/security/opasswd"} {
		passed, detail, err := runForTest(context.Background(), ft, watch(p))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", p, err)
		}
		if passed {
			t.Errorf("%s watch not loaded but check passed (key-only false pass): %s", p, detail)
		}
	}
}

// TestCheckAuditRuleExists_ExecPathMatch locks the path match for
// privileged-command exec rules: several commands share a -k key (priv_cmd,
// perm_chng, ...), so a key-only match would falsely pass every command once
// one is loaded. The -F path= field distinguishes them.
func TestCheckAuditRuleExists_ExecPathMatch(t *testing.T) {
	// Only /usr/bin/sudo is loaded; its key priv_cmd is shared with chsh etc.
	loaded := "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd"
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{"auditctl -l 2>/dev/null": result(0, loaded)},
	}
	exec := func(path string) api.Check {
		return api.Check{Method: "audit_rule_exists", Params: api.Params{
			"rule": "-a always,exit -F path=" + path + " -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd",
		}}
	}
	if passed, _, err := runForTest(context.Background(), ft, exec("/usr/bin/sudo")); err != nil || !passed {
		t.Fatalf("loaded /usr/bin/sudo exec rule should pass; passed=%v err=%v", passed, err)
	}
	// Different command sharing the key priv_cmd must NOT pass.
	if passed, detail, err := runForTest(context.Background(), ft, exec("/usr/bin/chsh")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else if passed {
		t.Errorf("/usr/bin/chsh not loaded but check passed (key-only false pass): %s", detail)
	}
}

// TestCheckAuditRuleExists_SyscallSetMatch locks the syscall-set match:
// chmod and chown rules share the key perm_chng and differ only by their -S
// set, so a key-only match would false-pass. Also covers multi-line rules
// (b32 + b64): every line must be loaded.
func TestCheckAuditRuleExists_SyscallSetMatch(t *testing.T) {
	// Only the chmod b64 + b32 rules are loaded (auditctl-style: -F key=, auid!=-1).
	loaded := "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng\n" +
		"-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng"
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l 2>/dev/null": result(0, loaded)}}
	rule := func(arches []string, syscalls string) api.Check {
		var lines []string
		for _, a := range arches {
			lines = append(lines, "-a always,exit -F arch="+a+" -S "+syscalls+" -F auid>=1000 -F auid!=unset -k perm_chng")
		}
		return api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": strings.Join(lines, "\n")}}
	}
	// chmod (both arches) loaded -> pass (set match despite auid!=unset vs -1).
	if passed, d, err := runForTest(context.Background(), ft, rule([]string{"b32", "b64"}, "chmod,fchmod,fchmodat")); err != nil || !passed {
		t.Fatalf("chmod rule should pass; passed=%v detail=%s err=%v", passed, d, err)
	}
	// chown shares key perm_chng but is NOT loaded -> must fail (set differs).
	if passed, d, err := runForTest(context.Background(), ft, rule([]string{"b32", "b64"}, "chown,fchown,fchownat,lchown")); err != nil {
		t.Fatalf("err: %v", err)
	} else if passed {
		t.Errorf("chown not loaded but passed (key-only false pass): %s", d)
	}
	// Multi-line completeness: chmod requiring an arch that isn't loaded fails.
	loaded2 := "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng"
	ft2 := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l 2>/dev/null": result(0, loaded2)}}
	if passed, _, err := runForTest(context.Background(), ft2, rule([]string{"b32", "b64"}, "chmod,fchmod,fchmodat")); err != nil {
		t.Fatalf("err: %v", err)
	} else if passed {
		t.Errorf("only b64 loaded but b32+b64 rule passed (missing-line not detected)")
	}
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
	passed, detail, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
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
	_, _, err := runForTest(context.Background(), ft, chk)
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
	passed, detail, err := runForTest(context.Background(), ft, chk)
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
	passed, detail, err := runForTest(context.Background(), ft, chk)
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
	passed, _, err := runForTest(context.Background(), ft, chk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Error("expected multi-check to fail when all children fail")
	}
}
