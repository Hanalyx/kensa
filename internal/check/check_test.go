package check

import (
	"context"
	"errors"
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
	// auditTarget answers the audit host-facts probe (AuditTargetProbe).
	// Nil answers it as testAuditTarget does; see fakeAuditProbe.
	auditTarget *AuditTarget
	// noAuditProbe makes the probe fail like an unknown command.
	noAuditProbe bool
}

func (f *fakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	if err, ok := f.errOn[cmd]; ok {
		return nil, err
	}
	if r, ok := f.cmdResult[cmd]; ok {
		return &r, nil
	}
	if strings.HasPrefix(cmd, auditProbePrefix) && !f.noAuditProbe {
		return &api.CommandResult{ExitCode: 0, Stdout: fakeAuditProbe(cmd, f.auditTarget), Duration: time.Millisecond}, nil
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
// satisfy the checks for the others. The loaded watch itself cannot be shown
// to cover its rule from the listing (a path= and a dir= rule both print as
// -w), so it is not assessable rather than a pass.
func TestCheckAuditRuleExists_WatchFullMatch(t *testing.T) {
	// Only /etc/group is loaded; its key usergroup_modification is present.
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
		"auditctl -l": result(0, "-w /etc/group -p wa -k usergroup_modification")}}
	watch := func(path string) api.Check {
		return api.Check{Method: "audit_rule_exists", Params: api.Params{
			"rule": "-w " + path + " -p wa -k usergroup_modification",
		}}
	}
	// The loaded watch may cover its own rule; the listing cannot prove it.
	if passed, _, err := runForTest(context.Background(), ft, watch("/etc/group")); !errors.Is(err, ErrAmbiguousEvidence) || passed {
		t.Fatalf("loaded /etc/group watch should be ambiguous; passed=%v err=%v", passed, err)
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
	// A rule with no arch and no -S covers every syscall, and auditctl -l
	// prints it with -S all.
	loaded := "-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd"
	ft := &fakeTransport{
		cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, loaded)},
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
	// A b64 execve-only rule on the same path is a narrower kernel rule: it
	// misses a 32-bit exec, so it does not satisfy the rule over every syscall.
	narrow := "-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd"
	ftNarrow := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, narrow)}}
	if passed, detail, err := runForTest(context.Background(), ftNarrow, exec("/usr/bin/sudo")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else if passed {
		t.Errorf("a b64 execve-only rule passed the rule over every syscall: %s", detail)
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
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, loaded)}}
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
	ft2 := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, loaded2)}}
	if passed, _, err := runForTest(context.Background(), ft2, rule([]string{"b32", "b64"}, "chmod,fchmod,fchmodat")); err != nil {
		t.Fatalf("err: %v", err)
	} else if passed {
		t.Errorf("only b64 loaded but b32+b64 rule passed (missing-line not detected)")
	}
}

// TestCheckAuditRuleExists_ActionDecides locks the rule that the audited
// action decides compliance, not the -k key label. A RHEL 9 host that watches
// writes to /etc/passwd under audit_rules_usergroup_modification failed
// audit-file-passwd, whose rule names the key identity, while the
// audit_rule_set guard refused to add the rule because the action was already
// audited. The check now gives the guard's answer. A rule that needs its own
// key sets key_required. Loaded lines are auditctl -l output. The path rule
// here has an arch, so the listing names its field and decides it.
func TestCheckAuditRuleExists_ActionDecides(t *testing.T) {
	loaded := "-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -F key=audit_rules_usergroup_modification\n" +
		"-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F key=perm_mod"
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, loaded)}}
	chk := func(rule string, extra api.Params) api.Check {
		p := api.Params{"rule": rule}
		for k, v := range extra {
			p[k] = v
		}
		return api.Check{Method: "audit_rule_exists", Params: p}
	}
	keyRequired := api.Params{"key_required": true}

	cases := []struct {
		name   string
		rule   string
		params api.Params
		want   bool
		detail string
	}{
		{"path rule under another key passes", "-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -k identity", nil, true, "under another key"},
		{"path rule under its own key passes", "-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -k audit_rules_usergroup_modification", nil, true, "all rule lines present"},
		{"syscall under another key passes",
			"-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng", nil, true, "under another key"},
		{"path rule with other perms fails", "-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=rwa -k identity", nil, false, "rule line not loaded"},
		{"path rule on another path fails", "-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=wa -k audit_rules_usergroup_modification", nil, false, "rule line not loaded"},
		{"syscall on another arch fails",
			"-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod", nil, false, "rule line not loaded"},
		{"key_required refuses another key", "-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -k identity", keyRequired, false, "key_required"},
		{"key_required accepts its own key", "-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -k audit_rules_usergroup_modification", keyRequired, true, "all rule lines present"},
		{"key_required false behaves as unset", "-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -k identity", api.Params{"key_required": false}, true, "under another key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			passed, detail, err := runForTest(context.Background(), ft, chk(c.rule, c.params))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if passed != c.want {
				t.Errorf("passed=%v want %v (detail: %s)", passed, c.want, detail)
			}
			if !strings.Contains(detail, c.detail) {
				t.Errorf("detail %q does not say %q", detail, c.detail)
			}
		})
	}

	t.Run("key_required must be a boolean", func(t *testing.T) {
		_, _, err := runForTest(context.Background(), ft, chk("-w /etc/passwd -p wa -k identity", api.Params{"key_required": "true"}))
		if err == nil || !strings.Contains(err.Error(), "key_required must be a boolean") {
			t.Errorf("a string key_required was not refused: %v", err)
		}
	})

	// The remediation guard's matcher skips -C comparisons and fields such as
	// euid. A loaded line under another key passes only when those match too,
	// so a plain execve rule does not satisfy the privileged-exec rule.
	t.Run("filters the guard skips must match", func(t *testing.T) {
		rule := "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv"
		cases := []struct {
			name, loaded string
			want         bool
		}{
			{"plain execve under no key", "-a always,exit -F arch=b64 -S execve", false},
			{"user emulation comparison", "-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=-1 -F key=user_emulation", false},
			{"same filters under another key", "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=setuid", true},
		}
		for _, c := range cases {
			ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, c.loaded)}}
			passed, detail, err := runForTest(context.Background(), ft, chk(rule, nil))
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", c.name, err)
			}
			if passed != c.want {
				t.Errorf("%s: passed=%v want %v (detail: %s)", c.name, passed, c.want, detail)
			}
		}

		// A loaded line narrowed by a filter the rule does not carry audits
		// fewer events, so it is not the rule's action.
		narrowed := "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -F success=0 -F key=perm_fail"
		ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, narrowed)}}
		chown := "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng"
		if passed, detail, _ := runForTest(context.Background(), ft, chk(chown, nil)); passed {
			t.Errorf("a loaded line narrowed by success=0 passed the broader rule: %s", detail)
		}
	})

	// Every line of a multi-line rule is still required; one line present
	// under another key does not carry a missing line.
	t.Run("multi-line rule still needs every action", func(t *testing.T) {
		rule := "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng\n" +
			"-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng"
		if passed, detail, _ := runForTest(context.Background(), ft, chk(rule, nil)); passed {
			t.Errorf("b32 line is not loaded under any key, but the rule passed: %s", detail)
		}
	})
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

// --- Finding D: static/socket-activated units must not false-FAIL ---

// TestCheckServiceEnabled_StaticCountsAsEnabled: a `static` unit (no [Install],
// socket/dependency-activated, e.g. systemd-journald on RHEL) satisfies a
// "must be enabled" control. Previously false-FAILed via Contains(out,"enabled").
func TestCheckServiceEnabled_StaticCountsAsEnabled(t *testing.T) {
	// On-by-design states that satisfy "must be enabled".
	for _, status := range []string{"static", "generated", "enabled-runtime"} {
		ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
			"systemctl is-enabled 'systemd-journald'": result(0, status+"\n"),
		}}
		chk := api.Check{Method: "service_enabled", Params: api.Params{"name": "systemd-journald"}}
		passed, _, err := runForTest(context.Background(), ft, chk)
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if !passed {
			t.Errorf("status %q must count as enabled (Finding D)", status)
		}
	}
	// indirect/alias must NOT count as enabled: per systemd the queried unit
	// itself is not [Install]-enabled, so counting them PASS would be a false
	// PASS masking non-compliance (panel finding).
	for _, status := range []string{"indirect", "alias", "disabled", "masked"} {
		ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
			"systemctl is-enabled 'svc'": result(0, status+"\n"),
		}}
		chk := api.Check{Method: "service_enabled", Params: api.Params{"name": "svc"}}
		passed, _, err := runForTest(context.Background(), ft, chk)
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if passed {
			t.Errorf("status %q must NOT count as enabled (false-PASS risk)", status)
		}
	}
}

// TestCheckServiceState_EnabledDirection covers the service_state enabled param:
// static passes want=enabled; masked/disabled fail it; and the want=disabled
// direction is unchanged (only [Install]-enabled units fail).
func TestCheckServiceState_EnabledDirection(t *testing.T) {
	cases := []struct {
		status string
		want   bool // desired enabled state
		pass   bool
	}{
		{"static", true, true},    // Finding D: static satisfies want=enabled
		{"generated", true, true}, // on-by-design (generator-created)
		{"indirect", true, false}, // NOT [Install]-enabled -> fail want=enabled (no false PASS)
		{"enabled", true, true},   // explicit
		{"disabled", true, false}, // genuinely off -> fail want=enabled
		{"masked", true, false},   // masked is not enabled
		{"enabled", false, false}, // want=disabled but explicitly enabled -> fail (no regression)
		{"enabled-runtime", false, false},
		{"static", false, true},   // want=disabled: static isn't [Install]-enabled -> pass (no regression)
		{"disabled", false, true}, // genuinely off -> pass want=disabled
	}
	for _, c := range cases {
		ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
			"systemctl is-enabled 'svc'": result(0, c.status+"\n"),
		}}
		chk := api.Check{Method: "service_state", Params: api.Params{"name": "svc", "enabled": c.want}}
		passed, _, err := runForTest(context.Background(), ft, chk)
		if err != nil {
			t.Fatalf("status=%s want=%v: %v", c.status, c.want, err)
		}
		if passed != c.pass {
			t.Errorf("status=%q want-enabled=%v: got pass=%v, want pass=%v", c.status, c.want, passed, c.pass)
		}
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

// TestCheckKernelModuleState_DisabledFormsAndNotFound locks the fix for the
// disabled-module false-FAIL: the check must accept BOTH `install /bin/true`
// and the CIS-standard `install /bin/false` no-op overrides, and must treat a
// module that is absent from the kernel tree ("... not found ...") as "not
// available" (compliant). Only a genuinely loadable module (insmod lines) fails.
//
// @spec check-kernel-module-state
// @ac AC-01
func TestCheckKernelModuleState_DisabledFormsAndNotFound(t *testing.T) {
	t.Run("check-kernel-module-state/AC-01", func(t *testing.T) {
		// @spec check-kernel-module-state
		// @ac AC-01
		mod := "atm"
		lsmod := "lsmod 2>/dev/null | grep -qw '" + mod + "'" // exit!=0 => not loaded
		depends := "modprobe -n --show-depends '" + mod + "' 2>&1"
		chk := api.Check{Method: "kernel_module_state", Params: api.Params{"name": mod, "state": "disabled"}}

		// Exit statuses are kmod's: 0 for a dependency listing, 1 when the module
		// is not in the tree.
		cases := []struct {
			name   string
			exit   int
			stdout string
			want   bool
		}{
			{"install-bin-true", 0, "install /bin/true", true},
			{"install-bin-false", 0, "install /bin/false", true}, // CIS-standard form; was a false-FAIL
			{"module-not-found", 1, "modprobe: FATAL: Module atm not found in directory /lib/modules/x", true},
			{"loadable", 0, "insmod /lib/modules/x/kernel/net/atm/atm.ko.xz", false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
					lsmod:   result(1, ""), // not currently loaded
					depends: result(c.exit, c.stdout),
				}}
				passed, detail, err := runForTest(context.Background(), ft, chk)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if passed != c.want {
					t.Errorf("%s: passed=%v want=%v (detail: %s)", c.name, passed, c.want, detail)
				}
			})
		}

		// A loaded module always fails regardless of modprobe output.
		t.Run("loaded", func(t *testing.T) {
			ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
				lsmod:   result(0, mod), // currently loaded
				depends: result(0, "install /bin/false"),
			}}
			if passed, _, _ := runForTest(context.Background(), ft, chk); passed {
				t.Errorf("a currently-loaded module must fail the disabled check")
			}
		})
	})
}

// TestCheckKernelModuleState_ModprobeMissingIsAnError locks the fix for the
// missing-modprobe false PASS. A shell reports a command it cannot find as
// "not found", which the disabled branch used to read as "module not
// present". With modprobe off PATH, every module passed. The shell's message
// says nothing about the module, so the check must return an error, not a
// verdict. Outputs are what the transport returns: stderr merged, trailing
// newline trimmed.
//
// @spec check-kernel-module-state
// @ac AC-02
func TestCheckKernelModuleState_ModprobeMissingIsAnError(t *testing.T) {
	t.Run("check-kernel-module-state/AC-02", func(t *testing.T) {
		// @spec check-kernel-module-state
		// @ac AC-02
		mod := "atm"
		lsmod := "lsmod 2>/dev/null | grep -qw '" + mod + "'"
		depends := "modprobe -n --show-depends '" + mod + "' 2>&1"
		chk := api.Check{Method: "kernel_module_state", Params: api.Params{"name": mod, "state": "disabled"}}

		cases := []struct {
			name   string
			exit   int
			stdout string
		}{
			{"dash", 127, "sh: 1: modprobe: not found"},
			{"bash", 127, "sh: line 1: modprobe: command not found"},
			{"bash-older", 127, "sh: modprobe: command not found"},
			{"not-executable", 126, "sh: 1: modprobe: Permission denied"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
					lsmod:   result(1, ""),
					depends: result(c.exit, c.stdout),
				}}
				passed, detail, err := runForTest(context.Background(), ft, chk)
				if passed {
					t.Fatalf("missing modprobe reported PASS (detail: %s)", detail)
				}
				if err == nil {
					t.Fatalf("missing modprobe must be a check error, got a FAIL verdict (detail: %s)", detail)
				}
				if !strings.Contains(err.Error(), "modprobe could not run") {
					t.Errorf("error does not say modprobe could not run: %v", err)
				}
			})
		}

		// "not found" text is not enough on its own: modprobe exits non-zero when
		// the module is absent, so a zero exit with that text is not that case.
		t.Run("not-found-text-with-zero-exit", func(t *testing.T) {
			ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
				lsmod:   result(1, ""),
				depends: result(0, "modprobe: FATAL: Module atm not found in directory /lib/modules/x"),
			}}
			if passed, detail, _ := runForTest(context.Background(), ft, chk); passed {
				t.Errorf("not-found text with exit 0 reported PASS (detail: %s)", detail)
			}
		})

		// Another tool's "not found" line, with a non-zero exit, is not
		// modprobe's module-not-found message.
		for _, out := range []string{
			"sh: 1: /etc/profile.d/x.sh: not found",
			"/usr/local/sbin/modprobe: line 2: Module atm not found",
			"modprobe: ERROR: could not insert 'atm': not found",
		} {
			t.Run("foreign-not-found-line", func(t *testing.T) {
				ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
					lsmod:   result(1, ""),
					depends: result(1, out),
				}}
				if passed, detail, _ := runForTest(context.Background(), ft, chk); passed {
					t.Errorf("a foreign not-found line %q reported PASS (detail: %s)", out, detail)
				}
			})
		}
	})
}

// TestAuditRuleIdentity_GuardCases covers the duplicate guard's predicate on
// rules.d lines: two lines are refused only when they build one kernel rule
// on the target, or when that cannot be ruled out. A rule under another key
// loads twice (captured for syscall rules and for watches on a file and on a
// directory), so it is allowed.
func TestAuditRuleIdentity_GuardCases(t *testing.T) {
	onDisk := []string{
		"-w /etc/shadow -p wa -k audit_rules_usergroup_modification",
		"-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
	}
	cases := []struct {
		name   string
		rule   string
		refuse bool
	}{
		{"file watch same path+perm, different key (captured: loads twice)", "-w /etc/shadow -p wa -k identity", false},
		{"file watch same path+perm, same key", "-w /etc/shadow -p wa -k audit_rules_usergroup_modification", true},
		{"watch different path", "-w /etc/gshadow -p wa -k identity", false},
		{"watch different perm", "-w /etc/shadow -p r -k identity", false},
		{"syscall same rule, different key", "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k other", false},
		{"syscall same rule, same key", "-a always,exit -F arch=b64 -S fchown,chown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod", true},
		{"syscall different arch", "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refused := false
			for _, d := range onDisk {
				refused = refused || guardRefuses(tc.rule, d)
			}
			if refused != tc.refuse {
				t.Errorf("guard refuses %q = %v, want %v", tc.rule, refused, tc.refuse)
			}
		})
	}
}

// TestAuditMatch_NoPrefixPathFalseMatch is the regression for the panel-found
// substring bug: "-F path=/usr/bin/su" must NOT match a loaded
// "-F path=/usr/bin/sudo" (su ⊂ sudo). Guards both the staged-rollback
// identity (AuditLoadedIdentity) and the conflict guard (AuditRuleIdentity,
// where a false match is a wrongly-refused legitimate rule).
func TestAuditMatch_NoPrefixPathFalseMatch(t *testing.T) {
	target := testAuditTarget()
	loadedSudo := "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged"
	su := "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged"
	if id, _ := AuditLoadedIdentity(su, loadedSudo, target); id != AuditDistinct {
		t.Errorf("AuditLoadedIdentity: /usr/bin/su vs loaded /usr/bin/sudo = %v, want Distinct", id)
	}
	if guardRefuses(su, loadedSudo) {
		t.Error("the guard refused /usr/bin/su as a duplicate of /usr/bin/sudo (false conflict)")
	}
	// Sanity: an EXACT path is never Distinct (fix didn't over-tighten). With
	// no arch the loaded mask is not known, so it is Unresolved, which a
	// staged rollback reports as possibly loaded.
	loadedSu := "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged"
	if id, why := AuditLoadedIdentity(su, loadedSu, target); id == AuditDistinct {
		t.Errorf("AuditLoadedIdentity: exact /usr/bin/su = Distinct (%s)", why)
	}
	// auid prefix must not substring-match either.
	if id, _ := AuditLoadedIdentity("-a always,exit -S execve -F auid>=1000 -k exec",
		"-a always,exit -S execve -F auid>=10000 -F key=exec", target); id != AuditDistinct {
		t.Errorf("AuditLoadedIdentity: auid>=1000 vs auid>=10000 = %v, want Distinct", id)
	}
}

// TestCheckAuditRuleExists_UnreadableRulesetIsNotAssessable locks the
// distinction between "the rule is not loaded" and "we could not look".
//
// On RHEL 10 auditctl moved out of the `audit` package into `audit-rules`,
// which a stock install does not pull in. The command is then missing, stdout
// is empty, and every audit rule on the host reported non-compliant for a
// reason that had nothing to do with its audit configuration. `rpm -q audit`
// still reports the package present, so the host does not make the cause
// obvious either.
//
// Reporting FAIL there states something the check never measured. It must
// report not-assessable, which the scan surfaces as skipped.
func TestCheckAuditRuleExists_UnreadableRulesetIsNotAssessable(t *testing.T) {
	chk := api.Check{Method: "audit_rule_exists", Params: api.Params{
		"rule": "-w /etc/passwd -p wa -k identity",
	}}

	// auditctl absent: the shell reports 127 and says why on stderr.
	missing := &fakeTransport{cmdResult: map[string]api.CommandResult{
		"auditctl -l": {ExitCode: 127, Stderr: "sh: auditctl: command not found"},
	}}
	passed, _, err := runForTest(context.Background(), missing, chk)
	if !errors.Is(err, ErrNotAssessable) {
		t.Fatalf("auditctl missing must be not-assessable, got passed=%v err=%v", passed, err)
	}
	if passed {
		t.Error("a check that could not read the ruleset must not report passed")
	}
	if !strings.Contains(err.Error(), "audit-rules") {
		t.Errorf("the reason should name the package that provides auditctl; got %v", err)
	}

	// Any other non-zero exit is equally unreadable, even with no stderr.
	silent := &fakeTransport{cmdResult: map[string]api.CommandResult{
		"auditctl -l": {ExitCode: 1},
	}}
	if _, _, err := runForTest(context.Background(), silent, chk); !errors.Is(err, ErrNotAssessable) {
		t.Errorf("non-zero exit must be not-assessable; got %v", err)
	}

	// Contrast: a readable but EMPTY ruleset is a real verdict, not a skip.
	// "No rules" is what auditctl prints on a host with none loaded, exit 0.
	empty := &fakeTransport{cmdResult: map[string]api.CommandResult{
		"auditctl -l": result(0, "No rules"),
	}}
	passed, _, err = runForTest(context.Background(), empty, chk)
	if err != nil {
		t.Fatalf("an empty ruleset is readable; expected a verdict, got %v", err)
	}
	if passed {
		t.Error("rule is genuinely not loaded; must fail, not pass")
	}
}

// A composite check with one member that provably fails is a fail, even
// when another member cannot be decided: under AND the proven failure
// settles it.
func TestRunMulti_ProvenFailBeatsAnUndecidedMember(t *testing.T) {
	ft := &fakeTransport{cmdResult: map[string]api.CommandResult{
		"auditctl -l": result(0, "-w /etc/passwd -p wa -k identity"),
	}}
	chk := api.Check{Checks: []api.Check{
		{Method: "file_exists", Params: api.Params{"path": "/etc/kensa-absent"}},
		{Method: "audit_rule_exists", Params: api.Params{"rule": "-w /etc/passwd -p wa -k identity"}},
	}}
	res, err := Run(context.Background(), ft, chk)
	if err != nil || res.Passed {
		t.Fatalf("passed=%v err=%v, want a clean fail", res.Passed, err)
	}
	// With no member failing, the undecided member's error stands.
	only := api.Check{Checks: []api.Check{chk.Checks[1]}}
	if _, err := Run(context.Background(), ft, only); !errors.Is(err, ErrAmbiguousEvidence) {
		t.Errorf("undecided alone: %v", err)
	}
}
