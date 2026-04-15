package rule_test

import (
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/rule"
)

// TestLint_W001_SshdConfigWithoutDropinSibling fires W001 when config_value
// reads /etc/ssh/sshd_config and there is no sshd_config_d-gated sibling.
func TestLint_W001_SshdConfigWithoutDropinSibling(t *testing.T) {
	r := &api.Rule{
		ID: "ssh-root-login",
		Implementations: []api.Implementation{
			{
				Default: true,
				Check: api.Check{
					Method: "config_value",
					Params: api.Params{"path": "/etc/ssh/sshd_config", "key": "PermitRootLogin"},
				},
			},
		},
	}
	warns := rule.Lint(r)
	if !hasWarningCode(warns, "W001") {
		t.Errorf("expected W001 warning, got %v", warns)
	}
}

// TestLint_NoW001_WhenDropinSiblingExists suppresses W001 when there is a
// sshd_config_d-gated sibling implementation.
func TestLint_NoW001_WhenDropinSiblingExists(t *testing.T) {
	r, _ := rule.ParseFile("testdata/ssh-disable-root-login.yml")
	warns := rule.Lint(r)
	if hasWarningCode(warns, "W001") {
		t.Errorf("did not expect W001 for ssh-disable-root-login (has dropin sibling): %v", warns)
	}
}

// TestLint_W002_SysctlConfDirectRead fires W002 for config_value on /etc/sysctl.conf.
func TestLint_W002_SysctlConfDirectRead(t *testing.T) {
	r := ruleWithCheck(api.Check{
		Method: "config_value",
		Params: api.Params{"path": "/etc/sysctl.conf", "key": "net.ipv4.ip_forward"},
	})
	warns := rule.Lint(r)
	if !hasWarningCode(warns, "W002") {
		t.Errorf("expected W002 warning, got %v", warns)
	}
}

// TestLint_NoW002_SysctlValue verifies no W002 for sysctl_value method.
func TestLint_NoW002_SysctlValue(t *testing.T) {
	r, _ := rule.ParseFile("testdata/sysctl-net-ipv4-ip-forward.yml")
	warns := rule.Lint(r)
	if hasWarningCode(warns, "W002") {
		t.Errorf("did not expect W002 for sysctl_value check: %v", warns)
	}
}

// TestLint_W003_PamDirectRead fires W003 for config_value on /etc/pam.d/* without
// authselect capability gate.
func TestLint_W003_PamDirectRead(t *testing.T) {
	r := ruleWithCheck(api.Check{
		Method: "config_value",
		Params: api.Params{"path": "/etc/pam.d/password-auth"},
	})
	warns := rule.Lint(r)
	if !hasWarningCode(warns, "W003") {
		t.Errorf("expected W003 warning, got %v", warns)
	}
}

// TestLint_NoW003_WithAuthselectGate suppresses W003 when the implementation
// is gated on authselect.
func TestLint_NoW003_WithAuthselectGate(t *testing.T) {
	r := &api.Rule{
		ID: "pam-rule",
		Implementations: []api.Implementation{
			{
				When: "authselect",
				Check: api.Check{
					Method: "config_value",
					Params: api.Params{"path": "/etc/pam.d/password-auth"},
				},
			},
			{Default: true},
		},
	}
	warns := rule.Lint(r)
	if hasWarningCode(warns, "W003") {
		t.Errorf("did not expect W003 when authselect is in when gate: %v", warns)
	}
}

// TestLint_W004_FstabDirectRead fires W004 for file_content_match on /etc/fstab.
func TestLint_W004_FstabDirectRead(t *testing.T) {
	r := ruleWithCheck(api.Check{
		Method: "file_content_match",
		Params: api.Params{"path": "/etc/fstab", "pattern": "nosuid"},
	})
	warns := rule.Lint(r)
	if !hasWarningCode(warns, "W004") {
		t.Errorf("expected W004 warning, got %v", warns)
	}
}

// TestLint_W005_SelinuxConfigRead fires W005 for config_value on /etc/selinux/config.
func TestLint_W005_SelinuxConfigRead(t *testing.T) {
	r := ruleWithCheck(api.Check{
		Method: "config_value",
		Params: api.Params{"path": "/etc/selinux/config", "key": "SELINUX"},
	})
	warns := rule.Lint(r)
	if !hasWarningCode(warns, "W005") {
		t.Errorf("expected W005 warning, got %v", warns)
	}
}

// TestLint_CleanRule verifies no warnings for the well-formed fixture rules.
func TestLint_CleanRule(t *testing.T) {
	fixtures := []string{
		"testdata/sysctl-net-ipv4-ip-forward.yml",
		"testdata/ssh-disable-root-login.yml",
		"testdata/faillock-configure.yml",
	}
	for _, path := range fixtures {
		r, err := rule.ParseFile(path)
		if err != nil {
			t.Fatalf("%s: ParseFile: %v", path, err)
		}
		warns := rule.Lint(r)
		if len(warns) > 0 {
			t.Errorf("%s: expected no lint warnings, got: %v", path, warns)
		}
	}
}

// TestLint_MultiCheckWarning fires the warning when a check within a
// multi-check list triggers a pattern.
func TestLint_MultiCheckWarning(t *testing.T) {
	r := &api.Rule{
		ID: "multi-check",
		Implementations: []api.Implementation{
			{
				Default: true,
				Check: api.Check{
					Checks: []api.Check{
						{Method: "package_state", Params: api.Params{"name": "aide"}},
						{
							Method: "config_value",
							Params: api.Params{"path": "/etc/sysctl.conf", "key": "x"},
						},
					},
				},
			},
		},
	}
	warns := rule.Lint(r)
	if !hasWarningCode(warns, "W002") {
		t.Errorf("expected W002 in multi-check lint, got %v", warns)
	}
}

// ─── helpers ───────────────────────────────────────────────────────────────

// ruleWithCheck builds a minimal rule with a single default implementation
// using the given check.
func ruleWithCheck(check api.Check) *api.Rule {
	return &api.Rule{
		ID: "lint-test-rule",
		Implementations: []api.Implementation{
			{Default: true, Check: check},
		},
	}
}

// hasWarningCode returns true when warns contains a LintWarning with the
// given code.
func hasWarningCode(warns []rule.LintWarning, code string) bool {
	for _, w := range warns {
		if w.Code == code {
			return true
		}
	}
	return false
}
