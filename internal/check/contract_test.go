package check

import (
	"strings"
	"testing"
)

// @spec check-param-contract
// @ac AC-01
func TestCheckContractsCoverDispatch(t *testing.T) {
	t.Run("check-param-contract/AC-01", func(t *testing.T) {})
	// Every method string accepted by the dispatch switch in Run (check.go)
	// must have a CheckContracts entry. This is the parity guard against the
	// contract drifting from the implemented methods.
	dispatch := []string{
		"config_value", "sysctl_value", "package_installed", "package_absent",
		"package_state", "dpkg_installed", "dpkg_absent", "apparmor_state",
		"file_exists", "file_absent", "file_content_match", "file_content",
		"file_permissions", "file_permission", "service_enabled", "service_active",
		"service_state", "audit_rule_exists", "sshd_effective_config", "mount_option",
		"kernel_module_state", "grub_parameter", "selinux_state", "systemd_target", "command",
	}
	for _, m := range dispatch {
		if !KnownCheckMethod(m) {
			t.Errorf("dispatch method %q has no CheckContracts entry", m)
		}
	}
}

// @spec check-param-contract
// @ac AC-02
func TestValidateCheckParams(t *testing.T) {
	t.Run("check-param-contract/AC-02", func(t *testing.T) {})

	// conforming — comparator + delimiter are valid optionals on config_value.
	if p := ValidateCheckParams("config_value", []string{"path", "key", "expected", "delimiter", "comparator"}); len(p) != 0 {
		t.Errorf("conforming config_value (incl. comparator/delimiter) should pass; got %v", p)
	}
	// genuinely unknown param is flagged
	if p := ValidateCheckParams("config_value", []string{"path", "key", "expected", "bogus_param"}); len(p) == 0 ||
		!strings.Contains(strings.Join(p, ";"), "bogus_param") {
		t.Errorf("unknown 'bogus_param' must be flagged; got %v", p)
	}
	// missing required
	if p := ValidateCheckParams("config_value", []string{"path", "key"}); len(p) == 0 ||
		!strings.Contains(strings.Join(p, ";"), "expected") {
		t.Errorf("missing 'expected' must be flagged; got %v", p)
	}
	// OneOf: command needs cmd|run
	if p := ValidateCheckParams("command", []string{"expected_exit"}); len(p) == 0 {
		t.Errorf("command without cmd/run must be flagged; got %v", p)
	}
	if p := ValidateCheckParams("command", []string{"run"}); len(p) != 0 {
		t.Errorf("command with run should pass; got %v", p)
	}
	// service_state: enabled+active both allowed (AND), not OneOf
	if p := ValidateCheckParams("service_state", []string{"name", "enabled", "active"}); len(p) != 0 {
		t.Errorf("service_state enabled+active should pass (AND-combined); got %v", p)
	}
	// the verified file_permissions fix: glob is NOT allowed
	if p := ValidateCheckParams("file_permissions", []string{"path", "mode", "glob"}); len(p) == 0 ||
		!strings.Contains(strings.Join(p, ";"), "glob") {
		t.Errorf("file_permissions 'glob' must be flagged (check reads only path/mode/owner/group); got %v", p)
	}
	// unknown method
	if p := ValidateCheckParams("no_such_method", []string{"x"}); len(p) == 0 {
		t.Errorf("unknown method must be flagged")
	}
}
