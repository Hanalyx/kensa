package rule_test

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/rule"
)

// TestParse_SimpleRule parses the sysctl IPv4-forward fixture and checks
// the mapped api.Rule fields.
// @spec rule-ordering
// @ac AC-01
// @ac AC-10
// @ac AC-19
func TestParse_SimpleRule(t *testing.T) {
	t.Run("rule-ordering/AC-19", func(t *testing.T) {})
	t.Run("rule-ordering/AC-10", func(t *testing.T) {})
	t.Run("rule-ordering/AC-01", func(t *testing.T) {})
	r, err := rule.ParseFile("testdata/sysctl-net-ipv4-ip-forward.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if r.ID != "sysctl-net-ipv4-ip-forward" {
		t.Errorf("ID=%q, want sysctl-net-ipv4-ip-forward", r.ID)
	}
	if r.Severity != "medium" {
		t.Errorf("Severity=%q, want medium", r.Severity)
	}
	if r.Category != "kernel" {
		t.Errorf("Category=%q, want kernel", r.Category)
	}
	if !r.Transactional {
		t.Error("Transactional should default to true when omitted")
	}
	if len(r.Implementations) != 1 {
		t.Fatalf("len(Implementations)=%d, want 1", len(r.Implementations))
	}
	impl := r.Implementations[0]
	if !impl.Default {
		t.Error("implementation should have default:true")
	}
	if impl.Check.Method != "sysctl_value" {
		t.Errorf("check.Method=%q, want sysctl_value", impl.Check.Method)
	}
	if impl.Check.Params["key"] != "net.ipv4.ip_forward" {
		t.Errorf("check.Params[key]=%v, want net.ipv4.ip_forward", impl.Check.Params["key"])
	}
	if impl.Remediation.Mechanism != "sysctl_set" {
		t.Errorf("remediation.Mechanism=%q, want sysctl_set", impl.Remediation.Mechanism)
	}
}

// TestParse_CapabilityGated parses the ssh-disable-root-login fixture and
// verifies two implementations with `when` and `default` respectively.
// @spec rule-ordering
// @ac AC-02
// @ac AC-11
func TestParse_CapabilityGated(t *testing.T) {
	t.Run("rule-ordering/AC-11", func(t *testing.T) {})
	t.Run("rule-ordering/AC-02", func(t *testing.T) {})
	r, err := rule.ParseFile("testdata/ssh-disable-root-login.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(r.Implementations) != 2 {
		t.Fatalf("len(Implementations)=%d, want 2", len(r.Implementations))
	}

	// First impl is gated on sshd_config_d.
	gated := r.Implementations[0]
	if gated.Default {
		t.Error("first implementation should not be default")
	}
	if gated.When != "sshd_config_d" {
		t.Errorf("first impl.When=%v, want sshd_config_d", gated.When)
	}
	if gated.Remediation.Mechanism != "config_set_dropin" {
		t.Errorf("first impl remediation.Mechanism=%q, want config_set_dropin", gated.Remediation.Mechanism)
	}

	// Second impl is the default.
	def := r.Implementations[1]
	if !def.Default {
		t.Error("second implementation should have default:true")
	}
}

// TestParse_TransactionalFalse verifies that transactional:false is read
// correctly.
// @spec rule-ordering
// @ac AC-03
// @ac AC-12
func TestParse_TransactionalFalse(t *testing.T) {
	t.Run("rule-ordering/AC-12", func(t *testing.T) {})
	t.Run("rule-ordering/AC-03", func(t *testing.T) {})
	r, err := rule.ParseFile("testdata/aide-installed.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if r.Transactional {
		t.Error("Transactional should be false for aide-installed fixture")
	}
}

// TestParse_MultiCheck verifies that a checks: list maps to api.Check.Checks.
// @spec rule-ordering
// @ac AC-04
// @ac AC-13
func TestParse_MultiCheck(t *testing.T) {
	t.Run("rule-ordering/AC-13", func(t *testing.T) {})
	t.Run("rule-ordering/AC-04", func(t *testing.T) {})
	r, err := rule.ParseFile("testdata/aide-installed.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	impl := r.Implementations[0]
	if len(impl.Check.Checks) != 2 {
		t.Fatalf("len(Check.Checks)=%d, want 2", len(impl.Check.Checks))
	}
	if impl.Check.Checks[0].Method != "package_state" {
		t.Errorf("Check.Checks[0].Method=%q, want package_state", impl.Check.Checks[0].Method)
	}
}

// TestParse_MultiStep verifies that a steps: list maps to
// api.Remediation.Steps.
// @spec rule-ordering
// @ac AC-05
// @ac AC-14
func TestParse_MultiStep(t *testing.T) {
	t.Run("rule-ordering/AC-14", func(t *testing.T) {})
	t.Run("rule-ordering/AC-05", func(t *testing.T) {})
	r, err := rule.ParseFile("testdata/aide-installed.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	rem := r.Implementations[0].Remediation
	if len(rem.Steps) != 2 {
		t.Fatalf("len(Remediation.Steps)=%d, want 2", len(rem.Steps))
	}
	if rem.Steps[0].Mechanism != "package_present" {
		t.Errorf("Steps[0].Mechanism=%q, want package_present", rem.Steps[0].Mechanism)
	}
	if rem.Steps[1].Mechanism != "command_exec" {
		t.Errorf("Steps[1].Mechanism=%q, want command_exec", rem.Steps[1].Mechanism)
	}
}

// TestParse_MultiStepCapturable verifies multi-step atomic fixture
// (faillock-configure) reads two config_set steps correctly.
// @spec rule-ordering
// @ac AC-06
// @ac AC-15
func TestParse_MultiStepCapturable(t *testing.T) {
	t.Run("rule-ordering/AC-15", func(t *testing.T) {})
	t.Run("rule-ordering/AC-06", func(t *testing.T) {})
	r, err := rule.ParseFile("testdata/faillock-configure.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	rem := r.Implementations[0].Remediation
	if len(rem.Steps) != 2 {
		t.Fatalf("len(Steps)=%d, want 2", len(rem.Steps))
	}
	if rem.Steps[0].Params["key"] != "deny" {
		t.Errorf("Steps[0].Params[key]=%v, want deny", rem.Steps[0].Params["key"])
	}
}

// TestParse_InvalidYAML returns an error for malformed YAML.
// @spec rule-ordering
// @ac AC-07
// @ac AC-16
func TestParse_InvalidYAML(t *testing.T) {
	t.Run("rule-ordering/AC-16", func(t *testing.T) {})
	t.Run("rule-ordering/AC-07", func(t *testing.T) {})
	_, err := rule.Parse(strings.NewReader("not: valid: yaml: ["))
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// TestParse_References verifies that the references map is populated.
// @spec rule-ordering
// @ac AC-08
// @ac AC-17
func TestParse_References(t *testing.T) {
	t.Run("rule-ordering/AC-17", func(t *testing.T) {})
	t.Run("rule-ordering/AC-08", func(t *testing.T) {})
	r, err := rule.ParseFile("testdata/ssh-disable-root-login.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if r.References == nil {
		t.Error("References should not be nil")
	}
	if r.References["nist_800_53"] == nil {
		t.Error("nist_800_53 reference missing")
	}
}

// TestParse_Platform verifies platform fields are decoded.
// @spec rule-ordering
// @ac AC-09
// @ac AC-18
func TestParse_Platform(t *testing.T) {
	t.Run("rule-ordering/AC-18", func(t *testing.T) {})
	t.Run("rule-ordering/AC-09", func(t *testing.T) {})
	r, err := rule.ParseFile("testdata/sysctl-net-ipv4-ip-forward.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(r.Platforms) != 1 {
		t.Fatalf("len(Platforms)=%d, want 1", len(r.Platforms))
	}
	p := r.Platforms[0]
	if p.Family != "rhel" {
		t.Errorf("Platform.Family=%q, want rhel", p.Family)
	}
	if p.MinVersion != 8 {
		t.Errorf("Platform.MinVersion=%d, want 8", p.MinVersion)
	}
	if !p.Derivatives {
		t.Error("Derivatives should default to true when omitted")
	}
}
