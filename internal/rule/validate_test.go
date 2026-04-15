package rule_test

import (
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/rule"
)

// TestValidate_ValidRule verifies that the well-formed fixture rules produce
// no validation errors.
func TestValidate_ValidRule(t *testing.T) {
	fixtures := []string{
		"testdata/sysctl-net-ipv4-ip-forward.yml",
		"testdata/ssh-disable-root-login.yml",
		"testdata/aide-installed.yml",
		"testdata/faillock-configure.yml",
	}
	for _, path := range fixtures {
		r, err := rule.ParseFile(path)
		if err != nil {
			t.Fatalf("%s: ParseFile: %v", path, err)
		}
		errs := rule.Validate(r, rule.ValidateOptions{})
		if len(errs) != 0 {
			t.Errorf("%s: expected no validation errors, got: %v", path, errs)
		}
	}
}

// TestValidate_MissingRequiredFields reports errors for each missing required field.
func TestValidate_MissingRequiredFields(t *testing.T) {
	r := &api.Rule{
		// All required fields intentionally empty.
		Implementations: []api.Implementation{
			{Default: true, Remediation: api.Remediation{Mechanism: "config_set"}},
		},
	}
	errs := rule.Validate(r, rule.ValidateOptions{})
	required := []string{"id", "title", "description", "rationale", "severity", "category"}
	for _, f := range required {
		found := false
		for _, e := range errs {
			if e.Field == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected ValidationError for field %q, not found in %v", f, errs)
		}
	}
}

// TestValidate_InvalidSeverity flags an unknown severity value.
func TestValidate_InvalidSeverity(t *testing.T) {
	r := minimalRule()
	r.Severity = "severe"
	errs := rule.Validate(r, rule.ValidateOptions{})
	if !hasFieldError(errs, "severity") {
		t.Errorf("expected severity error, got %v", errs)
	}
}

// TestValidate_NoDefault flags a rule with no default implementation.
func TestValidate_NoDefault(t *testing.T) {
	r := minimalRule()
	r.Implementations = []api.Implementation{
		{When: "some_cap", Remediation: api.Remediation{Mechanism: "config_set"}},
	}
	errs := rule.Validate(r, rule.ValidateOptions{})
	if !hasFieldError(errs, "implementations") {
		t.Errorf("expected implementations error, got %v", errs)
	}
}

// TestValidate_MultipleDefaults flags a rule with more than one default.
func TestValidate_MultipleDefaults(t *testing.T) {
	r := minimalRule()
	r.Implementations = []api.Implementation{
		{Default: true, Remediation: api.Remediation{Mechanism: "config_set"}},
		{Default: true, Remediation: api.Remediation{Mechanism: "sysctl_set"}},
	}
	errs := rule.Validate(r, rule.ValidateOptions{})
	if !hasFieldError(errs, "implementations") {
		t.Errorf("expected implementations error for multiple defaults, got %v", errs)
	}
}

// TestValidate_AtomicityConsistency flags a transactional:true rule with
// a non-capturable mechanism.
func TestValidate_AtomicityConsistency(t *testing.T) {
	r := minimalRule()
	r.Transactional = true
	r.Implementations = []api.Implementation{
		{
			Default: true,
			Remediation: api.Remediation{
				Steps: []api.RemediationStep{
					{Mechanism: "config_set"},
					{Mechanism: "command_exec"}, // non-capturable
				},
			},
		},
	}
	errs := rule.Validate(r, rule.ValidateOptions{})
	if !hasFieldError(errs, "implementations[0].remediation.steps[1].mechanism") {
		t.Errorf("expected atomicity error for command_exec, got %v", errs)
	}
}

// TestValidate_AtomicityConsistency_SingleStep tests the single-mechanism path.
func TestValidate_AtomicityConsistency_SingleStep(t *testing.T) {
	r := minimalRule()
	r.Transactional = true
	r.Implementations = []api.Implementation{
		{Default: true, Remediation: api.Remediation{Mechanism: "command_exec"}},
	}
	errs := rule.Validate(r, rule.ValidateOptions{})
	if !hasFieldError(errs, "implementations[0].remediation.mechanism") {
		t.Errorf("expected atomicity error for command_exec single step, got %v", errs)
	}
}

// TestValidate_TransactionalFalse_NonCapturable verifies that
// transactional:false rules are not flagged for non-capturable mechanisms.
func TestValidate_TransactionalFalse_NonCapturable(t *testing.T) {
	r := minimalRule()
	r.Transactional = false
	r.Implementations = []api.Implementation{
		{Default: true, Remediation: api.Remediation{Mechanism: "command_exec"}},
	}
	errs := rule.Validate(r, rule.ValidateOptions{})
	if hasFieldError(errs, "implementations[0].remediation.mechanism") {
		t.Error("transactional:false rule should not be flagged for command_exec")
	}
}

// TestValidate_FileNaming flags id mismatch with filename stem.
func TestValidate_FileNaming(t *testing.T) {
	r := minimalRule()
	r.ID = "my-rule"
	opts := rule.ValidateOptions{Filename: "/rules/kernel/wrong-name.yml"}
	errs := rule.Validate(r, opts)
	if !hasFieldError(errs, "id") {
		t.Errorf("expected id error for filename mismatch, got %v", errs)
	}
}

// TestValidate_FileNaming_Match verifies no error when filename matches id.
func TestValidate_FileNaming_Match(t *testing.T) {
	r := minimalRule()
	r.ID = "my-rule"
	opts := rule.ValidateOptions{Filename: "/rules/kernel/my-rule.yml"}
	errs := rule.Validate(r, opts)
	if hasFieldError(errs, "id") {
		t.Errorf("unexpected id error when filename matches: %v", errs)
	}
}

// TestValidate_CategoryConsistency flags category mismatch with directory.
func TestValidate_CategoryConsistency(t *testing.T) {
	r := minimalRule()
	r.Category = "kernel"
	opts := rule.ValidateOptions{ExpectedCategory: "network"}
	errs := rule.Validate(r, opts)
	if !hasFieldError(errs, "category") {
		t.Errorf("expected category error, got %v", errs)
	}
}

// TestValidate_KnownCapabilities flags an unknown capability name.
func TestValidate_KnownCapabilities(t *testing.T) {
	r := minimalRule()
	r.Implementations = []api.Implementation{
		{When: "nonexistent_cap", Remediation: api.Remediation{Mechanism: "config_set"}},
		{Default: true, Remediation: api.Remediation{Mechanism: "config_set"}},
	}
	opts := rule.ValidateOptions{KnownCapabilities: rule.KnownCapabilities}
	errs := rule.Validate(r, opts)
	if !hasFieldError(errs, "implementations[0].when") {
		t.Errorf("expected capability reference error, got %v", errs)
	}
}

// TestValidate_KnownCapabilities_Valid verifies that sshd_config_d passes.
func TestValidate_KnownCapabilities_Valid(t *testing.T) {
	r, _ := rule.ParseFile("testdata/ssh-disable-root-login.yml")
	opts := rule.ValidateOptions{KnownCapabilities: rule.KnownCapabilities}
	errs := rule.Validate(r, opts)
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid capabilities, got %v", errs)
	}
}

// ─── helpers ───────────────────────────────────────────────────────────────

// minimalRule returns a valid minimal api.Rule for mutation in tests.
func minimalRule() *api.Rule {
	return &api.Rule{
		ID:            "test-rule",
		Title:         "Test rule title",
		Description:   "Test rule description.",
		Rationale:     "Test rationale.",
		Severity:      "medium",
		Category:      "kernel",
		Transactional: true,
		Implementations: []api.Implementation{
			{Default: true, Remediation: api.Remediation{Mechanism: "sysctl_set"}},
		},
	}
}

// hasFieldError returns true when errs contains a ValidationError with the
// given field.
func hasFieldError(errs []rule.ValidationError, field string) bool {
	for _, e := range errs {
		if e.Field == field {
			return true
		}
	}
	return false
}
