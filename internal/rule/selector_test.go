package rule_test

import (
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/rule"
)

// TestSelect_MatchesWhenGate verifies that the first satisfied when gate wins.
func TestSelect_MatchesWhenGate(t *testing.T) {
	r, _ := rule.ParseFile("testdata/ssh-disable-root-login.yml")
	caps := api.CapabilitySet{"sshd_config_d": true}

	impl, err := rule.Select(r, caps)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if impl.Remediation.Mechanism != "config_set_dropin" {
		t.Errorf("got mechanism %q, want config_set_dropin", impl.Remediation.Mechanism)
	}
}

// TestSelect_FallsBackToDefault verifies that the default implementation is
// returned when no when gate is satisfied.
func TestSelect_FallsBackToDefault(t *testing.T) {
	r, _ := rule.ParseFile("testdata/ssh-disable-root-login.yml")
	caps := api.CapabilitySet{} // sshd_config_d is absent

	impl, err := rule.Select(r, caps)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !impl.Default {
		t.Error("expected the default implementation to be returned")
	}
	if impl.Remediation.Mechanism != "config_set" {
		t.Errorf("got mechanism %q, want config_set", impl.Remediation.Mechanism)
	}
}

// TestSelect_SingleDefault verifies that a rule with only a default
// implementation always returns it.
func TestSelect_SingleDefault(t *testing.T) {
	r, _ := rule.ParseFile("testdata/sysctl-net-ipv4-ip-forward.yml")
	impl, err := rule.Select(r, api.CapabilitySet{})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !impl.Default {
		t.Error("expected the default implementation")
	}
}

// TestSelect_NilCaps treats a nil CapabilitySet as empty.
func TestSelect_NilCaps(t *testing.T) {
	r, _ := rule.ParseFile("testdata/sysctl-net-ipv4-ip-forward.yml")
	impl, err := rule.Select(r, nil)
	if err != nil {
		t.Fatalf("Select with nil caps: %v", err)
	}
	if impl == nil {
		t.Error("expected non-nil implementation")
	}
}

// TestSelect_AllGate tests {all: [cap1, cap2]} evaluation.
func TestSelect_AllGate(t *testing.T) {
	r := ruleWithWhen(map[string]interface{}{"all": []interface{}{"cap_a", "cap_b"}})

	// Both present → gated impl selected.
	impl, err := rule.Select(r, api.CapabilitySet{"cap_a": true, "cap_b": true})
	if err != nil {
		t.Fatalf("Select (all match): %v", err)
	}
	if impl.Remediation.Mechanism != "gated" {
		t.Errorf("expected gated mechanism, got %q", impl.Remediation.Mechanism)
	}

	// Only one present → fallback.
	impl, err = rule.Select(r, api.CapabilitySet{"cap_a": true})
	if err != nil {
		t.Fatalf("Select (partial): %v", err)
	}
	if impl.Remediation.Mechanism != "default_mech" {
		t.Errorf("expected default_mech, got %q", impl.Remediation.Mechanism)
	}
}

// TestSelect_AnyGate tests {any: [cap1, cap2]} evaluation.
func TestSelect_AnyGate(t *testing.T) {
	r := ruleWithWhen(map[string]interface{}{"any": []interface{}{"cap_x", "cap_y"}})

	impl, err := rule.Select(r, api.CapabilitySet{"cap_x": true})
	if err != nil {
		t.Fatalf("Select (any): %v", err)
	}
	if impl.Remediation.Mechanism != "gated" {
		t.Errorf("expected gated, got %q", impl.Remediation.Mechanism)
	}

	impl, err = rule.Select(r, api.CapabilitySet{})
	if err != nil {
		t.Fatalf("Select (any miss): %v", err)
	}
	if impl.Remediation.Mechanism != "default_mech" {
		t.Errorf("expected default_mech, got %q", impl.Remediation.Mechanism)
	}
}

// TestSelect_NotGate tests {not: cap} evaluation.
func TestSelect_NotGate(t *testing.T) {
	r := ruleWithWhen(map[string]interface{}{"not": "legacy_svc"})

	// Cap absent → not(false) → gated impl selected.
	impl, err := rule.Select(r, api.CapabilitySet{})
	if err != nil {
		t.Fatalf("Select (not, absent): %v", err)
	}
	if impl.Remediation.Mechanism != "gated" {
		t.Errorf("expected gated, got %q", impl.Remediation.Mechanism)
	}

	// Cap present → not(true) = false → fallback.
	impl, err = rule.Select(r, api.CapabilitySet{"legacy_svc": true})
	if err != nil {
		t.Fatalf("Select (not, present): %v", err)
	}
	if impl.Remediation.Mechanism != "default_mech" {
		t.Errorf("expected default_mech, got %q", impl.Remediation.Mechanism)
	}
}

// TestSelect_NoDefault returns an error when the rule has no default.
func TestSelect_NoDefault(t *testing.T) {
	r := &api.Rule{
		ID: "no-default",
		Implementations: []api.Implementation{
			{When: "missing_cap", Remediation: api.Remediation{Mechanism: "gated"}},
		},
	}
	_, err := rule.Select(r, api.CapabilitySet{})
	if err == nil {
		t.Error("expected error for rule with no default implementation")
	}
}

// ruleWithWhen builds a minimal two-implementation rule for gate testing.
// The first implementation has the given when expression; the second is
// the default fallback.
func ruleWithWhen(when interface{}) *api.Rule {
	return &api.Rule{
		ID: "test-rule",
		Implementations: []api.Implementation{
			{
				When:        when,
				Remediation: api.Remediation{Mechanism: "gated"},
			},
			{
				Default:     true,
				Remediation: api.Remediation{Mechanism: "default_mech"},
			},
		},
	}
}
