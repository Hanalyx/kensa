// Tests for --control framework-control filter (C-035).
package main

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

func TestParseControlFilters_Empty(t *testing.T) {
	got, err := parseControlFilters(nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil; got %v", got)
	}
}

func TestParseControlFilters_WellFormed(t *testing.T) {
	got, err := parseControlFilters([]string{"cis_rhel9:5.1.12"})
	if err != nil {
		t.Fatalf("well-formed: %v", err)
	}
	if len(got) != 1 || got[0].frameworkID != "cis_rhel9" || got[0].controlID != "5.1.12" {
		t.Errorf("got %v", got)
	}
}

func TestParseControlFilters_HyphenAlias(t *testing.T) {
	got, err := parseControlFilters([]string{"cis-rhel9:5.1.12"})
	if err != nil {
		t.Fatalf("hyphen: %v", err)
	}
	if got[0].frameworkID != "cis_rhel9" {
		t.Errorf("framework portion should normalize hyphen→underscore; got %q", got[0].frameworkID)
	}
}

func TestParseControlFilters_PreservesControlCase(t *testing.T) {
	// NIST control IDs are case-sensitive ("AC-1" vs "ac-1");
	// don't lowercase the control portion.
	got, err := parseControlFilters([]string{"nist_800_53:AC-1"})
	if err != nil {
		t.Fatalf("case: %v", err)
	}
	if got[0].controlID != "AC-1" {
		t.Errorf("control portion should preserve case; got %q", got[0].controlID)
	}
}

func TestParseControlFilters_Multiple(t *testing.T) {
	got, err := parseControlFilters([]string{"cis_rhel9:5.1.12", "nist_800_53:AC-1"})
	if err != nil {
		t.Fatalf("multiple: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestParseControlFilters_MissingColon(t *testing.T) {
	_, err := parseControlFilters([]string{"cis_rhel9"})
	if err == nil || !strings.Contains(err.Error(), "missing ':'") {
		t.Errorf("expected missing-colon error; got %v", err)
	}
}

func TestParseControlFilters_EmptyFramework(t *testing.T) {
	_, err := parseControlFilters([]string{":5.1.12"})
	if err == nil || !strings.Contains(err.Error(), "empty FRAMEWORK") {
		t.Errorf("expected empty-framework error; got %v", err)
	}
}

func TestParseControlFilters_EmptyControl(t *testing.T) {
	_, err := parseControlFilters([]string{"cis_rhel9:"})
	if err == nil || !strings.Contains(err.Error(), "empty CONTROL") {
		t.Errorf("expected empty-control error; got %v", err)
	}
}

func sampleRulesForControl() []*api.Rule {
	return []*api.Rule{
		ruleWithRefs("a", map[string]interface{}{
			"cis": map[string]interface{}{
				"rhel9": map[string]interface{}{"section": "5.1.12"},
			},
			"nist_800_53": []interface{}{"AC-1"},
		}),
		ruleWithRefs("b", map[string]interface{}{
			"cis": map[string]interface{}{
				"rhel9": map[string]interface{}{"section": "5.2.1"},
			},
		}),
		ruleWithRefs("c", map[string]interface{}{
			"nist_800_53": []interface{}{"CM-1"},
		}),
	}
}

func TestValidateControls_Empty(t *testing.T) {
	if err := validateControls(nil, sampleRulesForControl()); err != nil {
		t.Errorf("nil filters: %v", err)
	}
}

func TestValidateControls_KnownFrameworkAndControl(t *testing.T) {
	filters := []controlFilter{{frameworkID: "cis_rhel9", controlID: "5.1.12"}}
	if err := validateControls(filters, sampleRulesForControl()); err != nil {
		t.Errorf("known: %v", err)
	}
}

func TestValidateControls_UnknownFramework(t *testing.T) {
	filters := []controlFilter{{frameworkID: "hipaa", controlID: "X"}}
	err := validateControls(filters, sampleRulesForControl())
	if err == nil {
		t.Fatal("expected unknown-framework error")
	}
	if !strings.Contains(err.Error(), "unknown framework") {
		t.Errorf("error should mention unknown framework: %v", err)
	}
	if !strings.Contains(err.Error(), "cis_rhel9") {
		t.Errorf("error should list available frameworks: %v", err)
	}
}

func TestValidateControls_UnknownControl(t *testing.T) {
	filters := []controlFilter{{frameworkID: "cis_rhel9", controlID: "9.9.9"}}
	err := validateControls(filters, sampleRulesForControl())
	if err == nil {
		t.Fatal("expected unknown-control error")
	}
	if !strings.Contains(err.Error(), "not found under framework") {
		t.Errorf("error should mention not-found: %v", err)
	}
	// Sample of available controls should be in the error so the
	// operator can correct.
	if !strings.Contains(err.Error(), "5.1.12") {
		t.Errorf("error should list sample available controls: %v", err)
	}
}

func TestFilterRulesByControl_Empty(t *testing.T) {
	rules := sampleRulesForControl()
	got := filterRulesByControl(rules, nil)
	if len(got) != len(rules) {
		t.Errorf("empty filters should pass through; got %d", len(got))
	}
}

func TestFilterRulesByControl_SingleMatch(t *testing.T) {
	rules := sampleRulesForControl()
	filters := []controlFilter{{frameworkID: "cis_rhel9", controlID: "5.1.12"}}
	got := filterRulesByControl(rules, filters)
	if len(got) != 1 || got[0].ID != "a" {
		t.Errorf("expected [a]; got %v", ids(got))
	}
}

func TestFilterRulesByControl_OrSemanticsAcrossFilters(t *testing.T) {
	rules := sampleRulesForControl()
	filters := []controlFilter{
		{frameworkID: "cis_rhel9", controlID: "5.2.1"},
		{frameworkID: "nist_800_53", controlID: "CM-1"},
	}
	got := filterRulesByControl(rules, filters)
	if len(got) != 2 || got[0].ID != "b" || got[1].ID != "c" {
		t.Errorf("expected [b,c]; got %v", ids(got))
	}
}

func TestFilterRulesByControl_PreservesOrder(t *testing.T) {
	rules := []*api.Rule{
		ruleWithRefs("z", map[string]interface{}{
			"nist_800_53": []interface{}{"AC-1"},
		}),
		ruleWithRefs("a", map[string]interface{}{
			"nist_800_53": []interface{}{"AC-1"},
		}),
	}
	filters := []controlFilter{{frameworkID: "nist_800_53", controlID: "AC-1"}}
	got := filterRulesByControl(rules, filters)
	if len(got) != 2 || got[0].ID != "z" || got[1].ID != "a" {
		t.Errorf("expected [z,a]; got %v", ids(got))
	}
}
