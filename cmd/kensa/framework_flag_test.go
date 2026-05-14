// Tests for --framework / -f rule filter (C-033).
package main

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// @spec cli-framework-filter
// @ac AC-01
func TestNormalizeFrameworkID_Identity(t *testing.T) {
	t.Run("cli-framework-filter/AC-01", func(t *testing.T) {})
	if got := normalizeFrameworkID("cis_rhel9"); got != "cis_rhel9" {
		t.Errorf("got %q", got)
	}
}

// @spec cli-framework-filter
// @ac AC-02
func TestNormalizeFrameworkID_HyphenToUnderscore(t *testing.T) {
	t.Run("cli-framework-filter/AC-02", func(t *testing.T) {})
	if got := normalizeFrameworkID("cis-rhel9"); got != "cis_rhel9" {
		t.Errorf("got %q; want cis_rhel9", got)
	}
}

// @spec cli-framework-filter
// @ac AC-03
func TestNormalizeFrameworkID_LowercasesAndTrims(t *testing.T) {
	t.Run("cli-framework-filter/AC-03", func(t *testing.T) {})
	if got := normalizeFrameworkID("  CIS-RHEL9  "); got != "cis_rhel9" {
		t.Errorf("got %q; want cis_rhel9", got)
	}
}

// ruleWithRefs constructs a rule whose References block decodes
// the way mappings.RefsFromReferences expects. CIS uses a
// versioned-object shape; nist_800_53 uses a flat list.
func ruleWithRefs(id string, refs map[string]interface{}) *api.Rule {
	return &api.Rule{ID: id, References: refs}
}

func sampleRules() []*api.Rule {
	return []*api.Rule{
		ruleWithRefs("a", map[string]interface{}{
			"cis": map[string]interface{}{
				"rhel9": map[string]interface{}{"section": "1.1.1"},
				"rhel8": map[string]interface{}{"section": "1.1.2"},
			},
			"nist_800_53": []interface{}{"AC-1", "AC-2"},
		}),
		ruleWithRefs("b", map[string]interface{}{
			"cis": map[string]interface{}{
				"rhel9": map[string]interface{}{"section": "1.2.1"},
			},
		}),
		ruleWithRefs("c", map[string]interface{}{
			"nist_800_53": []interface{}{"CM-1"},
		}),
		ruleWithRefs("d", nil), // no references
		ruleWithRefs("e", map[string]interface{}{
			"stig": map[string]interface{}{
				"rhel9": map[string]interface{}{"vuln_id": "V-257974"},
			},
		}),
	}
}

// TestFilterRulesByFramework_StigVersionedShape locks the STIG
// versioned-object handling path through mappings. Adds defense
// against a regression that breaks one shape but not the other.
// @spec cli-framework-filter
// @ac AC-04
func TestFilterRulesByFramework_StigVersionedShape(t *testing.T) {
	t.Run("cli-framework-filter/AC-04", func(t *testing.T) {})
	rules := sampleRules()
	got := filterRulesByFramework(rules, "stig_rhel9")
	if len(got) != 1 || got[0].ID != "e" {
		t.Errorf("expected only [e]; got %v", ids(got))
	}
}

// @spec cli-framework-filter
// @ac AC-05
func TestAvailableFrameworks_UnionAndSorted(t *testing.T) {
	t.Run("cli-framework-filter/AC-05", func(t *testing.T) {})
	got := availableFrameworks(sampleRules())
	want := []string{"cis_rhel8", "cis_rhel9", "nist_800_53", "stig_rhel9"}
	if len(got) != len(want) {
		t.Fatalf("got %v; want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("idx %d: got %q; want %q", i, got[i], w)
		}
	}
}

// @spec cli-framework-filter
// @ac AC-06
func TestAvailableFrameworks_Empty(t *testing.T) {
	t.Run("cli-framework-filter/AC-06", func(t *testing.T) {})
	got := availableFrameworks([]*api.Rule{
		ruleWithRefs("a", nil),
		ruleWithRefs("b", map[string]interface{}{}),
	})
	if len(got) != 0 {
		t.Errorf("expected empty; got %v", got)
	}
}

// @spec cli-framework-filter
// @ac AC-07
func TestValidateFramework_Empty(t *testing.T) {
	t.Run("cli-framework-filter/AC-07", func(t *testing.T) {})
	got, err := validateFramework("", []string{"cis_rhel9"})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if got != "" {
		t.Errorf("got %q; want empty (pass-through)", got)
	}
}

// @spec cli-framework-filter
// @ac AC-08
func TestValidateFramework_Match(t *testing.T) {
	t.Run("cli-framework-filter/AC-08", func(t *testing.T) {})
	got, err := validateFramework("cis_rhel9", []string{"cis_rhel9", "nist_800_53"})
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if got != "cis_rhel9" {
		t.Errorf("got %q; want cis_rhel9", got)
	}
}

// @spec cli-framework-filter
// @ac AC-09
func TestValidateFramework_HyphenAlias(t *testing.T) {
	t.Run("cli-framework-filter/AC-09", func(t *testing.T) {})
	got, err := validateFramework("cis-rhel9", []string{"cis_rhel9"})
	if err != nil {
		t.Fatalf("hyphen alias: %v", err)
	}
	if got != "cis_rhel9" {
		t.Errorf("got %q; want canonical cis_rhel9", got)
	}
}

// @spec cli-framework-filter
// @ac AC-10
func TestValidateFramework_CaseInsensitive(t *testing.T) {
	t.Run("cli-framework-filter/AC-10", func(t *testing.T) {})
	got, err := validateFramework("CIS_RHEL9", []string{"cis_rhel9"})
	if err != nil {
		t.Fatalf("case: %v", err)
	}
	if got != "cis_rhel9" {
		t.Errorf("got %q; want cis_rhel9", got)
	}
}

// @spec cli-framework-filter
// @ac AC-11
func TestValidateFramework_Unknown(t *testing.T) {
	t.Run("cli-framework-filter/AC-11", func(t *testing.T) {})
	_, err := validateFramework("hipaa", []string{"cis_rhel9", "nist_800_53"})
	if err == nil {
		t.Fatal("unknown framework should error")
	}
	if !strings.Contains(err.Error(), "unknown framework") {
		t.Errorf("error should mention 'unknown framework': %v", err)
	}
	if !strings.Contains(err.Error(), "cis_rhel9") {
		t.Errorf("error should list available frameworks: %v", err)
	}
}

// @spec cli-framework-filter
// @ac AC-12
func TestValidateFramework_EmptyAvailable(t *testing.T) {
	t.Run("cli-framework-filter/AC-12", func(t *testing.T) {})
	_, err := validateFramework("cis_rhel9", nil)
	if err == nil {
		t.Fatal("empty available + non-empty input should error")
	}
	if !strings.Contains(err.Error(), "no rules") {
		t.Errorf("error should mention empty corpus: %v", err)
	}
}

// @spec cli-framework-filter
// @ac AC-13
func TestFilterRulesByFramework_Empty(t *testing.T) {
	t.Run("cli-framework-filter/AC-13", func(t *testing.T) {})
	rules := sampleRules()
	got := filterRulesByFramework(rules, "")
	if len(got) != len(rules) {
		t.Errorf("empty allowed should pass through; got %d", len(got))
	}
}

// @spec cli-framework-filter
// @ac AC-14
func TestFilterRulesByFramework_Match(t *testing.T) {
	t.Run("cli-framework-filter/AC-14", func(t *testing.T) {})
	rules := sampleRules()
	got := filterRulesByFramework(rules, "cis_rhel9")
	// Both 'a' and 'b' have cis.rhel9.
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Errorf("expected [a,b]; got %v", ids(got))
	}
}

// @spec cli-framework-filter
// @ac AC-15
func TestFilterRulesByFramework_FlatListMatch(t *testing.T) {
	t.Run("cli-framework-filter/AC-15", func(t *testing.T) {})
	rules := sampleRules()
	got := filterRulesByFramework(rules, "nist_800_53")
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "c" {
		t.Errorf("expected [a,c]; got %v", ids(got))
	}
}

// @spec cli-framework-filter
// @ac AC-16
func TestFilterRulesByFramework_PreservesOrder(t *testing.T) {
	t.Run("cli-framework-filter/AC-16", func(t *testing.T) {})
	rules := []*api.Rule{
		ruleWithRefs("z", map[string]interface{}{"nist_800_53": []interface{}{"AC-1"}}),
		ruleWithRefs("a", map[string]interface{}{"nist_800_53": []interface{}{"AC-2"}}),
	}
	got := filterRulesByFramework(rules, "nist_800_53")
	if len(got) != 2 || got[0].ID != "z" || got[1].ID != "a" {
		t.Errorf("expected [z,a] (input order); got %v", ids(got))
	}
}

// ids helper for diagnostic readability in test failures.
func ids(rules []*api.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.ID
	}
	return out
}
