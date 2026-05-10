package coverage

import (
	"sort"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

// makeRule constructs an api.Rule with the given ID and
// framework references. References uses the same map shape
// that mappings.RefsFromReferences expects: a top-level key
// per framework, value is either a flat []string of control
// IDs or a versioned map. We use the flat form throughout
// because it's the simpler shape and exercises the same
// code path that yields Framework.RefsFromReferences →
// FrameworkRef tuples.
func makeRule(id string, refs map[string]any) *api.Rule {
	return &api.Rule{
		ID:         id,
		References: refs,
	}
}

func TestComputeReport_Basic(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", map[string]any{
			"nist_800_53": []any{"AC-1", "AU-2"},
		}),
		makeRule("r2", map[string]any{
			"nist_800_53": []any{"AC-1"},
		}),
	}

	got := ComputeReport("nist_800_53", rules)

	if got.Framework != "nist_800_53" {
		t.Errorf("Framework: got %q want nist_800_53", got.Framework)
	}
	if got.RulesScanned != 2 {
		t.Errorf("RulesScanned: got %d want 2", got.RulesScanned)
	}
	if got.RulesMatching != 2 {
		t.Errorf("RulesMatching: got %d want 2", got.RulesMatching)
	}
	if got.ControlsMapped != 2 { // AC-1 + AU-2
		t.Errorf("ControlsMapped: got %d want 2", got.ControlsMapped)
	}
	if len(got.Controls) != 2 {
		t.Fatalf("Controls len: got %d want 2", len(got.Controls))
	}
	// Sorted by control_id; "AC-1" < "AU-2" alphabetically.
	if got.Controls[0].ControlID != "AC-1" {
		t.Errorf("first control: got %q want AC-1", got.Controls[0].ControlID)
	}
	if got.Controls[0].RuleCount != 2 {
		t.Errorf("AC-1 RuleCount: got %d want 2", got.Controls[0].RuleCount)
	}
	if got.Controls[1].RuleCount != 1 {
		t.Errorf("AU-2 RuleCount: got %d want 1", got.Controls[1].RuleCount)
	}
}

// TestComputeReport_FilterByFramework: rules referencing other
// frameworks don't pollute the output.
func TestComputeReport_FilterByFramework(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", map[string]any{"nist_800_53": []any{"AC-1"}}),
		makeRule("r2", map[string]any{"pci_dss": []any{"2.2.4"}}),
	}
	got := ComputeReport("nist_800_53", rules)
	if got.RulesMatching != 1 {
		t.Errorf("RulesMatching: got %d want 1", got.RulesMatching)
	}
	if got.ControlsMapped != 1 {
		t.Errorf("ControlsMapped: got %d want 1", got.ControlsMapped)
	}
	if got.Controls[0].ControlID != "AC-1" {
		t.Errorf("first control: got %q", got.Controls[0].ControlID)
	}
}

// TestComputeReport_DedupesControls: multiple rules referencing
// the same control yield one ControlCoverage row with both rules
// listed.
func TestComputeReport_DedupesControls(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", map[string]any{"nist_800_53": []any{"AC-1"}}),
		makeRule("r2", map[string]any{"nist_800_53": []any{"AC-1"}}),
		makeRule("r3", map[string]any{"nist_800_53": []any{"AC-1"}}),
	}
	got := ComputeReport("nist_800_53", rules)
	if got.ControlsMapped != 1 {
		t.Errorf("ControlsMapped: got %d want 1", got.ControlsMapped)
	}
	if got.Controls[0].RuleCount != 3 {
		t.Errorf("RuleCount: got %d want 3", got.Controls[0].RuleCount)
	}
	if !sort.StringsAreSorted(got.Controls[0].Rules) {
		t.Errorf("Rules slice not sorted: %v", got.Controls[0].Rules)
	}
}

// TestComputeReport_Empty: no rules, no matching framework — zero
// counts, empty Controls.
func TestComputeReport_Empty(t *testing.T) {
	got := ComputeReport("nist_800_53", nil)
	if got.RulesScanned != 0 || got.RulesMatching != 0 || got.ControlsMapped != 0 {
		t.Errorf("empty corpus should yield zero counts; got %+v", got)
	}
	if len(got.Controls) != 0 {
		t.Errorf("empty Controls expected; got %v", got.Controls)
	}
}

// TestComputeReport_NoMatchingFramework: rules exist but none
// match the requested framework.
func TestComputeReport_NoMatchingFramework(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", map[string]any{"pci_dss": []any{"2.2.4"}}),
	}
	got := ComputeReport("nist_800_53", rules)
	if got.RulesScanned != 1 {
		t.Errorf("RulesScanned: got %d want 1", got.RulesScanned)
	}
	if got.RulesMatching != 0 {
		t.Errorf("RulesMatching: got %d want 0", got.RulesMatching)
	}
	if got.ControlsMapped != 0 {
		t.Errorf("ControlsMapped: got %d want 0", got.ControlsMapped)
	}
}

// TestComputeReport_Deterministic: control IDs sorted; rules
// per control sorted. Run the same input twice and compare
// every order-sensitive slice.
func TestComputeReport_Deterministic(t *testing.T) {
	rules := []*api.Rule{
		makeRule("z-rule", map[string]any{"nist_800_53": []any{"AC-3", "AC-1", "AC-2"}}),
		makeRule("a-rule", map[string]any{"nist_800_53": []any{"AC-1", "AC-2"}}),
		makeRule("m-rule", map[string]any{"nist_800_53": []any{"AC-1"}}),
	}
	for i := 0; i < 3; i++ {
		got := ComputeReport("nist_800_53", rules)
		want := []string{"AC-1", "AC-2", "AC-3"}
		var ids []string
		for _, c := range got.Controls {
			ids = append(ids, c.ControlID)
		}
		if !equalStrings(ids, want) {
			t.Errorf("iter %d: control order: got %v want %v", i, ids, want)
		}
		// AC-1 has 3 rules — must be sorted alphabetically.
		ac1 := got.Controls[0]
		want1 := []string{"a-rule", "m-rule", "z-rule"}
		if !equalStrings(ac1.Rules, want1) {
			t.Errorf("iter %d: AC-1 rules order: got %v want %v", i, ac1.Rules, want1)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestComputeReport_VersionedFramework exercises the CIS-style
// versioned reference map (the mappings.RefsFromReferences side
// produces "cis_rhel9" framework_id from a "cis" key with an
// "rhel9" subkey).
func TestComputeReport_VersionedFramework(t *testing.T) {
	// The mappings extractor expects CIS versioned details as a
	// nested object with a "section" field; "rhel9" key produces
	// FrameworkID "cis_rhel9".
	rules := []*api.Rule{
		makeRule("r1", map[string]any{
			"cis": map[string]any{
				"rhel9": map[string]any{
					"section": "5.1.12",
				},
			},
		}),
	}
	got := ComputeReport("cis_rhel9", rules)
	if got.ControlsMapped != 1 {
		t.Errorf("ControlsMapped: got %d want 1", got.ControlsMapped)
	}
	if got.Controls[0].ControlID != "5.1.12" {
		t.Errorf("ControlID: got %q want 5.1.12", got.Controls[0].ControlID)
	}
}
