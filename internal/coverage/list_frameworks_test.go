package coverage

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
)

func TestListFrameworks_Basic(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", map[string]any{
			"nist_800_53": []any{"AC-1", "AU-2"},
		}),
		makeRule("r2", map[string]any{
			"nist_800_53": []any{"AC-1"},
		}),
		makeRule("r3", map[string]any{
			"pci_dss": []any{"2.2.4"},
		}),
	}

	got := ListFrameworks(rules)

	if len(got) != 2 {
		t.Fatalf("expected 2 frameworks, got %d: %+v", len(got), got)
	}
	// Alphabetical: nist_800_53 < pci_dss.
	if got[0].FrameworkID != "nist_800_53" {
		t.Errorf("first framework: got %q want nist_800_53", got[0].FrameworkID)
	}
	if got[0].Controls != 2 { // AC-1, AU-2
		t.Errorf("nist controls: got %d want 2", got[0].Controls)
	}
	if got[0].Rules != 2 { // r1, r2
		t.Errorf("nist rules: got %d want 2", got[0].Rules)
	}
	if got[1].FrameworkID != "pci_dss" {
		t.Errorf("second framework: got %q want pci_dss", got[1].FrameworkID)
	}
	if got[1].Controls != 1 || got[1].Rules != 1 {
		t.Errorf("pci_dss row wrong: got %+v want {1, 1}", got[1])
	}
}

// TestListFrameworks_DistinctCounts: multiple rules referencing
// the same control collapse on the controls axis, but each
// distinct rule_id is counted in the rules axis.
func TestListFrameworks_DistinctCounts(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", map[string]any{"nist_800_53": []any{"AC-1"}}),
		makeRule("r2", map[string]any{"nist_800_53": []any{"AC-1"}}),
		makeRule("r3", map[string]any{"nist_800_53": []any{"AC-1"}}),
	}
	got := ListFrameworks(rules)
	if len(got) != 1 {
		t.Fatalf("expected 1 framework, got %d", len(got))
	}
	if got[0].Controls != 1 {
		t.Errorf("Controls: got %d want 1 (one distinct control_id)", got[0].Controls)
	}
	if got[0].Rules != 3 {
		t.Errorf("Rules: got %d want 3 (three distinct rule_ids)", got[0].Rules)
	}
}

func TestListFrameworks_Empty(t *testing.T) {
	got := ListFrameworks(nil)
	if len(got) != 0 {
		t.Errorf("empty corpus should yield empty slice; got %v", got)
	}
}

func TestListFrameworks_Deterministic(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", map[string]any{"z_framework": []any{"x"}}),
		makeRule("r2", map[string]any{"a_framework": []any{"x"}}),
		makeRule("r3", map[string]any{"m_framework": []any{"x"}}),
	}
	for i := 0; i < 3; i++ {
		got := ListFrameworks(rules)
		want := []string{"a_framework", "m_framework", "z_framework"}
		var ids []string
		for _, f := range got {
			ids = append(ids, f.FrameworkID)
		}
		if !equalStrings(ids, want) {
			t.Errorf("iter %d: order: got %v want %v", i, ids, want)
		}
	}
}

// TestListFrameworks_VersionedCIS exercises the CIS-style
// versioned references (rhel8 + rhel9 expand to two distinct
// framework_ids: cis_rhel8 and cis_rhel9).
func TestListFrameworks_VersionedCIS(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", map[string]any{
			"cis": map[string]any{
				"rhel8": map[string]any{"section": "1.1.1"},
				"rhel9": map[string]any{"section": "1.1.1"},
			},
		}),
	}
	got := ListFrameworks(rules)
	if len(got) != 2 {
		t.Fatalf("expected 2 framework_ids (cis_rhel8 + cis_rhel9), got %d: %+v",
			len(got), got)
	}
	// Each version row has 1 control + 1 rule.
	for _, f := range got {
		if f.Controls != 1 || f.Rules != 1 {
			t.Errorf("%s: got %+v want {1, 1}", f.FrameworkID, f)
		}
	}
}
