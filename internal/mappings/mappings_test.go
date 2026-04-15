package mappings_test

import (
	"sort"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/mappings"
	"github.com/Hanalyx/kensa-go/internal/rule"
)

// TestRefsFromReferences_CIS verifies that CIS versioned references are
// expanded to one FrameworkRef per OS version.
func TestRefsFromReferences_CIS(t *testing.T) {
	refs := map[string]interface{}{
		"cis": map[string]interface{}{
			"rhel8": map[string]interface{}{"section": "5.2.10", "level": "L1"},
			"rhel9": map[string]interface{}{"section": "5.2.3", "level": "L1"},
		},
	}
	got := mappings.RefsFromReferences(refs)
	if len(got) != 2 {
		t.Fatalf("expected 2 refs, got %d: %v", len(got), got)
	}
	byFID := refsByFrameworkID(got)
	if byFID["cis_rhel8"] != "5.2.10" {
		t.Errorf("cis_rhel8 control=%q, want 5.2.10", byFID["cis_rhel8"])
	}
	if byFID["cis_rhel9"] != "5.2.3" {
		t.Errorf("cis_rhel9 control=%q, want 5.2.3", byFID["cis_rhel9"])
	}
}

// TestRefsFromReferences_STIG verifies that STIG versioned references use
// vuln_id as the control identifier.
func TestRefsFromReferences_STIG(t *testing.T) {
	refs := map[string]interface{}{
		"stig": map[string]interface{}{
			"rhel9": map[string]interface{}{
				"vuln_id":  "V-257947",
				"stig_id":  "RHEL-09-255045",
				"severity": "CAT II",
			},
		},
	}
	got := mappings.RefsFromReferences(refs)
	if len(got) != 1 {
		t.Fatalf("expected 1 ref, got %d: %v", len(got), got)
	}
	if got[0].FrameworkID != "stig_rhel9" {
		t.Errorf("FrameworkID=%q, want stig_rhel9", got[0].FrameworkID)
	}
	if got[0].ControlID != "V-257947" {
		t.Errorf("ControlID=%q, want V-257947", got[0].ControlID)
	}
}

// TestRefsFromReferences_FlatList verifies that flat-list frameworks produce
// one FrameworkRef per control string.
func TestRefsFromReferences_FlatList(t *testing.T) {
	refs := map[string]interface{}{
		"nist_800_53": []interface{}{"AC-6(2)", "AC-17(2)", "IA-2(5)"},
		"pci_dss_4":   []interface{}{"2.2.6", "8.6.1"},
	}
	got := mappings.RefsFromReferences(refs)
	if len(got) != 5 {
		t.Fatalf("expected 5 refs, got %d: %v", len(got), got)
	}
	nist := refsForFramework(got, "nist_800_53")
	if len(nist) != 3 {
		t.Errorf("nist_800_53 refs=%d, want 3", len(nist))
	}
	pci := refsForFramework(got, "pci_dss_4")
	if len(pci) != 2 {
		t.Errorf("pci_dss_4 refs=%d, want 2", len(pci))
	}
}

// TestRefsFromReferences_Mixed tests a realistic multi-framework references block.
func TestRefsFromReferences_Mixed(t *testing.T) {
	refs := map[string]interface{}{
		"cis": map[string]interface{}{
			"rhel9": map[string]interface{}{"section": "5.1.20", "level": "L1"},
		},
		"stig": map[string]interface{}{
			"rhel9": map[string]interface{}{"vuln_id": "V-257947", "stig_id": "RHEL-09-255045"},
		},
		"nist_800_53": []interface{}{"AC-6(2)", "AC-17(2)"},
	}
	got := mappings.RefsFromReferences(refs)
	if len(got) != 4 {
		t.Fatalf("expected 4 refs, got %d: %v", len(got), got)
	}
}

// TestRefsFromReferences_EmptyNil verifies that nil and empty maps return nil.
func TestRefsFromReferences_EmptyNil(t *testing.T) {
	if refs := mappings.RefsFromReferences(nil); refs != nil {
		t.Errorf("expected nil for nil input, got %v", refs)
	}
	if refs := mappings.RefsFromReferences(map[string]interface{}{}); refs != nil {
		t.Errorf("expected nil for empty input, got %v", refs)
	}
}

// TestRefsFromReferences_UnknownVersionedFramework verifies best-effort
// extraction for an unrecognized versioned framework.
func TestRefsFromReferences_UnknownVersionedFramework(t *testing.T) {
	refs := map[string]interface{}{
		"iso27001_2022": map[string]interface{}{
			"2022": map[string]interface{}{"control": "A.8.9"},
		},
	}
	got := mappings.RefsFromReferences(refs)
	// Best-effort: should produce at least one ref with FrameworkID iso27001_2022_2022.
	if len(got) == 0 {
		t.Error("expected at least one ref for unknown versioned framework")
	}
}

// TestRefsFromReferences_Fixture verifies that the ssh-disable-root-login
// fixture produces the expected FrameworkRefs when its references block is
// parsed via the rule loader then expanded.
func TestRefsFromReferences_Fixture(t *testing.T) {
	r, err := rule.ParseFile("../rule/testdata/ssh-disable-root-login.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	got := mappings.RefsFromReferences(r.References)
	// Expect: cis_rhel9 + stig_rhel9 + 3 nist_800_53 = 5 refs.
	if len(got) != 5 {
		t.Fatalf("expected 5 refs, got %d: %v", len(got), got)
	}
	byFID := refsByFrameworkID(got)
	if byFID["cis_rhel9"] != "5.1.20" {
		t.Errorf("cis_rhel9=%q, want 5.1.20", byFID["cis_rhel9"])
	}
	if byFID["stig_rhel9"] != "V-257947" {
		t.Errorf("stig_rhel9=%q, want V-257947", byFID["stig_rhel9"])
	}
}

// ─── helpers ───────────────────────────────────────────────────────────────

// refsByFrameworkID returns a map from FrameworkID to ControlID.
// When multiple refs share the same FrameworkID, the last one wins
// (use refsForFramework for multi-value cases).
func refsByFrameworkID(refs []api.FrameworkRef) map[string]string {
	m := make(map[string]string, len(refs))
	for _, r := range refs {
		m[r.FrameworkID] = r.ControlID
	}
	return m
}

// refsForFramework returns all refs with the given FrameworkID, sorted by
// ControlID for deterministic comparison.
func refsForFramework(refs []api.FrameworkRef, frameworkID string) []api.FrameworkRef {
	var out []api.FrameworkRef
	for _, r := range refs {
		if r.FrameworkID == frameworkID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ControlID < out[j].ControlID
	})
	return out
}
