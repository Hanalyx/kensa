package info

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

func makeRule(id, title, desc string, severity string, refs map[string]any, platforms ...api.Platform) *api.Rule {
	return &api.Rule{
		ID:          id,
		Title:       title,
		Description: desc,
		Severity:    severity,
		References:  refs,
		Platforms:   platforms,
	}
}

func TestDescribeRule_Found(t *testing.T) {
	rules := []*api.Rule{
		makeRule("foo", "Foo title", "Foo desc", "high",
			map[string]any{"nist_800_53": []any{"AC-1"}}),
	}
	got, err := DescribeRule("foo", rules)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if got.ID != "foo" || got.Title != "Foo title" {
		t.Errorf("got %+v", got)
	}
	if len(got.FrameworkRefs) != 1 || got.FrameworkRefs[0].ControlID != "AC-1" {
		t.Errorf("framework refs: %+v", got.FrameworkRefs)
	}
}

func TestDescribeRule_NotFound(t *testing.T) {
	_, err := DescribeRule("missing", nil)
	var nf *ErrNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected ErrNotFound; got %T %v", err, err)
	}
	if nf.What != "rule" || nf.Key != "missing" {
		t.Errorf("not-found shape: got %+v", nf)
	}
}

func TestRulesForControl_Found(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "R1", "", "", map[string]any{"nist_800_53": []any{"AC-1"}}),
		makeRule("r2", "R2", "", "", map[string]any{"nist_800_53": []any{"AC-1"}}),
		makeRule("r3", "R3", "", "", map[string]any{"nist_800_53": []any{"AU-2"}}),
	}
	got, err := RulesForControl("nist_800_53", "AC-1", rules)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(got.Rules) != 2 {
		t.Errorf("expected 2 mapping rules, got %d", len(got.Rules))
	}
	// Sorted alphabetically.
	if got.Rules[0] != "r1" || got.Rules[1] != "r2" {
		t.Errorf("not sorted: %v", got.Rules)
	}
}

func TestRulesForControl_NotFound(t *testing.T) {
	_, err := RulesForControl("nist_800_53", "ZZ-99", nil)
	var nf *ErrNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestListFrameworkControls_Found(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "", "", "", map[string]any{"nist_800_53": []any{"AC-1", "AU-2"}}),
		makeRule("r2", "", "", "", map[string]any{"nist_800_53": []any{"AC-1"}}),
	}
	got, err := ListFrameworkControls("nist_800_53", rules)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got.Controls) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(got.Controls))
	}
	// AC-1 (2 rules) sorts before AU-2 (1 rule) alphabetically.
	if got.Controls[0].ControlID != "AC-1" || got.Controls[0].RuleCount != 2 {
		t.Errorf("first control: %+v", got.Controls[0])
	}
	if got.Controls[1].ControlID != "AU-2" || got.Controls[1].RuleCount != 1 {
		t.Errorf("second control: %+v", got.Controls[1])
	}
}

func TestListFrameworkControls_NotFound(t *testing.T) {
	_, err := ListFrameworkControls("missing_framework", nil)
	var nf *ErrNotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected ErrNotFound; got %v", err)
	}
}

func TestListFrameworkControls_Deterministic(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "", "", "", map[string]any{"nist_800_53": []any{"AC-3", "AC-1", "AC-2"}}),
	}
	for i := 0; i < 3; i++ {
		got, err := ListFrameworkControls("nist_800_53", rules)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"AC-1", "AC-2", "AC-3"}
		var ids []string
		for _, c := range got.Controls {
			ids = append(ids, c.ControlID)
		}
		if !equalStrings(ids, want) {
			t.Errorf("iter %d: order: got %v want %v", i, ids, want)
		}
	}
}

func TestSearchRules_Basic(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "Disable SSH root login", "Restrict SSH access", "high", nil),
		makeRule("r2", "Enable ASLR", "Memory protection", "medium", nil),
		makeRule("r3", "SSH banner config", "Login banner setup", "low", nil),
	}
	got := SearchRules("ssh", SearchFilters{}, rules)
	if len(got) != 2 {
		t.Errorf("expected 2 SSH-matching rules, got %d: %+v", len(got), got)
	}
	// Sorted by ID.
	if got[0].ID != "r1" || got[1].ID != "r3" {
		t.Errorf("order: got %v", got)
	}
}

func TestSearchRules_CaseInsensitive(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "DISABLE SSH ROOT", "MEMORY PROTECTION", "high", nil),
	}
	for _, q := range []string{"ssh", "SSH", "Ssh", "MEMORY", "memory"} {
		got := SearchRules(q, SearchFilters{}, rules)
		if len(got) != 1 {
			t.Errorf("query %q: expected 1 hit, got %d", q, len(got))
		}
	}
}

func TestSearchRules_EmptyQuery(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "A", "", "", nil),
		makeRule("r2", "B", "", "", nil),
	}
	got := SearchRules("", SearchFilters{}, rules)
	if len(got) != 2 {
		t.Errorf("empty query should return all; got %d", len(got))
	}
}

func TestSearchRules_FamilyFilter(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "T1", "", "", map[string]any{"nist_800_53": []any{"AC-1"}}),
		makeRule("r2", "T2", "", "", map[string]any{"pci_dss": []any{"1.1"}}),
		makeRule("r3", "T3", "", "", map[string]any{
			"cis": map[string]any{"rhel9": map[string]any{"section": "1.1.1"}},
		}),
	}
	got := SearchRules("", SearchFilters{FamilyPrefix: "cis_"}, rules)
	if len(got) != 1 || got[0].ID != "r3" {
		t.Errorf("cis_ filter: got %v", got)
	}
}

func TestSearchRules_RhelFilter(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "T1", "", "", nil, api.Platform{Family: "rhel", MinVersion: 8}),
		makeRule("r2", "T2", "", "", nil, api.Platform{Family: "rhel", MinVersion: 9}),
		makeRule("r3", "T3", "", "", nil, api.Platform{Family: "ubuntu"}),
	}
	got := SearchRules("", SearchFilters{Rhel: 8}, rules)
	// MinVersion 8 matches r1 (8 ≥ 8) and r2 (8 < 9 → no, rejected).
	// MinVersion 9 means "RHEL 9 or later"; querying for rhel=8 should
	// reject r2 (8 < 9). Only r1 matches.
	if len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("rhel=8 filter: got %v", got)
	}
}

func TestSearchRules_Deterministic(t *testing.T) {
	rules := []*api.Rule{
		makeRule("z-rule", "T", "", "", nil),
		makeRule("a-rule", "T", "", "", nil),
		makeRule("m-rule", "T", "", "", nil),
	}
	for i := 0; i < 3; i++ {
		got := SearchRules("", SearchFilters{}, rules)
		want := []string{"a-rule", "m-rule", "z-rule"}
		var ids []string
		for _, h := range got {
			ids = append(ids, h.ID)
		}
		if !equalStrings(ids, want) {
			t.Errorf("iter %d: order: got %v want %v", i, ids, want)
		}
	}
}

func TestSearchRules_TitleAndDescription(t *testing.T) {
	rules := []*api.Rule{
		makeRule("r1", "Title-only-match", "no", "", nil),
		makeRule("r2", "no", "Description-only-match", "", nil),
	}
	got := SearchRules("title-only", SearchFilters{}, rules)
	if len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("title-substring search: got %v", got)
	}
	got = SearchRules("description-only", SearchFilters{}, rules)
	if len(got) != 1 || got[0].ID != "r2" {
		t.Errorf("description-substring search: got %v", got)
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

// silenceImport avoids an "unused" warning if `strings` becomes
// unused after future test pruning.
var _ = strings.HasPrefix
