// Tests for --tag / -t rule filtering (C-031).
package main

import (
	"reflect"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

// @spec cli-tag-filter
// @ac AC-01
func TestNormalizeTags_Empty(t *testing.T) {
	t.Run("cli-tag-filter/AC-01", func(t *testing.T) {})
	if got := normalizeTags(nil); got != nil {
		t.Errorf("nil should return nil; got %v", got)
	}
	if got := normalizeTags([]string{}); got != nil {
		t.Errorf("empty should return nil; got %v", got)
	}
}

// @spec cli-tag-filter
// @ac AC-02
func TestNormalizeTags_LowercasesTrims(t *testing.T) {
	t.Run("cli-tag-filter/AC-02", func(t *testing.T) {})
	got := normalizeTags([]string{"PCI", "  CIS  ", "Network"})
	want := []string{"pci", "cis", "network"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// @spec cli-tag-filter
// @ac AC-03
func TestNormalizeTags_Deduplicates(t *testing.T) {
	t.Run("cli-tag-filter/AC-03", func(t *testing.T) {})
	got := normalizeTags([]string{"pci", "PCI", "  pci  "})
	want := []string{"pci"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// @spec cli-tag-filter
// @ac AC-04
func TestNormalizeTags_DropsEmpty(t *testing.T) {
	t.Run("cli-tag-filter/AC-04", func(t *testing.T) {})
	got := normalizeTags([]string{"pci", "", "  ", "cis"})
	want := []string{"pci", "cis"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// @spec cli-tag-filter
// @ac AC-05
func TestFilterRulesByTag_Empty(t *testing.T) {
	t.Run("cli-tag-filter/AC-05", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Tags: []string{"pci"}},
		{ID: "b", Tags: []string{"cis"}},
	}
	got := filterRulesByTag(rules, nil)
	if len(got) != 2 {
		t.Errorf("empty allowed should pass through; got %d", len(got))
	}
}

// @spec cli-tag-filter
// @ac AC-06
func TestFilterRulesByTag_SingleTag(t *testing.T) {
	t.Run("cli-tag-filter/AC-06", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Tags: []string{"pci", "network"}},
		{ID: "b", Tags: []string{"cis"}},
		{ID: "c", Tags: []string{"network"}},
	}
	got := filterRulesByTag(rules, []string{"pci"})
	if len(got) != 1 || got[0].ID != "a" {
		t.Errorf("expected only [a]; got %v", got)
	}
}

// @spec cli-tag-filter
// @ac AC-07
func TestFilterRulesByTag_OrSemanticsAcrossValues(t *testing.T) {
	t.Run("cli-tag-filter/AC-07", func(t *testing.T) {})
	// -t pci -t cis matches rules with PCI OR CIS, not AND.
	rules := []*api.Rule{
		{ID: "a", Tags: []string{"pci"}},
		{ID: "b", Tags: []string{"cis"}},
		{ID: "c", Tags: []string{"network"}},
	}
	got := filterRulesByTag(rules, []string{"pci", "cis"})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].ID != "a" || got[1].ID != "b" {
		t.Errorf("expected [a,b]; got %v", got)
	}
}

// @spec cli-tag-filter
// @ac AC-08
func TestFilterRulesByTag_PreservesOrder(t *testing.T) {
	t.Run("cli-tag-filter/AC-08", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "z", Tags: []string{"pci"}},
		{ID: "a", Tags: []string{"cis"}},
		{ID: "m", Tags: []string{"pci"}},
	}
	got := filterRulesByTag(rules, []string{"pci"})
	if len(got) != 2 || got[0].ID != "z" || got[1].ID != "m" {
		t.Errorf("expected [z,m] (input order); got %v", got)
	}
}

// @spec cli-tag-filter
// @ac AC-09
func TestFilterRulesByTag_CaseInsensitive(t *testing.T) {
	t.Run("cli-tag-filter/AC-09", func(t *testing.T) {})
	// Rule corpora may have any casing; match must work either way.
	rules := []*api.Rule{
		{ID: "a", Tags: []string{"PCI"}},
		{ID: "b", Tags: []string{"  Network  "}},
	}
	got := filterRulesByTag(rules, []string{"pci", "network"})
	if len(got) != 2 {
		t.Errorf("case-insensitive match expected; got %d", len(got))
	}
}

// @spec cli-tag-filter
// @ac AC-10
func TestFilterRulesByTag_NoMatch(t *testing.T) {
	t.Run("cli-tag-filter/AC-10", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Tags: []string{"pci"}},
	}
	got := filterRulesByTag(rules, []string{"hipaa"})
	if len(got) != 0 {
		t.Errorf("expected no matches; got %v", got)
	}
}

// @spec cli-tag-filter
// @ac AC-11
func TestFilterRulesByTag_RuleWithEmptyTags(t *testing.T) {
	t.Run("cli-tag-filter/AC-11", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Tags: nil},
		{ID: "b", Tags: []string{}},
		{ID: "c", Tags: []string{"pci"}},
	}
	got := filterRulesByTag(rules, []string{"pci"})
	if len(got) != 1 || got[0].ID != "c" {
		t.Errorf("rules with empty Tags should not match; got %v", got)
	}
}
