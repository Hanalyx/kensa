// Tests for --category / -c rule filter (C-032).
package main

import (
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

// @spec cli-category-filter
// @ac AC-01
// @ac AC-08
func TestFilterRulesByCategory_Empty(t *testing.T) {
	t.Run("cli-category-filter/AC-01", func(t *testing.T) {})
	t.Run("cli-category-filter/AC-08", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Category: "audit"},
		{ID: "b", Category: "network"},
	}
	if got := filterRulesByCategory(rules, ""); len(got) != 2 {
		t.Errorf("empty allowed should pass through; got %d", len(got))
	}
	if got := filterRulesByCategory(rules, "   "); len(got) != 2 {
		t.Errorf("whitespace-only allowed should pass through; got %d", len(got))
	}
}

// @spec cli-category-filter
// @ac AC-02
func TestFilterRulesByCategory_ExactMatch(t *testing.T) {
	t.Run("cli-category-filter/AC-02", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Category: "audit"},
		{ID: "b", Category: "network"},
		{ID: "c", Category: "audit"},
	}
	got := filterRulesByCategory(rules, "audit")
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "c" {
		t.Errorf("expected [a,c]; got %v", got)
	}
}

// @spec cli-category-filter
// @ac AC-03
func TestFilterRulesByCategory_CaseInsensitive(t *testing.T) {
	t.Run("cli-category-filter/AC-03", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Category: "Audit"},
		{ID: "b", Category: "AUDIT"},
		{ID: "c", Category: "  audit  "},
	}
	got := filterRulesByCategory(rules, "AUDIT")
	if len(got) != 3 {
		t.Errorf("case-insensitive match should hit all 3; got %d", len(got))
	}
}

// @spec cli-category-filter
// @ac AC-04
func TestFilterRulesByCategory_NoMatch(t *testing.T) {
	t.Run("cli-category-filter/AC-04", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Category: "audit"},
	}
	got := filterRulesByCategory(rules, "kernel")
	if len(got) != 0 {
		t.Errorf("expected empty; got %v", got)
	}
}

// @spec cli-category-filter
// @ac AC-05
func TestFilterRulesByCategory_PreservesOrder(t *testing.T) {
	t.Run("cli-category-filter/AC-05", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "z", Category: "audit"},
		{ID: "a", Category: "network"},
		{ID: "m", Category: "audit"},
	}
	got := filterRulesByCategory(rules, "audit")
	if len(got) != 2 || got[0].ID != "z" || got[1].ID != "m" {
		t.Errorf("expected [z,m]; got %v", got)
	}
}

// @spec cli-category-filter
// @ac AC-06
func TestFilterRulesByCategory_RuleEmptyCategory(t *testing.T) {
	t.Run("cli-category-filter/AC-06", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Category: ""},
		{ID: "b", Category: "audit"},
	}
	got := filterRulesByCategory(rules, "audit")
	if len(got) != 1 || got[0].ID != "b" {
		t.Errorf("expected only [b]; got %v", got)
	}
}

// @spec cli-category-filter
// @ac AC-07
func TestFilterRulesByCategory_OperatorInputTrimmed(t *testing.T) {
	t.Run("cli-category-filter/AC-07", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Category: "audit"},
	}
	got := filterRulesByCategory(rules, "  audit  ")
	if len(got) != 1 {
		t.Errorf("operator-side whitespace should be trimmed; got %d", len(got))
	}
}
