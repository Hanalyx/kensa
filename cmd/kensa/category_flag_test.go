// Tests for --category / -c rule filter (C-032).
package main

import (
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

func TestFilterRulesByCategory_Empty(t *testing.T) {
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

func TestFilterRulesByCategory_ExactMatch(t *testing.T) {
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

func TestFilterRulesByCategory_CaseInsensitive(t *testing.T) {
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

func TestFilterRulesByCategory_NoMatch(t *testing.T) {
	rules := []*api.Rule{
		{ID: "a", Category: "audit"},
	}
	got := filterRulesByCategory(rules, "kernel")
	if len(got) != 0 {
		t.Errorf("expected empty; got %v", got)
	}
}

func TestFilterRulesByCategory_PreservesOrder(t *testing.T) {
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

func TestFilterRulesByCategory_RuleEmptyCategory(t *testing.T) {
	rules := []*api.Rule{
		{ID: "a", Category: ""},
		{ID: "b", Category: "audit"},
	}
	got := filterRulesByCategory(rules, "audit")
	if len(got) != 1 || got[0].ID != "b" {
		t.Errorf("expected only [b]; got %v", got)
	}
}

func TestFilterRulesByCategory_OperatorInputTrimmed(t *testing.T) {
	rules := []*api.Rule{
		{ID: "a", Category: "audit"},
	}
	got := filterRulesByCategory(rules, "  audit  ")
	if len(got) != 1 {
		t.Errorf("operator-side whitespace should be trimmed; got %d", len(got))
	}
}
