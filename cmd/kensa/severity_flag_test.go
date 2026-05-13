// Tests for --severity / -s validation and filtering (C-030).
package main

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

// @spec cli-severity-filter
// @ac AC-01
// @ac AC-11
func TestValidateSeverities_Empty(t *testing.T) {
	t.Run("cli-severity-filter/AC-01", func(t *testing.T) {})
	t.Run("cli-severity-filter/AC-11", func(t *testing.T) {})
	got, err := validateSeverities(nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if got != nil {
		t.Errorf("nil should return nil; got %v", got)
	}
	got, err = validateSeverities([]string{})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if got != nil {
		t.Errorf("empty should return nil; got %v", got)
	}
}

// @spec cli-severity-filter
// @ac AC-02
func TestValidateSeverities_AllValid(t *testing.T) {
	t.Run("cli-severity-filter/AC-02", func(t *testing.T) {})
	for _, s := range []string{"critical", "high", "medium", "low"} {
		got, err := validateSeverities([]string{s})
		if err != nil {
			t.Errorf("%s: %v", s, err)
		}
		if len(got) != 1 || got[0] != s {
			t.Errorf("%s: expected [%s], got %v", s, s, got)
		}
	}
}

// @spec cli-severity-filter
// @ac AC-03
func TestValidateSeverities_CaseInsensitive(t *testing.T) {
	t.Run("cli-severity-filter/AC-03", func(t *testing.T) {})
	got, err := validateSeverities([]string{"CRITICAL", "High", "  medium  "})
	if err != nil {
		t.Fatalf("case: %v", err)
	}
	expected := []string{"critical", "high", "medium"}
	if len(got) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
	for i, e := range expected {
		if got[i] != e {
			t.Errorf("idx %d: expected %s, got %s", i, e, got[i])
		}
	}
}

// @spec cli-severity-filter
// @ac AC-04
func TestValidateSeverities_Deduplicates(t *testing.T) {
	t.Run("cli-severity-filter/AC-04", func(t *testing.T) {})
	got, err := validateSeverities([]string{"high", "high", "HIGH"})
	if err != nil {
		t.Fatalf("dedup: %v", err)
	}
	if len(got) != 1 || got[0] != "high" {
		t.Errorf("expected single 'high'; got %v", got)
	}
}

// @spec cli-severity-filter
// @ac AC-05
func TestValidateSeverities_Unknown(t *testing.T) {
	t.Run("cli-severity-filter/AC-05", func(t *testing.T) {})
	for _, in := range []string{"severe", "info", "warn", "", "med"} {
		_, err := validateSeverities([]string{in})
		if err == nil {
			t.Errorf("%q should reject", in)
			continue
		}
		if !strings.Contains(err.Error(), "unknown severity") {
			t.Errorf("%q error should mention 'unknown severity': %v", in, err)
		}
		if !strings.Contains(err.Error(), "critical") {
			t.Errorf("%q error should list valid choices: %v", in, err)
		}
	}
}

// @spec cli-severity-filter
// @ac AC-06
func TestFilterRulesBySeverity_Empty(t *testing.T) {
	t.Run("cli-severity-filter/AC-06", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Severity: "critical"},
		{ID: "b", Severity: "low"},
	}
	got := filterRulesBySeverity(rules, nil)
	if len(got) != 2 {
		t.Errorf("empty allowed should pass through unchanged; got %d", len(got))
	}
}

// @spec cli-severity-filter
// @ac AC-07
func TestFilterRulesBySeverity_Single(t *testing.T) {
	t.Run("cli-severity-filter/AC-07", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Severity: "critical"},
		{ID: "b", Severity: "low"},
		{ID: "c", Severity: "high"},
		{ID: "d", Severity: "medium"},
	}
	got := filterRulesBySeverity(rules, []string{"high"})
	if len(got) != 1 || got[0].ID != "c" {
		t.Errorf("expected only 'c'; got %v", got)
	}
}

// @spec cli-severity-filter
// @ac AC-08
func TestFilterRulesBySeverity_Multiple(t *testing.T) {
	t.Run("cli-severity-filter/AC-08", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "a", Severity: "critical"},
		{ID: "b", Severity: "low"},
		{ID: "c", Severity: "high"},
		{ID: "d", Severity: "medium"},
	}
	got := filterRulesBySeverity(rules, []string{"critical", "high"})
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].ID != "a" || got[1].ID != "c" {
		t.Errorf("expected [a,c]; got %v", got)
	}
}

// @spec cli-severity-filter
// @ac AC-09
func TestFilterRulesBySeverity_PreservesOrder(t *testing.T) {
	t.Run("cli-severity-filter/AC-09", func(t *testing.T) {})
	// Filter must not re-sort; the surrounding pipeline expects
	// stable ordering for deterministic output.
	rules := []*api.Rule{
		{ID: "z", Severity: "high"},
		{ID: "a", Severity: "high"},
		{ID: "m", Severity: "low"},
	}
	got := filterRulesBySeverity(rules, []string{"high"})
	if len(got) != 2 || got[0].ID != "z" || got[1].ID != "a" {
		t.Errorf("expected [z,a] (input order); got %v", got)
	}
}

// @spec cli-severity-filter
// @ac AC-10
func TestFilterRulesBySeverity_RuleSeverityCaseInsensitive(t *testing.T) {
	t.Run("cli-severity-filter/AC-10", func(t *testing.T) {})
	// Rules in the corpus may have severity in any case; the filter
	// should match regardless.
	rules := []*api.Rule{
		{ID: "a", Severity: "Critical"},
		{ID: "b", Severity: "HIGH"},
	}
	got := filterRulesBySeverity(rules, []string{"critical", "high"})
	if len(got) != 2 {
		t.Errorf("case-insensitive match expected; got %d", len(got))
	}
}
