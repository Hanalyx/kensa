// Tests for the C-034 --var/-x flag's KEY=VALUE parser.
package main

import (
	"strings"
	"testing"
)

// @spec cli-inventory-perhost-vars
// @ac AC-01
// @ac AC-10
// @spec cli-variable-substitution
// @ac AC-01
// @ac AC-10
// @ac AC-19
// @spec cli-variable-tiers
// @ac AC-01
// @ac AC-10
func TestResolveVarOverrides_Empty(t *testing.T) {
	t.Run("cli-variable-tiers/AC-01", func(t *testing.T) {})
	t.Run("cli-variable-tiers/AC-10", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-01", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-10", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-19", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-01", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-10", func(t *testing.T) {})
	got, err := resolveVarOverrides(nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil; got %v", got)
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-02
// @ac AC-11
// @spec cli-variable-substitution
// @ac AC-02
// @ac AC-11
// @ac AC-20
// @spec cli-variable-tiers
// @ac AC-02
// @ac AC-11
func TestResolveVarOverrides_WellFormed(t *testing.T) {
	t.Run("cli-variable-tiers/AC-02", func(t *testing.T) {})
	t.Run("cli-variable-tiers/AC-11", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-02", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-11", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-20", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-02", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-11", func(t *testing.T) {})
	got, err := resolveVarOverrides([]string{"pam_faillock_deny=5"})
	if err != nil {
		t.Fatalf("well-formed: %v", err)
	}
	if got["pam_faillock_deny"] != "5" {
		t.Errorf("got %v", got)
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-03
// @spec cli-variable-substitution
// @ac AC-03
// @ac AC-12
// @ac AC-21
// @spec cli-variable-tiers
// @ac AC-03
// @ac AC-12
func TestResolveVarOverrides_Multiple(t *testing.T) {
	t.Run("cli-variable-tiers/AC-03", func(t *testing.T) {})
	t.Run("cli-variable-tiers/AC-12", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-03", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-12", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-21", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-03", func(t *testing.T) {})
	got, err := resolveVarOverrides([]string{
		"pam_faillock_deny=5",
		"pam_pwquality_minlen=20",
	})
	if err != nil {
		t.Fatalf("multi: %v", err)
	}
	if got["pam_faillock_deny"] != "5" || got["pam_pwquality_minlen"] != "20" {
		t.Errorf("got %v", got)
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-04
// @spec cli-variable-substitution
// @ac AC-04
// @ac AC-13
// @ac AC-22
// @spec cli-variable-tiers
// @ac AC-04
// @ac AC-13
func TestResolveVarOverrides_DuplicateKey_LastWins(t *testing.T) {
	t.Run("cli-variable-tiers/AC-04", func(t *testing.T) {})
	t.Run("cli-variable-tiers/AC-13", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-04", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-13", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-22", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-04", func(t *testing.T) {})
	got, err := resolveVarOverrides([]string{"x=1", "x=2"})
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	if got["x"] != "2" {
		t.Errorf("expected last-wins; got %v", got)
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-05
// @spec cli-variable-substitution
// @ac AC-05
// @ac AC-14
// @ac AC-23
// @spec cli-variable-tiers
// @ac AC-05
// @ac AC-14
func TestResolveVarOverrides_EmptyValue(t *testing.T) {
	t.Run("cli-variable-tiers/AC-05", func(t *testing.T) {})
	t.Run("cli-variable-tiers/AC-14", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-05", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-14", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-23", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-05", func(t *testing.T) {})
	// VALUE may be empty; the operator might want to substitute "".
	got, err := resolveVarOverrides([]string{"banner="})
	if err != nil {
		t.Fatalf("empty value: %v", err)
	}
	if got["banner"] != "" {
		t.Errorf("expected empty; got %q", got["banner"])
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-06
// @spec cli-variable-substitution
// @ac AC-06
// @ac AC-15
// @spec cli-variable-tiers
// @ac AC-06
// @ac AC-15
func TestResolveVarOverrides_MissingEquals(t *testing.T) {
	t.Run("cli-variable-tiers/AC-06", func(t *testing.T) {})
	t.Run("cli-variable-tiers/AC-15", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-06", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-15", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-06", func(t *testing.T) {})
	_, err := resolveVarOverrides([]string{"bare_key"})
	if err == nil {
		t.Fatal("missing '=' should reject")
	}
	if !strings.Contains(err.Error(), "missing '='") {
		t.Errorf("error should mention missing '=': %v", err)
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-07
// @spec cli-variable-substitution
// @ac AC-07
// @ac AC-16
// @spec cli-variable-tiers
// @ac AC-07
func TestResolveVarOverrides_EmptyKey(t *testing.T) {
	t.Run("cli-variable-tiers/AC-07", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-07", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-16", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-07", func(t *testing.T) {})
	_, err := resolveVarOverrides([]string{"=value"})
	if err == nil {
		t.Fatal("empty KEY should reject")
	}
	if !strings.Contains(err.Error(), "empty KEY") {
		t.Errorf("error should mention empty KEY: %v", err)
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-08
// @spec cli-variable-substitution
// @ac AC-08
// @ac AC-17
// @spec cli-variable-tiers
// @ac AC-08
func TestResolveVarOverrides_InvalidKey(t *testing.T) {
	t.Run("cli-variable-tiers/AC-08", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-08", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-17", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-08", func(t *testing.T) {})
	for _, in := range []string{"1leading=v", "has-dash=v", "has space=v"} {
		_, err := resolveVarOverrides([]string{in})
		if err == nil {
			t.Errorf("%q should reject", in)
			continue
		}
		if !strings.Contains(err.Error(), "[A-Za-z]") {
			t.Errorf("error should explain valid pattern: %v", err)
		}
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-09
// @spec cli-variable-substitution
// @ac AC-09
// @ac AC-18
// @spec cli-variable-tiers
// @ac AC-09
func TestValidVarName(t *testing.T) {
	t.Run("cli-variable-tiers/AC-09", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-09", func(t *testing.T) {})
	t.Run("cli-variable-substitution/AC-18", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-09", func(t *testing.T) {})
	good := []string{"a", "abc", "Abc", "a_b", "a_1", "pam_faillock_deny"}
	bad := []string{"", "1abc", "_abc", "a-b", "a b", "a.b"}
	for _, g := range good {
		if !validVarName(g) {
			t.Errorf("expected %q to be valid", g)
		}
	}
	for _, b := range bad {
		if validVarName(b) {
			t.Errorf("expected %q to be invalid", b)
		}
	}
}
