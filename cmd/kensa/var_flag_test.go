// Tests for the C-034 --var/-x flag's KEY=VALUE parser.
package main

import (
	"strings"
	"testing"
)

func TestResolveVarOverrides_Empty(t *testing.T) {
	got, err := resolveVarOverrides(nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil; got %v", got)
	}
}

func TestResolveVarOverrides_WellFormed(t *testing.T) {
	got, err := resolveVarOverrides([]string{"pam_faillock_deny=5"})
	if err != nil {
		t.Fatalf("well-formed: %v", err)
	}
	if got["pam_faillock_deny"] != "5" {
		t.Errorf("got %v", got)
	}
}

func TestResolveVarOverrides_Multiple(t *testing.T) {
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

func TestResolveVarOverrides_DuplicateKey_LastWins(t *testing.T) {
	got, err := resolveVarOverrides([]string{"x=1", "x=2"})
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	if got["x"] != "2" {
		t.Errorf("expected last-wins; got %v", got)
	}
}

func TestResolveVarOverrides_EmptyValue(t *testing.T) {
	// VALUE may be empty; the operator might want to substitute "".
	got, err := resolveVarOverrides([]string{"banner="})
	if err != nil {
		t.Fatalf("empty value: %v", err)
	}
	if got["banner"] != "" {
		t.Errorf("expected empty; got %q", got["banner"])
	}
}

func TestResolveVarOverrides_MissingEquals(t *testing.T) {
	_, err := resolveVarOverrides([]string{"bare_key"})
	if err == nil {
		t.Fatal("missing '=' should reject")
	}
	if !strings.Contains(err.Error(), "missing '='") {
		t.Errorf("error should mention missing '=': %v", err)
	}
}

func TestResolveVarOverrides_EmptyKey(t *testing.T) {
	_, err := resolveVarOverrides([]string{"=value"})
	if err == nil {
		t.Fatal("empty KEY should reject")
	}
	if !strings.Contains(err.Error(), "empty KEY") {
		t.Errorf("error should mention empty KEY: %v", err)
	}
}

func TestResolveVarOverrides_InvalidKey(t *testing.T) {
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

func TestValidVarName(t *testing.T) {
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
