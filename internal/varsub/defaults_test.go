// Tests for the Phase 3.5 defaults.yml loader.
package varsub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaults_EmptyConfigDir(t *testing.T) {
	got, err := LoadDefaults("")
	if err != nil {
		t.Fatalf("empty dir: %v", err)
	}
	if got != nil {
		t.Errorf("empty dir should return nil; got %v", got)
	}
}

func TestLoadDefaults_NoDefaultsFile(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadDefaults(dir)
	if err != nil {
		t.Fatalf("missing defaults.yml: %v", err)
	}
	if got != nil {
		t.Errorf("missing file should return nil; got %v", got)
	}
}

func TestLoadDefaults_BasicScalars(t *testing.T) {
	dir := t.TempDir()
	body := `variables:
  pam_faillock_deny: 3
  pam_pwquality_minlen: 15
  banner_file: "/etc/issue"
  enable_thing: true
  ratio: 0.5
`
	if err := os.WriteFile(filepath.Join(dir, "defaults.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDefaults(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := map[string]string{
		"pam_faillock_deny":   "3",
		"pam_pwquality_minlen": "15",
		"banner_file":          "/etc/issue",
		"enable_thing":         "true",
		"ratio":                "0.5",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q: got %q, want %q", k, got[k], v)
		}
	}
}

func TestLoadDefaults_NilValueRejected(t *testing.T) {
	dir := t.TempDir()
	body := `variables:
  empty_var:
`
	if err := os.WriteFile(filepath.Join(dir, "defaults.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDefaults(dir)
	if err == nil {
		t.Fatal("nil value should reject")
	}
	if !strings.Contains(err.Error(), "nil/empty value") {
		t.Errorf("error should name the issue: %v", err)
	}
}

func TestLoadDefaults_NonScalarRejected(t *testing.T) {
	dir := t.TempDir()
	body := `variables:
  weird:
    nested: thing
`
	if err := os.WriteFile(filepath.Join(dir, "defaults.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDefaults(dir)
	if err == nil {
		t.Fatal("non-scalar should reject")
	}
	if !strings.Contains(err.Error(), "nested map values not allowed") {
		t.Errorf("error should name the issue (nested map): %v", err)
	}
}

func TestLoadDefaults_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "defaults.yml"), []byte("not: valid: yaml: stuff:"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDefaults(dir)
	if err == nil {
		t.Fatal("malformed should reject")
	}
}

// TestLoadDefaults_InvalidVarName rejects a defaults.yml entry
// whose key can't be referenced by the substitution engine
// (templateRe vocabulary [A-Za-z][A-Za-z0-9_]*). Catches typos
// like dashes-in-names or digit-leading keys.
func TestLoadDefaults_InvalidVarName(t *testing.T) {
	dir := t.TempDir()
	body := `variables:
  has-dash: 5
`
	if err := os.WriteFile(filepath.Join(dir, "defaults.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDefaults(dir)
	if err == nil {
		t.Fatal("invalid key should reject")
	}
	if !strings.Contains(err.Error(), "[A-Za-z]") {
		t.Errorf("error should explain valid pattern: %v", err)
	}
	if !strings.Contains(err.Error(), "has-dash") {
		t.Errorf("error should name offending key: %v", err)
	}
}

func TestLoadDefaults_NoVariablesBlock(t *testing.T) {
	// A defaults.yml with an unrelated top-level key (frameworks:,
	// for forward compat with Phase 3.6) should load empty
	// variables — not error.
	dir := t.TempDir()
	body := `frameworks:
  cis-rhel9: {}
`
	if err := os.WriteFile(filepath.Join(dir, "defaults.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDefaults(dir)
	if err != nil {
		t.Fatalf("frameworks-only: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty variables; got %v", got)
	}
}
