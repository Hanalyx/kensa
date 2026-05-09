// Tests for the C-037 --rule single-file flag and the additive
// loader semantics.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMinimalRule writes a tiny but valid rule YAML to dir/name
// and returns its full path.
func writeMinimalRule(t *testing.T, dir, name, ruleID string) string {
	t.Helper()
	body := `id: ` + ruleID + `
title: Test rule for C-037 loader semantics
description: minimal rule
rationale: minimal rule
severity: low
category: system
tags: [test]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      method: command
      run: "true"
      expected_exit: 0
`
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoadRulesFromDirOrFiles_FilesOnly(t *testing.T) {
	dir := t.TempDir()
	a := writeMinimalRule(t, dir, "a.yml", "rule-a")
	b := writeMinimalRule(t, dir, "b.yml", "rule-b")

	rules, err := loadRulesFromDirOrFiles("", []string{a, b}, nil)
	if err != nil {
		t.Fatalf("files-only: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules; got %d", len(rules))
	}
}

func TestLoadRulesFromDirOrFiles_DirOnly(t *testing.T) {
	dir := t.TempDir()
	writeMinimalRule(t, dir, "a.yml", "rule-a")
	writeMinimalRule(t, dir, "b.yml", "rule-b")

	rules, err := loadRulesFromDirOrFiles(dir, nil, nil)
	if err != nil {
		t.Fatalf("dir-only: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules; got %d", len(rules))
	}
}

// TestLoadRulesFromDirOrFiles_DirAndFiles_Additive locks the C-037
// behavior change: --rules-dir and --rule (or positional) compose
// additively, not mutually-exclusively.
func TestLoadRulesFromDirOrFiles_DirAndFiles_Additive(t *testing.T) {
	dirRoot := t.TempDir()
	corpus := filepath.Join(dirRoot, "corpus")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMinimalRule(t, corpus, "a.yml", "rule-a")
	writeMinimalRule(t, corpus, "b.yml", "rule-b")
	extra := writeMinimalRule(t, dirRoot, "extra.yml", "rule-extra")

	rules, err := loadRulesFromDirOrFiles(corpus, []string{extra}, nil)
	if err != nil {
		t.Fatalf("additive: %v", err)
	}
	if len(rules) != 3 {
		t.Errorf("expected dir(2) + file(1) = 3; got %d", len(rules))
	}
	// Verify the explicit file landed in the result.
	found := false
	for _, r := range rules {
		if r.ID == "rule-extra" {
			found = true
			break
		}
	}
	if !found {
		t.Error("extra file should have loaded; not present in result")
	}
}

func TestLoadRulesFromDirOrFiles_BothEmpty(t *testing.T) {
	_, err := loadRulesFromDirOrFiles("", nil, nil)
	if err == nil {
		t.Fatal("expected usage error when both empty")
	}
	if !strings.Contains(err.Error(), "rule YAML file or --rules-dir") {
		t.Errorf("error should mention required input; got %v", err)
	}
}

// TestLoadRulesFromDirOrFiles_StrictOnExplicitFile locks the
// strict-vs-skip-invalid distinction. Files named explicitly via
// --rule (or positional) MUST surface parse errors; only the
// dir-walk path skips invalid YAMLs with a warning.
func TestLoadRulesFromDirOrFiles_StrictOnExplicitFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "broken.yml")
	if err := os.WriteFile(bad, []byte("not: valid: yaml: stuff:"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadRulesFromDirOrFiles("", []string{bad}, nil)
	if err == nil {
		t.Fatal("explicit broken file should fail to load (strict)")
	}
}

func TestLoadRulesFromDirOrFiles_DirSkipsInvalid(t *testing.T) {
	dir := t.TempDir()
	good := writeMinimalRule(t, dir, "good.yml", "rule-good")
	if err := os.WriteFile(filepath.Join(dir, "broken.yml"), []byte("not: valid: yaml: stuff:"), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRulesFromDirOrFiles(dir, nil, nil)
	if err != nil {
		t.Fatalf("dir walk should skip the broken file, not error; got %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule (good); got %d", len(rules))
	}
	if rules[0].ID != "rule-good" {
		t.Errorf("loaded rule should be the good one; got %s", rules[0].ID)
	}
	_ = good
}

// TestLoadRulesFromDirOrFiles_NonExistentExplicitFile locks that
// a non-existent --rule path produces an error rather than being
// silently skipped (strict-loading discipline for explicit files).
func TestLoadRulesFromDirOrFiles_NonExistentExplicitFile(t *testing.T) {
	_, err := loadRulesFromDirOrFiles("", []string{"/no/such/file.yml"}, nil)
	if err == nil {
		t.Fatal("non-existent file should error under strict loader")
	}
}

// TestLoadRulesFromDirOrFiles_DuplicatePaths_BothLoaded documents
// that a rule named both via --rules-dir (walked in) and via
// --rule (explicit file) loads twice. Filter consumers downstream
// (rule.Resolve) detect duplicate IDs and surface conflicts; the
// loader doesn't dedup. Test locks current behavior so a future
// dedup change is a deliberate decision, not accidental drift.
func TestLoadRulesFromDirOrFiles_DuplicatePaths_BothLoaded(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "corpus")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		t.Fatal(err)
	}
	dup := writeMinimalRule(t, corpus, "rule.yml", "dup-id")

	rules, err := loadRulesFromDirOrFiles(corpus, []string{dup}, nil)
	if err != nil {
		t.Fatalf("dup paths: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules (loader does not dedup; downstream resolve flags conflict); got %d", len(rules))
	}
}

// TestConcatPaths verifies the helper combines two slices into a
// fresh allocation without mutating either input.
func TestConcatPaths(t *testing.T) {
	a := []string{"a", "b"}
	b := []string{"c"}
	got := concatPaths(a, b)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("got %v; want [a b c]", got)
	}
	// Mutate the returned slice; inputs must remain unchanged.
	got[0] = "x"
	if a[0] != "a" {
		t.Error("concatPaths mutated input slice a")
	}
	// Empty inputs.
	if got := concatPaths(nil, nil); len(got) != 0 {
		t.Errorf("nil+nil should produce empty; got %v", got)
	}
}
