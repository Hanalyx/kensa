// Tests for the Phase 3.7 ruleLoadFilterSpec helper used by
// inventory mode to re-load the corpus per host with that
// host's full 5-tier resolved variables.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa-go/internal/varsub"
)

// pipelineRule writes a templated rule whose check.expected
// references {{ pam_faillock_deny }} so we can verify that
// LoadAndFilter passes vars through and the substitution
// produces the expected concrete text.
func pipelineRule(t *testing.T, dir, name, ruleID string) string {
	t.Helper()
	body := `id: ` + ruleID + `
title: Phase 3.7 pipeline test rule
description: pipeline
rationale: pipeline
severity: high
category: access-control
tags: [pipeline]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      method: config_value
      path: "/etc/security/faillock.conf"
      key: "deny"
      expected: "{{ pam_faillock_deny }}"
      comparator: "<="
`
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRuleLoadFilterSpec_LoadAndFilter_Basic(t *testing.T) {
	dir := t.TempDir()
	pipelineRule(t, dir, "a.yml", "rule-a")

	spec := ruleLoadFilterSpec{
		rulesDir:  dir,
		rulePaths: nil,
	}
	rules, err := spec.LoadAndFilter(varsub.Variables{"pam_faillock_deny": "5"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "rule-a" {
		t.Errorf("got %s; want rule-a", rules[0].ID)
	}
	// Confirm substitution produced the concrete text. The
	// Check.Expected field is method-specific and decoded into
	// Params (not a top-level struct field). The config_value
	// check's "expected" value lands at Params["expected"].
	got := rules[0].Implementations[0].Check.Params["expected"]
	if got != "5" {
		t.Errorf("substitution should produce '5'; got %v", got)
	}
}

func TestRuleLoadFilterSpec_LoadAndFilter_DifferentVarsPerCall(t *testing.T) {
	// The Phase 3.7 contract: calling LoadAndFilter with
	// different vars produces rules with different
	// substituted values. This is the load-bearing semantic
	// for per-host inventory re-load.
	dir := t.TempDir()
	pipelineRule(t, dir, "a.yml", "rule-a")

	spec := ruleLoadFilterSpec{rulesDir: dir}

	rulesA, err := spec.LoadAndFilter(varsub.Variables{"pam_faillock_deny": "3"})
	if err != nil {
		t.Fatalf("load A: %v", err)
	}
	rulesB, err := spec.LoadAndFilter(varsub.Variables{"pam_faillock_deny": "7"})
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	if rulesA[0].Implementations[0].Check.Params["expected"] != "3" {
		t.Errorf("A: got %v; want 3", rulesA[0].Implementations[0].Check.Params["expected"])
	}
	if rulesB[0].Implementations[0].Check.Params["expected"] != "7" {
		t.Errorf("B: got %v; want 7", rulesB[0].Implementations[0].Check.Params["expected"])
	}
	// Confirm rule IDs are equal (filter chain doesn't
	// change which rules are in scope, just their values).
	if rulesA[0].ID != rulesB[0].ID {
		t.Errorf("rule IDs should match across var changes")
	}
}

func TestRuleLoadFilterSpec_FilterChain(t *testing.T) {
	dir := t.TempDir()
	// Two rules: one critical, one low.
	pipelineRule(t, dir, "crit.yml", "crit-rule")
	body := `id: low-rule
title: low
description: low
rationale: low
severity: low
category: access-control
tags: [pipeline]

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
	if err := os.WriteFile(filepath.Join(dir, "low.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Set the templated rule's severity to critical.
	patched := `id: crit-rule
title: critical pipeline
description: pipeline
rationale: pipeline
severity: critical
category: access-control
tags: [pipeline]

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
	if err := os.WriteFile(filepath.Join(dir, "crit.yml"), []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}

	spec := ruleLoadFilterSpec{
		rulesDir:   dir,
		severities: []string{"critical"}, // filter to critical only
	}
	rules, err := spec.LoadAndFilter(nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "crit-rule" {
		t.Errorf("severity filter should keep only critical; got %d rules", len(rules))
	}
}

func TestRuleLoadFilterSpec_EmptyRules(t *testing.T) {
	dir := t.TempDir() // empty
	spec := ruleLoadFilterSpec{rulesDir: dir}
	_, err := spec.LoadAndFilter(nil)
	if err == nil {
		t.Fatal("empty corpus should error")
	}
}
