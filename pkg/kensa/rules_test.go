package kensa

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/varsub"
)

// writeRule writes a rule YAML under dir and returns its path.
func writeRule(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const plainRule = `id: plain-rule
severity: low
implementations:
  - default: true
    check:
      method: sysctl_value
      key: net.ipv4.ip_forward
      expected: "0"
`

// templatedRule uses pam_faillock_deny, which has an embedded
// built-in default ("3"), so it loads with nil vars.
const templatedRule = `id: templated-rule
severity: medium
implementations:
  - default: true
    check:
      method: sysctl_value
      key: net.ipv4.ip_forward
      expected: '{{ pam_faillock_deny }}'
`

// orphanVarRule references a variable with no built-in default.
const orphanVarRule = `id: orphan-var-rule
severity: low
implementations:
  - default: true
    check:
      method: sysctl_value
      key: net.ipv4.ip_forward
      expected: '{{ no_such_variable_xyz }}'
`

// TestLoadRules covers the public loader surface.
//
// @spec rule-public-loader
func TestLoadRules(t *testing.T) {
	// AC-01: dir walk (recursive, sorted), explicit paths, and the
	// no-source error.
	t.Run("rule-public-loader/AC-01", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-01
		dir := t.TempDir()
		writeRule(t, dir, "b.yml", strings.Replace(plainRule, "plain-rule", "rule-b", 1))
		writeRule(t, dir, "sub/a.yml", strings.Replace(plainRule, "plain-rule", "rule-a", 1))
		writeRule(t, dir, "ignored.yaml", plainRule) // not .yml — excluded

		rules, err := LoadRules(dir, nil, nil)
		if err != nil {
			t.Fatalf("LoadRules(dir): %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("want 2 rules from dir walk, got %d", len(rules))
		}
		// Sorted file order: b.yml < sub/a.yml lexically.
		if rules[0].ID != "rule-b" || rules[1].ID != "rule-a" {
			t.Errorf("want deterministic sorted order [rule-b rule-a], got [%s %s]", rules[0].ID, rules[1].ID)
		}

		// Explicit paths alone load exactly those files.
		p := writeRule(t, t.TempDir(), "one.yml", plainRule)
		rules, err = LoadRules("", []string{p}, nil)
		if err != nil {
			t.Fatalf("LoadRules(paths): %v", err)
		}
		if len(rules) != 1 || rules[0].ID != "plain-rule" {
			t.Errorf("want exactly [plain-rule], got %v", rules)
		}

		// Neither dir nor paths, and no default install path on the
		// test host's view: must error (the default-path fallback is
		// stat-gated; on hosts WITH kensa-rules installed this branch
		// loads the corpus instead, so only assert when absent).
		if _, statErr := os.Stat("/usr/share/kensa/rules"); os.IsNotExist(statErr) {
			if _, err := LoadRules("", nil, nil); err == nil {
				t.Error("want error with no dir, no paths, no installed corpus")
			}
		}
	})

	// AC-02: built-in defaults fill templates with nil vars; caller
	// override wins over the built-in default.
	t.Run("rule-public-loader/AC-02", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-02
		p := writeRule(t, t.TempDir(), "tpl.yml", templatedRule)

		rules, err := LoadRules("", []string{p}, nil)
		if err != nil {
			t.Fatalf("nil vars: %v", err)
		}
		got := rules[0].Implementations[0].Check.Params["expected"]
		if got != "3" { // embedded default pam_faillock_deny: 3
			t.Errorf("built-in default: want expected=%q, got %q", "3", got)
		}

		rules, err = LoadRules("", []string{p}, map[string]string{"pam_faillock_deny": "5"})
		if err != nil {
			t.Fatalf("override vars: %v", err)
		}
		got = rules[0].Implementations[0].Check.Params["expected"]
		if got != "5" {
			t.Errorf("caller override: want expected=%q, got %q", "5", got)
		}
	})

	// AC-03: strict load — one bad file fails the whole load with the
	// file named; an undefined variable surfaces ErrUndefined.
	t.Run("rule-public-loader/AC-03", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-03
		dir := t.TempDir()
		writeRule(t, dir, "good.yml", plainRule)
		bad := writeRule(t, dir, "broken.yml", "not: valid: yaml: [")

		_, err := LoadRules(dir, nil, nil)
		if err == nil {
			t.Fatal("want strict failure on unparseable file, got nil")
		}
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("error must name the offending file %q, got: %v", bad, err)
		}

		orphan := writeRule(t, t.TempDir(), "orphan.yml", orphanVarRule)
		_, err = LoadRules("", []string{orphan}, nil)
		if err == nil {
			t.Fatal("want failure on undefined variable, got nil")
		}
		if !errors.Is(err, varsub.ErrUndefined) {
			t.Errorf("want errors.Is(err, varsub.ErrUndefined), got: %v", err)
		}
		if !strings.Contains(err.Error(), "no_such_variable_xyz") {
			t.Errorf("error must name the undefined variable, got: %v", err)
		}
	})

	// AC-04: BuiltInVars returns a defensive copy.
	t.Run("rule-public-loader/AC-04", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-04
		vars1, err := BuiltInVars()
		if err != nil {
			t.Fatalf("BuiltInVars: %v", err)
		}
		orig := vars1["pam_faillock_deny"]
		if orig == "" {
			t.Fatal("expected pam_faillock_deny in built-in defaults")
		}
		vars1["pam_faillock_deny"] = "tampered"
		vars2, err := BuiltInVars()
		if err != nil {
			t.Fatalf("BuiltInVars (2nd): %v", err)
		}
		if vars2["pam_faillock_deny"] != orig {
			t.Errorf("mutation leaked: want %q, got %q", orig, vars2["pam_faillock_deny"])
		}
		// And LoadRules substitution is unaffected by the tamper.
		p := writeRule(t, t.TempDir(), "tpl.yml", templatedRule)
		rules, err := LoadRules("", []string{p}, nil)
		if err != nil {
			t.Fatalf("LoadRules after tamper: %v", err)
		}
		if got := rules[0].Implementations[0].Check.Params["expected"]; got != orig {
			t.Errorf("substitution affected by tampered copy: want %q, got %q", orig, got)
		}
	})

	// AC-05: RuleVariables maps variable → sorted rule IDs, templated
	// rules only.
	t.Run("rule-public-loader/AC-05", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-05
		dir := t.TempDir()
		writeRule(t, dir, "plain.yml", plainRule)
		writeRule(t, dir, "z.yml", strings.Replace(templatedRule, "templated-rule", "z-rule", 1))
		writeRule(t, dir, "a.yml", strings.Replace(templatedRule, "templated-rule", "a-rule", 1))

		rv, err := RuleVariables(dir)
		if err != nil {
			t.Fatalf("RuleVariables: %v", err)
		}
		if len(rv) != 1 {
			t.Fatalf("want exactly 1 variable, got %d: %v", len(rv), rv)
		}
		ids := rv["pam_faillock_deny"]
		if len(ids) != 2 || ids[0] != "a-rule" || ids[1] != "z-rule" {
			t.Errorf("want sorted [a-rule z-rule], got %v", ids)
		}
	})
}

// TestLoadRules_ProductionCorpus locks the headline guarantee: the
// shipped 618-rule corpus — including its templated rules — loads
// strictly with nil vars on built-in defaults alone, and every
// template variable the corpus uses has a built-in default.
//
// @spec rule-public-loader
func TestLoadRules_ProductionCorpus(t *testing.T) {
	t.Run("rule-public-loader/AC-02", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-02
		corpus := "../../rules"
		if _, err := os.Stat(corpus); err != nil {
			t.Skip("corpus not present in this checkout")
		}
		rules, err := LoadRules(corpus, nil, nil)
		if err != nil {
			t.Fatalf("production corpus must load strictly on built-in defaults: %v", err)
		}
		if len(rules) != 623 {
			t.Errorf("want 623 rules, got %d", len(rules))
		}
		rv, err := RuleVariables(corpus)
		if err != nil {
			t.Fatalf("RuleVariables(corpus): %v", err)
		}
		defaults, err := BuiltInVars()
		if err != nil {
			t.Fatal(err)
		}
		for v, ids := range rv {
			if _, ok := defaults[v]; !ok {
				t.Errorf("corpus variable %s (used by %v) has no built-in default", v, ids)
			}
		}
	})
}
