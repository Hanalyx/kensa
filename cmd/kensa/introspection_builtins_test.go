// Tests for the corpus-introspection commands' variable resolution.
//
// `kensa list frameworks`, the generic `kensa coverage --framework` path and
// `kensa info` read the whole corpus and never contact a host. They must load
// it with the same embedded built-in defaults the scan path uses, or every
// rule carrying a `{{ name }}` template silently leaves the corpus and the
// counts they publish are low.
package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// builtinFixtureVar is a variable the binary ships a default for. The fixture
// depends on that: the templated rule must be loadable with no operator
// configuration at all, which is the whole property under test.
const builtinFixtureVar = "pam_faillock_deny"

// makeBuiltinTemplateCorpus writes the two-rule corpus the acceptance criteria
// name. Both documents are identical except for the id, the CIS RHEL 9 control
// and the templated rule's check.expected, so a count difference between them
// can only come from the template.
func makeBuiltinTemplateCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rule := func(id, section, expected string) string {
		return "id: " + id + `
title: Test rule
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
      expected: ` + expected + `

references:
  cis:
    rhel9:
      section: "` + section + `"
`
	}
	files := map[string]string{
		"plain-rule.yml":     rule("plain-rule", "5.1.1", `"0"`),
		"templated-rule.yml": rule("templated-rule", "5.1.2", `"{{ `+builtinFixtureVar+` }}"`),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// runIntrospection invokes the real CLI dispatcher and returns its exit code
// with both streams. Asserting on the dispatcher rather than on a helper is
// deliberate: the defect was missing wiring between the command and the
// variable tiers, so a test that called the loader directly would pass while
// the command stayed broken.
func runIntrospection(t *testing.T, argv ...string) (code int, stdout, stderr string) {
	t.Helper()
	// Ambient configuration must not reach a corpus-wide read model. Clearing
	// these here also keeps the result identical on a developer machine that
	// happens to have a config dir and on CI, which has none.
	t.Setenv("KENSA_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr

	outC := make(chan string)
	errC := make(chan string)
	go func() { outC <- readAll(rOut) }()
	go func() { errC <- readAll(rErr) }()

	code = runCLI(argv)

	_ = wOut.Close()
	_ = wErr.Close()
	stdout, stderr = <-outC, <-errC
	os.Stdout, os.Stderr = oldOut, oldErr
	return code, stdout, stderr
}

func readAll(f *os.File) string {
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

// assertNoUndefinedVariableLoss fails when stderr shows the loader dropped a
// rule, and names the rule so a regression says which one left the corpus.
func assertNoUndefinedVariableLoss(t *testing.T, stderr string) {
	t.Helper()
	for _, banned := range []string{"undefined variables", "templated-rule"} {
		if strings.Contains(stderr, banned) {
			t.Errorf("stderr must not report a dropped rule; found %q in:\n%s", banned, stderr)
		}
	}
}

// repoRulesDir locates the shipped corpus from the test's working directory
// (cmd/kensa), so AC-05 runs against the real rules rather than a fixture.
func repoRulesDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatalf("resolve rules dir: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("shipped corpus not present at %s: %v", dir, err)
	}
	return dir
}

// walk enumerates rule YAML independently of the loader under test, so the
// expected count does not come from the same code path being verified.
func walk(t *testing.T, dir string, out *[]string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".yml") {
			*out = append(*out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

// TestListFrameworks_CountsBuiltInTemplatedRule locks AC-01.
//
// Pre-fix this reports one framework row with controls=1 rules=1, because
// templated-rule fails substitution and is skipped. Both rules cite the same
// framework and different controls, so the assertion cannot be satisfied by a
// different rule supplying the count.
// @spec cli-introspection-builtins
// @ac AC-01
func TestListFrameworks_CountsBuiltInTemplatedRule(t *testing.T) {
	t.Run("cli-introspection-builtins/AC-01", func(t *testing.T) {})
	dir := makeBuiltinTemplateCorpus(t)
	code, stdout, stderr := runIntrospection(t,
		"list", "frameworks", "--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
	}
	var got struct {
		Frameworks []struct {
			FrameworkID string `json:"framework_id"`
			Controls    int    `json:"controls"`
			Rules       int    `json:"rules"`
		} `json:"frameworks"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode stdout: %v\n%s", err, stdout)
	}
	if len(got.Frameworks) != 1 {
		t.Fatalf("want exactly 1 framework row, got %d:\n%s", len(got.Frameworks), stdout)
	}
	f := got.Frameworks[0]
	if f.FrameworkID != "cis_rhel9" || f.Controls != 2 || f.Rules != 2 {
		t.Errorf("got %s controls=%d rules=%d; want cis_rhel9 controls=2 rules=2",
			f.FrameworkID, f.Controls, f.Rules)
	}
	assertNoUndefinedVariableLoss(t, stderr)
}

// TestCoverage_ScansBuiltInTemplatedRule locks AC-02 on the generic
// rule-loader route (a framework with no objective catalog).
//
// Pre-fix: rules_scanned=1, rules_matching=1, controls_mapped=1. Asserting the
// per-control rule lists proves the second control came from templated-rule
// specifically, not from a duplicate mapping on plain-rule.
// @spec cli-introspection-builtins
// @ac AC-02
func TestCoverage_ScansBuiltInTemplatedRule(t *testing.T) {
	t.Run("cli-introspection-builtins/AC-02", func(t *testing.T) {})
	dir := makeBuiltinTemplateCorpus(t)
	code, stdout, stderr := runIntrospection(t,
		"coverage", "--framework", "cis_rhel9", "--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
	}
	var got struct {
		Framework      string `json:"framework"`
		RulesScanned   int    `json:"rules_scanned"`
		RulesMatching  int    `json:"rules_matching"`
		ControlsMapped int    `json:"controls_mapped"`
		Controls       []struct {
			ControlID string   `json:"control_id"`
			RuleCount int      `json:"rule_count"`
			Rules     []string `json:"rules"`
		} `json:"controls"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode stdout: %v\n%s", err, stdout)
	}
	if got.RulesScanned != 2 || got.RulesMatching != 2 || got.ControlsMapped != 2 {
		t.Errorf("scanned=%d matching=%d mapped=%d; want 2/2/2",
			got.RulesScanned, got.RulesMatching, got.ControlsMapped)
	}
	want := map[string]string{"5.1.1": "plain-rule", "5.1.2": "templated-rule"}
	for _, c := range got.Controls {
		exp, ok := want[c.ControlID]
		if !ok {
			t.Errorf("unexpected control %q", c.ControlID)
			continue
		}
		if c.RuleCount != 1 || len(c.Rules) != 1 || c.Rules[0] != exp {
			t.Errorf("control %s: got count=%d rules=%v; want 1 [%s]",
				c.ControlID, c.RuleCount, c.Rules, exp)
		}
		delete(want, c.ControlID)
	}
	for id, r := range want {
		t.Errorf("control %s (rule %s) missing from the report", id, r)
	}
	assertNoUndefinedVariableLoss(t, stderr)
}

// TestInfo_ResolvesBuiltInTemplatedRule locks AC-03.
//
// Pre-fix: exit 1 and "rule not found", because the rule never entered the
// loaded set. The framework_refs assertion proves the whole rule was parsed
// with its references intact, not merely that an id matched.
// @spec cli-introspection-builtins
// @ac AC-03
func TestInfo_ResolvesBuiltInTemplatedRule(t *testing.T) {
	t.Run("cli-introspection-builtins/AC-03", func(t *testing.T) {})
	dir := makeBuiltinTemplateCorpus(t)
	code, stdout, stderr := runIntrospection(t,
		"info", "--rule", "templated-rule", "--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
	}
	if strings.Contains(stderr, "rule not found") {
		t.Errorf("info must resolve the templated rule; stderr:\n%s", stderr)
	}
	// api.FrameworkRef carries no JSON tags, so its members serialize under
	// their Go field names while the rest of the document is snake_case. That
	// is the shipped shape at this base commit and this change must preserve
	// it, so the assertion matches what the binary actually emits.
	var got struct {
		ID            string `json:"id"`
		FrameworkRefs []struct {
			FrameworkID string
			ControlID   string
		} `json:"framework_refs"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode stdout: %v\n%s", err, stdout)
	}
	if got.ID != "templated-rule" {
		t.Errorf("id = %q, want templated-rule", got.ID)
	}
	var found bool
	for _, r := range got.FrameworkRefs {
		if r.FrameworkID == "cis_rhel9" && r.ControlID == "5.1.2" {
			found = true
		}
	}
	if !found {
		t.Errorf("framework_refs missing cis_rhel9/5.1.2; got %+v", got.FrameworkRefs)
	}
	assertNoUndefinedVariableLoss(t, stderr)
}

// TestIntrospection_IgnoresAmbientConfig locks AC-04: nine runs, three
// commands against three ambient-configuration cases, each pointing at a
// directory holding an unparseable defaults.yml.
//
// A corpus-wide read model that consulted operator configuration would either
// fail on the malformed file or return different output per machine. Comparing
// against the same command with all three variables unset is what proves the
// resolution floor is embedded-only.
// @spec cli-introspection-builtins
// @ac AC-04
func TestIntrospection_IgnoresAmbientConfig(t *testing.T) {
	t.Run("cli-introspection-builtins/AC-04", func(t *testing.T) {})
	dir := makeBuiltinTemplateCorpus(t)

	commands := [][]string{
		{"list", "frameworks", "--rules-dir", dir, "--format", "json"},
		{"coverage", "--framework", "cis_rhel9", "--rules-dir", dir, "--format", "json"},
		{"info", "--rule", "templated-rule", "--rules-dir", dir, "--format", "json"},
	}

	// Baseline: every ambient candidate unset.
	baseline := make([]string, len(commands))
	for i, argv := range commands {
		code, stdout, stderr := runIntrospection(t, argv...)
		if code != 0 {
			t.Fatalf("baseline %v: exit %d; stderr:\n%s", argv, code, stderr)
		}
		baseline[i] = stdout
	}

	// A config dir whose defaults.yml cannot parse. If any command reads it,
	// the run fails or its output changes.
	poisoned := func(t *testing.T, nested string) string {
		t.Helper()
		root := t.TempDir()
		cfg := filepath.Join(root, nested)
		if err := os.MkdirAll(cfg, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", cfg, err)
		}
		body := []byte("variables:\n  : [unclosed\n    bad: : :\n")
		if err := os.WriteFile(filepath.Join(cfg, "defaults.yml"), body, 0o644); err != nil {
			t.Fatalf("write defaults.yml: %v", err)
		}
		return root
	}

	runs := 0
	for _, envCase := range []struct {
		name   string
		nested string
		apply  func(t *testing.T, root string)
	}{
		{"KENSA_CONFIG_DIR", ".", func(t *testing.T, root string) {
			t.Setenv("KENSA_CONFIG_DIR", root)
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("HOME", t.TempDir())
		}},
		{"XDG_CONFIG_HOME", "kensa", func(t *testing.T, root string) {
			t.Setenv("XDG_CONFIG_HOME", root)
			t.Setenv("KENSA_CONFIG_DIR", "")
			t.Setenv("HOME", t.TempDir())
		}},
		{"HOME", ".config/kensa", func(t *testing.T, root string) {
			t.Setenv("HOME", root)
			t.Setenv("KENSA_CONFIG_DIR", "")
			t.Setenv("XDG_CONFIG_HOME", "")
		}},
	} {
		for i, argv := range commands {
			t.Run(envCase.name+"/"+argv[0], func(t *testing.T) {
				root := poisoned(t, envCase.nested)
				envCase.apply(t, root)

				oldOut, oldErr := os.Stdout, os.Stderr
				rOut, wOut, _ := os.Pipe()
				rErr, wErr, _ := os.Pipe()
				os.Stdout, os.Stderr = wOut, wErr
				outC := make(chan string)
				errC := make(chan string)
				go func() { outC <- readAll(rOut) }()
				go func() { errC <- readAll(rErr) }()
				code := runCLI(argv)
				_ = wOut.Close()
				_ = wErr.Close()
				stdout, stderr := <-outC, <-errC
				os.Stdout, os.Stderr = oldOut, oldErr

				if code != 0 {
					t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
				}
				if stdout != baseline[i] {
					t.Errorf("stdout changed under %s; ambient config reached a corpus-wide read model\n got: %s\nwant: %s",
						envCase.name, stdout, baseline[i])
				}
				for _, banned := range []string{"defaults.yml", "parse defaults"} {
					if strings.Contains(stderr, banned) {
						t.Errorf("stderr mentions operator config (%q):\n%s", banned, stderr)
					}
				}
			})
			runs++
		}
	}
	if runs != 9 {
		t.Errorf("ran %d command/environment combinations, want 9", runs)
	}
}

// TestIntrospection_ShippedCorpusHasNoUndefinedVariableLoss locks AC-05
// against the real corpus rather than a fixture, because the defect was only
// visible at that scale and the fixture cannot prove the shipped defaults
// cover every shipped template.
// @spec cli-introspection-builtins
// @ac AC-05
func TestIntrospection_ShippedCorpusHasNoUndefinedVariableLoss(t *testing.T) {
	t.Run("cli-introspection-builtins/AC-05", func(t *testing.T) {})
	dir := repoRulesDir(t)

	// Independently enumerate the corpus from the filesystem, so the assertion
	// has a denominator the command under test did not produce.
	var onDisk []string
	walk(t, dir, &onDisk)
	if len(onDisk) == 0 {
		t.Fatalf("no rule YAML found under %s", dir)
	}

	code, stdout, stderr := runIntrospection(t,
		"list", "frameworks", "--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
	}
	if strings.Contains(stderr, "undefined variables") {
		t.Errorf("shipped corpus still loses rules to undefined variables:\n%s", stderr)
	}

	var lf struct {
		Frameworks []struct {
			FrameworkID string `json:"framework_id"`
			Rules       int    `json:"rules"`
		} `json:"frameworks"`
	}
	if err := json.Unmarshal([]byte(stdout), &lf); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(lf.Frameworks) == 0 {
		t.Fatal("no frameworks reported for the shipped corpus")
	}

	// coverage must scan every rule on disk.
	code, stdout, stderr = runIntrospection(t,
		"coverage", "--framework", "cis_rhel9", "--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("coverage exit = %d; stderr:\n%s", code, stderr)
	}
	var cov struct {
		RulesScanned int `json:"rules_scanned"`
	}
	if err := json.Unmarshal([]byte(stdout), &cov); err != nil {
		t.Fatalf("decode coverage: %v", err)
	}
	if cov.RulesScanned != len(onDisk) {
		t.Errorf("coverage scanned %d rules; the corpus holds %d", cov.RulesScanned, len(onDisk))
	}

	// info must resolve a rule that only loads with an embedded default.
	code, _, stderr = runIntrospection(t,
		"info", "--rule", "pam-faillock-deny", "--rules-dir", dir, "--format", "json")
	if code != 0 || strings.Contains(stderr, "rule not found") {
		t.Errorf("info could not resolve pam-faillock-deny: exit=%d stderr=%s", code, stderr)
	}
}

// TestIntrospection_PublicJSONKeysUnchanged locks AC-06. The fix changes which
// rules load; it must not change the documented shape consumers parse.
// @spec cli-introspection-builtins
// @ac AC-06
func TestIntrospection_PublicJSONKeysUnchanged(t *testing.T) {
	t.Run("cli-introspection-builtins/AC-06", func(t *testing.T) {})
	dir := makeBuiltinTemplateCorpus(t)

	keys := func(t *testing.T, raw string) []string {
		t.Helper()
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("decode: %v\n%s", err, raw)
		}
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	eq := func(t *testing.T, label string, got, want []string) {
		t.Helper()
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s keys = %v, want %v", label, got, want)
		}
	}

	_, stdout, _ := runIntrospection(t, "list", "frameworks", "--rules-dir", dir, "--format", "json")
	eq(t, "list_frameworks_top", keys(t, stdout), []string{"frameworks"})
	var lf struct {
		Frameworks []map[string]json.RawMessage `json:"frameworks"`
	}
	if err := json.Unmarshal([]byte(stdout), &lf); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(lf.Frameworks) == 0 {
		t.Fatal("no framework rows")
	}
	item := make([]string, 0)
	for k := range lf.Frameworks[0] {
		item = append(item, k)
	}
	sort.Strings(item)
	eq(t, "list_frameworks_item", item, []string{"framework_id", "controls", "rules"})

	_, stdout, _ = runIntrospection(t, "coverage", "--framework", "cis_rhel9",
		"--rules-dir", dir, "--format", "json")
	eq(t, "coverage_top", keys(t, stdout),
		[]string{"framework", "rules_scanned", "rules_matching", "controls_mapped", "controls"})
	var cov struct {
		Controls []map[string]json.RawMessage `json:"controls"`
	}
	if err := json.Unmarshal([]byte(stdout), &cov); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cov.Controls) == 0 {
		t.Fatal("no control rows")
	}
	ci := make([]string, 0)
	for k := range cov.Controls[0] {
		ci = append(ci, k)
	}
	sort.Strings(ci)
	eq(t, "coverage_control_item", ci, []string{"control_id", "rule_count", "rules"})

	_, stdout, _ = runIntrospection(t, "info", "--rule", "templated-rule",
		"--rules-dir", dir, "--format", "json")
	eq(t, "info_rule", keys(t, stdout),
		[]string{"id", "title", "description", "severity", "category", "tags", "platforms", "framework_refs"})
}
