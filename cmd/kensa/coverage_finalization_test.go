// Tests for the finalized `coverage` / `mechanisms` command contract.
//
// `coverage` used to mean two unrelated things depending on whether
// --framework was present. It now always reports framework coverage, and
// `mechanisms` is the only name for the mechanism listing. These tests drive
// the real runCLI dispatcher, because the defect being prevented lived at the
// dispatch site rather than inside either command.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// twoControlCorpus writes two rules mapping to CIS RHEL 9 controls: one rule
// covering 1.1 and 1.2, another covering 1.1 only. That shape makes a control
// with two rules and a control with one distinguishable.
func twoControlCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rule := func(id string, sections ...string) string {
		body := "id: " + id + `
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

references:
  cis:
    rhel9:
`
		for _, s := range sections {
			body += `      - section: "` + s + `"` + "\n"
		}
		return body
	}
	// The CIS block accepts either a mapping or a list of mappings; a list is
	// what lets one rule carry two controls.
	files := map[string]string{
		"alpha-rule.yml": rule("alpha-rule", "1.1", "1.2"),
		"beta-rule.yml":  rule("beta-rule", "1.1"),
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	return dir
}

// runCov drives runCLI with a clean environment and returns all three results.
func runCov(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	t.Setenv("KENSA_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())
	return runCLIAll(t, argv...)
}

func runCLIAll(t *testing.T, argv ...string) (int, string, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	outC, errC := make(chan string), make(chan string)
	go func() { outC <- readAll(rOut) }()
	go func() { errC <- readAll(rErr) }()
	code := runCLI(argv)
	_ = wOut.Close()
	_ = wErr.Close()
	so, se := <-outC, <-errC
	os.Stdout, os.Stderr = oldOut, oldErr
	return code, so, se
}

// TestCoverage_MissingFrameworkFailsThroughDispatch locks AC-01.
//
// Bare coverage used to exit 0 and print the mechanism listing. It must now be
// a usage error, and must never fall back. All three results are compared so
// an exit 2 from an unrelated parse error cannot pass this.
// @spec cli-coverage-command-finalization
// @ac AC-01
func TestCoverage_MissingFrameworkFailsThroughDispatch(t *testing.T) {
	t.Run("cli-coverage-command-finalization/AC-01", func(t *testing.T) {})
	for name, argv := range map[string][]string{
		"bare":                     {"coverage"},
		"format_without_framework": {"coverage", "--format", "json"},
		"quiet_without_framework":  {"coverage", "--quiet"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := runCov(t, argv...)
			if code != 2 {
				t.Errorf("exit = %d, want 2", code)
			}
			if stdout != "" {
				t.Errorf("stdout must be empty; got:\n%s", stdout)
			}
			for _, want := range []string{"--framework", "required"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr missing %q; got:\n%s", want, stderr)
				}
			}
			for _, banned := range []string{"Registered mechanisms", "change meaning", "v0.2"} {
				if strings.Contains(stdout, banned) || strings.Contains(stderr, banned) {
					t.Errorf("output still carries %q", banned)
				}
			}
		})
	}
}

// TestCoverage_GenericReportUnchanged locks AC-03: the existing report shape
// and values are untouched by the dispatch change.
// @spec cli-coverage-command-finalization
// @ac AC-03
func TestCoverage_GenericReportUnchanged(t *testing.T) {
	t.Run("cli-coverage-command-finalization/AC-03", func(t *testing.T) {})
	dir := twoControlCorpus(t)
	code, stdout, stderr := runCov(t, "coverage", "--framework", "cis_rhel9",
		"--rules-dir", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("exit=%d stderr:\n%s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr must be empty; got:\n%s", stderr)
	}
	if strings.Contains(stdout, "Registered mechanisms") {
		t.Fatal("coverage emitted the mechanism listing")
	}

	// Raw key sets first: Go matches struct fields case-insensitively, so a
	// typed decode alone would accept a renamed key.
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &top); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	wantTop := []string{"controls", "controls_mapped", "framework", "rules_matching", "rules_scanned"}
	if got := rawKeys(top); !reflect.DeepEqual(got, wantTop) {
		t.Errorf("top-level keys = %v, want %v", got, wantTop)
	}
	var ctlRaw struct {
		Controls []map[string]json.RawMessage `json:"controls"`
	}
	if err := json.Unmarshal([]byte(stdout), &ctlRaw); err != nil {
		t.Fatalf("decode controls: %v", err)
	}
	for i, c := range ctlRaw.Controls {
		want := []string{"control_id", "rule_count", "rules"}
		if got := rawKeys(c); !reflect.DeepEqual(got, want) {
			t.Errorf("control %d keys = %v, want %v", i, got, want)
		}
	}

	var doc struct {
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
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decode doc: %v", err)
	}
	if doc.Framework != "cis_rhel9" || doc.RulesScanned != 2 || doc.RulesMatching != 2 || doc.ControlsMapped != 2 {
		t.Errorf("got framework=%s scanned=%d matching=%d mapped=%d; want cis_rhel9 2 2 2",
			doc.Framework, doc.RulesScanned, doc.RulesMatching, doc.ControlsMapped)
	}
	want := map[string][]string{"1.1": {"alpha-rule", "beta-rule"}, "1.2": {"alpha-rule"}}
	for _, c := range doc.Controls {
		w, ok := want[c.ControlID]
		if !ok {
			t.Errorf("unexpected control %q", c.ControlID)
			continue
		}
		if c.RuleCount != len(w) || !reflect.DeepEqual(c.Rules, w) {
			t.Errorf("control %s: count=%d rules=%v; want %d %v", c.ControlID, c.RuleCount, c.Rules, len(w), w)
		}
		delete(want, c.ControlID)
	}
	for id := range want {
		t.Errorf("control %s missing from the report", id)
	}
}

func rawKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCoverage_RulesDirAsymmetry locks AC-04, both sides.
//
// A framework whose controls come from the corpus needs --rules-dir. One that
// ships an embedded objective catalog does not. That asymmetry is deliberate
// and surprising, so both directions are pinned: a later refactor that
// "tidies" it would break the working path.
// @spec cli-coverage-command-finalization
// @ac AC-04
func TestCoverage_RulesDirAsymmetry(t *testing.T) {
	t.Run("cli-coverage-command-finalization/AC-04", func(t *testing.T) {})

	t.Run("generic_requires_rules_dir", func(t *testing.T) {
		code, stdout, stderr := runCov(t, "coverage", "--framework", "cis_rhel9", "--format", "json")
		if code != 2 {
			t.Errorf("exit=%d want 2", code)
		}
		if stdout != "" {
			t.Errorf("stdout must be empty; got:\n%s", stdout)
		}
		for _, want := range []string{"--rules-dir", "required"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr missing %q; got:\n%s", want, stderr)
			}
		}
	})

	t.Run("embedded_catalog_needs_no_rules_dir", func(t *testing.T) {
		code, stdout, stderr := runCov(t, "coverage", "--framework", "nist_800_171", "--format", "json")
		if code != 0 {
			t.Fatalf("exit=%d stderr:\n%s", code, stderr)
		}
		if stderr != "" {
			t.Errorf("stderr must be empty; got:\n%s", stderr)
		}
		if strings.Contains(stdout, "Registered mechanisms") {
			t.Fatal("emitted the mechanism listing")
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
			t.Fatalf("decode: %v\n%s", err, stdout)
		}
		for _, k := range []string{
			"architecture", "ceilings", "framework", "hosts_scanned", "no_rule",
			"partial", "revision", "satisfied", "source_digest", "unclassified_ids",
		} {
			if _, ok := raw[k]; !ok {
				t.Errorf("objective report missing key %q; keys=%v", k, rawKeys(raw))
			}
		}
		var doc struct {
			Framework    string `json:"framework"`
			Revision     string `json:"revision"`
			SourceDigest string `json:"source_digest"`
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatalf("decode doc: %v", err)
		}
		if doc.Framework != "nist_800_171" || doc.Revision != "r2" {
			t.Errorf("framework=%s revision=%s; want nist_800_171 r2", doc.Framework, doc.Revision)
		}
		if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(doc.SourceDigest) || doc.SourceDigest == "" {
			t.Errorf("source_digest = %q; want non-empty lowercase hex", doc.SourceDigest)
		}
	})
}

// TestMechanisms_RemainsSeparateAndNarrow locks AC-05.
// @spec cli-coverage-command-finalization
// @ac AC-05
func TestMechanisms_RemainsSeparateAndNarrow(t *testing.T) {
	t.Run("cli-coverage-command-finalization/AC-05", func(t *testing.T) {})

	t.Run("list", func(t *testing.T) {
		code, stdout, stderr := runCov(t, "mechanisms")
		if code != 0 {
			t.Fatalf("exit=%d stderr:\n%s", code, stderr)
		}
		if stderr != "" {
			t.Errorf("stderr must be empty; got:\n%s", stderr)
		}
		for _, want := range []string{"Registered mechanisms", "file_permissions"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout missing %q", want)
			}
		}
	})

	t.Run("help", func(t *testing.T) {
		code, stdout, stderr := runCov(t, "mechanisms", "--help")
		if code != 0 || stderr != "" {
			t.Errorf("exit=%d stderr=%q", code, stderr)
		}
		if got := longFlagsIn(stdout); !reflect.DeepEqual(got, []string{"help"}) {
			t.Errorf("mechanisms help flags = %v, want [help]", got)
		}
		for _, banned := range []string{"framework coverage", "v0.2", "alias"} {
			if strings.Contains(stdout, banned) {
				t.Errorf("mechanisms help carries %q", banned)
			}
		}
		shortCode, shortOut, shortErr := runCov(t, "mechanisms", "-h")
		if shortCode != 0 || shortErr != "" {
			t.Errorf("-h exit=%d stderr=%q", shortCode, shortErr)
		}
		if shortOut != stdout {
			t.Errorf("-h and --help differ")
		}
	})

	t.Run("forbidden_framework", func(t *testing.T) {
		code, stdout, stderr := runCov(t, "mechanisms", "--framework", "cis_rhel9")
		if code != 2 {
			t.Errorf("exit=%d want 2", code)
		}
		if stdout != "" {
			t.Errorf("stdout must be empty; got:\n%s", stdout)
		}
		for _, want := range []string{"--framework", "kensa coverage"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr missing %q; got:\n%s", want, stderr)
			}
		}
	})
}

// longFlagsIn extracts the sorted set of long flags a help body advertises.
func longFlagsIn(help string) []string {
	re := regexp.MustCompile(`--([a-z][a-z0-9-]*)`)
	seen := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(help, -1) {
		seen[m[1]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// TestCoverage_ExpiredWarningControlIsInert locks AC-06.
// @spec cli-coverage-command-finalization
// @ac AC-06
func TestCoverage_ExpiredWarningControlIsInert(t *testing.T) {
	t.Run("cli-coverage-command-finalization/AC-06", func(t *testing.T) {})
	type result struct {
		code     int
		out, err string
	}
	var results []result
	for _, v := range []string{"", "1", "true"} {
		t.Setenv("KENSA_NO_REPURPOSE_WARNINGS", v)
		code, so, se := runCLIAll(t, "coverage")
		results = append(results, result{code, so, se})
	}
	first := results[0]
	for i, r := range results {
		if r != first {
			t.Errorf("run %d differs from the unset run; the knob still affects behavior", i)
		}
		if r.code != 2 {
			t.Errorf("run %d exit=%d want 2", i, r.code)
		}
		if r.out != "" {
			t.Errorf("run %d wrote stdout: %s", i, r.out)
		}
		for _, want := range []string{"--framework", "required"} {
			if !strings.Contains(r.err, want) {
				t.Errorf("run %d stderr missing %q; got %s", i, want, r.err)
			}
		}
	}
}

// TestTopHelpAndCompletion_ExposeFinalSurface locks AC-07.
//
// The completion flag set is compared against the flags the real help body
// advertises, so a hand-maintained list cannot drift from the binary.
// @spec cli-coverage-command-finalization
// @ac AC-07
func TestTopHelpAndCompletion_ExposeFinalSurface(t *testing.T) {
	t.Run("cli-coverage-command-finalization/AC-07", func(t *testing.T) {})

	code, stdout, stderr := runCov(t, "--help")
	if code != 0 || stderr != "" {
		t.Errorf("top help exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "mechanisms") || !strings.Contains(stdout, "coverage") {
		t.Errorf("top help missing a command row")
	}
	for _, banned := range []string{"Alias for", "change meaning", "v0.2", "migrate scripts"} {
		if strings.Contains(stdout, banned) {
			t.Errorf("top help still carries %q; got:\n%s", banned, stdout)
		}
	}

	// The authoritative set: what coverage --help actually advertises.
	_, covHelp, _ := runCov(t, "coverage", "--help")
	wantFlags := longFlagsIn(covHelp)
	if len(wantFlags) == 0 {
		t.Fatal("coverage help advertised no flags")
	}

	var covEntry *completionSpec
	for i := range completionSpecs {
		if completionSpecs[i].name == "coverage" {
			covEntry = &completionSpecs[i]
		}
	}
	if covEntry == nil {
		t.Fatal("coverage missing from the completion table")
	}
	got := append([]string(nil), covEntry.flags...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, wantFlags) {
		t.Errorf("completion flags = %v, but coverage --help advertises %v", got, wantFlags)
	}

	// Each shell spells a long option differently: bash and zsh emit "--name",
	// fish emits "-l name". Asserting one spelling everywhere would pass or
	// fail for the wrong reason.
	for _, shell := range []string{"bash", "zsh", "fish"} {
		_, script, _ := runCov(t, "completion", shell)
		for _, f := range wantFlags {
			var present bool
			if shell == "fish" {
				present = strings.Contains(script, "-l "+f)
			} else {
				present = strings.Contains(script, "--"+f)
			}
			if !present {
				t.Errorf("%s completion missing the %s flag", shell, f)
			}
		}
	}
}

// TestCoverage_QuietFollowsFinalParser locks AC-09.
// @spec cli-coverage-command-finalization
// @ac AC-09
func TestCoverage_QuietFollowsFinalParser(t *testing.T) {
	t.Run("cli-coverage-command-finalization/AC-09", func(t *testing.T) {})
	dir := twoControlCorpus(t)

	t.Run("quiet_success", func(t *testing.T) {
		code, stdout, stderr := runCov(t, "coverage", "--framework", "cis_rhel9",
			"--rules-dir", dir, "--quiet")
		if code != 0 || stdout != "" || stderr != "" {
			t.Errorf("exit=%d stdout=%q stderr=%q; want 0 and both empty", code, stdout, stderr)
		}
	})
	t.Run("quiet_missing_framework", func(t *testing.T) {
		code, stdout, stderr := runCov(t, "coverage", "--quiet")
		if code != 2 || stdout != "" {
			t.Errorf("exit=%d stdout=%q; want 2 and empty", code, stdout)
		}
		for _, want := range []string{"--framework", "required"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr missing %q; got:\n%s", want, stderr)
			}
		}
	})
	t.Run("quiet_help", func(t *testing.T) {
		code, stdout, stderr := runCov(t, "coverage", "--quiet", "--help")
		if code != 0 || stderr != "" {
			t.Errorf("exit=%d stderr=%q", code, stderr)
		}
		for _, want := range []string{"Usage: kensa coverage", "--quiet"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("help missing %q", want)
			}
		}
	})
}
