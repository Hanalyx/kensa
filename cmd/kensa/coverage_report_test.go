// Tests for the C-045 `kensa coverage --framework` flow.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/internal/coverage"
)

// makeCoverageCorpus writes a 3-rule directory:
//   - rule-a maps cis_rhel9 5.1.12 + nist_800_53 AC-1
//   - rule-b maps cis_rhel9 5.1.12 (same control as rule-a)
//   - rule-c maps nist_800_53 AC-2
//
// Uses the same minimal-rule shape as cmd/kensa/rule_flag_test.go's
// writeMinimalRule helper; that's the schema the parser actually
// accepts (rule_flag_test.go's lock would catch drift).
func makeCoverageCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	header := func(id string) string {
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

references:
`
	}
	rules := map[string]string{
		"rule-a.yml": header("rule-a") + `  cis:
    rhel9:
      section: "5.1.12"
  nist_800_53:
    - AC-1
`,
		"rule-b.yml": header("rule-b") + `  cis:
    rhel9:
      section: "5.1.12"
`,
		"rule-c.yml": header("rule-c") + `  nist_800_53:
    - AC-2
`,
	}
	for name, body := range rules {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// @spec cli-coverage-mechanisms-rename
// @ac AC-01
// @spec cli-framework-coverage
// @ac AC-01
// @ac AC-14
func TestRunCoverageReport_Basic(t *testing.T) {
	t.Run("cli-framework-coverage/AC-01", func(t *testing.T) {})
	t.Run("cli-framework-coverage/AC-14", func(t *testing.T) {})
	t.Run("cli-coverage-mechanisms-rename/AC-01", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"coverage", "--framework", "cis_rhel9", "--rules-dir", dir},
		t,
	)
	if !strings.Contains(stdout, "kensa coverage --framework cis_rhel9") {
		t.Errorf("missing header in stdout:\n%s", stdout)
	}
	// Reworded label per peer review: "controls with rules" not
	// "controls mapped" (avoids reading a numerator as a coverage %).
	if !strings.Contains(stdout, "controls with rules:       1") {
		t.Errorf("expected 'controls with rules: 1'; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "5.1.12") {
		t.Errorf("expected control 5.1.12 in output:\n%s", stdout)
	}
	// "numerator only" disclaimer must appear so operators don't
	// misread the count as a percentage denominator.
	if !strings.Contains(stdout, "numerator only") {
		t.Errorf("expected 'numerator only' disclaimer; got:\n%s", stdout)
	}
}

// TestRunCoverageReport_UnknownFramework locks AC-02. The error
// message MUST list available frameworks so the operator can
// recover without a separate `kensa list frameworks` call.
// @spec cli-coverage-mechanisms-rename
// @ac AC-02
// @spec cli-framework-coverage
// @ac AC-02
func TestRunCoverageReport_UnknownFramework(t *testing.T) {
	t.Run("cli-framework-coverage/AC-02", func(t *testing.T) {})
	t.Run("cli-coverage-mechanisms-rename/AC-02", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	_, stderr := captureRunCLI(
		[]string{"coverage", "--framework", "bogus_v999", "--rules-dir", dir},
		t,
	)
	if !strings.Contains(stderr, "cis_rhel9") || !strings.Contains(stderr, "nist_800_53") {
		t.Errorf("error message should list available frameworks; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "bogus_v999") {
		t.Errorf("error message should echo the bad framework; got:\n%s", stderr)
	}
	exit := runCLI([]string{"coverage", "--framework", "bogus_v999", "--rules-dir", dir})
	if exit != 2 {
		t.Errorf("unknown framework should exit 2; got %d", exit)
	}
}

// TestRunCoverageReport_BadFormat locks the format validation
// (caught zero coverage today; --format yaml silently fell back
// to text per peer review).
// @spec cli-coverage-mechanisms-rename
// @ac AC-03
// @spec cli-framework-coverage
// @ac AC-03
func TestRunCoverageReport_BadFormat(t *testing.T) {
	t.Run("cli-framework-coverage/AC-03", func(t *testing.T) {})
	t.Run("cli-coverage-mechanisms-rename/AC-03", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	exit := runCLI([]string{"coverage", "--framework", "cis_rhel9", "--rules-dir", dir, "--format", "yaml"})
	if exit != 2 {
		t.Errorf("unknown --format should exit 2; got %d", exit)
	}
}

// TestRunCoverageReport_FullFlag locks the --full audit-mode
// escape hatch — without --full, rule IDs truncate to 3 + "+N
// more"; with --full, all IDs render.
// @spec cli-coverage-mechanisms-rename
// @ac AC-04
// @spec cli-framework-coverage
// @ac AC-04
func TestRunCoverageReport_FullFlag(t *testing.T) {
	t.Run("cli-framework-coverage/AC-04", func(t *testing.T) {})
	t.Run("cli-coverage-mechanisms-rename/AC-04", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	// Default: rule-a + rule-b both map cis_rhel9 5.1.12; only 2
	// rules so no truncation either way. Use nist_800_53 with
	// rule-a + rule-c (2 rules, no truncation either) — neither
	// dimension exercises >3 rules in our minimal corpus. So
	// this test asserts only that --full doesn't break the
	// happy path; the truncate-with-+N path is unit-tested in
	// internal/coverage indirectly via Rules sort order.
	stdout, _ := captureRunCLI(
		[]string{"coverage", "--framework", "cis_rhel9", "--rules-dir", dir, "--full"},
		t,
	)
	if !strings.Contains(stdout, "rule-a") || !strings.Contains(stdout, "rule-b") {
		t.Errorf("--full should list all rule IDs; got:\n%s", stdout)
	}
	if strings.Contains(stdout, "+0 more") || strings.Contains(stdout, "truncated") {
		t.Errorf("--full should NOT print the truncation footer; got:\n%s", stdout)
	}
}

// @spec cli-coverage-mechanisms-rename
// @ac AC-05
// @spec cli-framework-coverage
// @ac AC-05
func TestRunCoverageReport_MissingRulesDir(t *testing.T) {
	t.Run("cli-framework-coverage/AC-05", func(t *testing.T) {})
	t.Run("cli-coverage-mechanisms-rename/AC-05", func(t *testing.T) {})
	exit := runCLI([]string{"coverage", "--framework", "cis_rhel9"})
	if exit != 2 {
		t.Errorf("missing --rules-dir should exit 2; got %d", exit)
	}
}

// @spec cli-coverage-mechanisms-rename
// @ac AC-06
// @spec cli-framework-coverage
// @ac AC-06
func TestRunCoverageReport_MissingFramework(t *testing.T) {
	t.Run("cli-framework-coverage/AC-06", func(t *testing.T) {})
	t.Run("cli-coverage-mechanisms-rename/AC-06", func(t *testing.T) {})
	// --framework is what activates the new code path; without
	// it dispatch falls through to the mechanism alias instead
	// of erroring. So this test exercises the dispatch directly
	// to verify that calling runCoverageReport with no framework
	// errors at parse time.
	err := runCoverageReport([]string{"--rules-dir", t.TempDir()})
	if err == nil {
		t.Fatal("missing --framework should error")
	}
	if !IsUsageError(err) {
		t.Errorf("expected UsageError; got %v", err)
	}
}

// @spec cli-coverage-mechanisms-rename
// @ac AC-07
// @spec cli-framework-coverage
// @ac AC-07
func TestRunCoverageReport_JSONShape(t *testing.T) {
	t.Run("cli-framework-coverage/AC-07", func(t *testing.T) {})
	t.Run("cli-coverage-mechanisms-rename/AC-07", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"coverage", "--framework", "nist_800_53", "--rules-dir", dir, "--format", "json"},
		t,
	)
	var got coverage.CoverageReport
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json unmarshal: %v\nstdout was:\n%s", err, stdout)
	}
	if got.Framework != "nist_800_53" {
		t.Errorf("Framework: got %q", got.Framework)
	}
	if got.ControlsMapped != 2 { // AC-1 + AC-2
		t.Errorf("ControlsMapped: got %d want 2", got.ControlsMapped)
	}
	// Snake_case JSON shape: walk the raw bytes for evidence the
	// fields aren't PascalCase (would break JSON consumers).
	for _, expected := range []string{"\"framework\":", "\"rules_scanned\":", "\"controls_mapped\":", "\"control_id\":"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected JSON field %q in:\n%s", expected, stdout)
		}
	}
}

// TestRunCoverage_FrameworkFlagSuppressesWarning locks AC-06 —
// when --framework is on argv, the C-044 repurpose warning is
// suppressed (operator already using the new behavior).
// @spec cli-coverage-mechanisms-rename
// @ac AC-08
// @spec cli-framework-coverage
// @ac AC-08
func TestRunCoverage_FrameworkFlagSuppressesWarning(t *testing.T) {
	t.Run("cli-framework-coverage/AC-08", func(t *testing.T) {})
	t.Run("cli-coverage-mechanisms-rename/AC-08", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	_, stderr := captureRunCLI(
		[]string{"coverage", "--framework", "cis_rhel9", "--rules-dir", dir},
		t,
	)
	if strings.Contains(stderr, "v0.2") || strings.Contains(stderr, "change meaning") {
		t.Errorf("--framework should suppress the C-044 repurpose warning; got stderr:\n%s", stderr)
	}
}

// TestRunMechanisms_FrameworkRejected locks AC-07 / C-05 —
// `kensa mechanisms --framework foo` is a usage error.
// @spec cli-framework-coverage
// @ac AC-09
func TestRunMechanisms_FrameworkRejected(t *testing.T) {
	t.Run("cli-framework-coverage/AC-09", func(t *testing.T) {})
	exit := runCLI([]string{"mechanisms", "--framework", "cis_rhel9"})
	if exit != 2 {
		t.Errorf("kensa mechanisms --framework should exit 2; got %d", exit)
	}
}

// TestHasFrameworkFlag locks the dispatch-time scanner. Now
// uses pflag itself so merged-short-bool forms (-qfX = -q + -f=X)
// route correctly — the previous hand-rolled scanner missed
// those, which would have routed `-qfcis_rhel9` to the alias
// path with a misleading repurpose warning.
// @spec cli-framework-coverage
// @ac AC-10
func TestHasFrameworkFlag(t *testing.T) {
	t.Run("cli-framework-coverage/AC-10", func(t *testing.T) {})
	cases := map[string][]string{
		// Should detect:
		"long form alone":           {"--framework", "cis_rhel9"},
		"long form with =":          {"--framework=cis_rhel9"},
		"short form alone":          {"-f", "cis_rhel9"},
		"short form with =":         {"-f=cis_rhel9"},
		"short form concat":         {"-fcis_rhel9"},
		"with other flags":          {"--rules-dir", "/x", "--framework", "cis_rhel9"},
		"after positional":          {"foo", "--framework", "cis_rhel9"},
		"merged short -qfcis_rhel9": {"-qfcis_rhel9"},
		// Should NOT detect:
		"empty":                nil,
		"unrelated long flag":  {"--rules-dir", "/x"},
		"-q quiet":             {"-q"},
		"--help":               {"--help"},
		"--foo (not -f short)": {"--foo"},
		"after end-of-options": {"--", "--framework", "cis_rhel9"},
	}
	wantTrue := map[string]bool{
		"long form alone": true, "long form with =": true,
		"short form alone": true, "short form with =": true, "short form concat": true,
		"with other flags": true, "after positional": true,
		"merged short -qfcis_rhel9": true,
	}
	for name, args := range cases {
		got := hasFrameworkFlag(args)
		want := wantTrue[name]
		if got != want {
			t.Errorf("hasFrameworkFlag(%v) [%s] = %v, want %v", args, name, got, want)
		}
	}
}

// TestRunCoverage_FrameworkHelpEmitsWarning locks R2's P1.3 fix:
// `kensa coverage --framework FOO --help` MUST emit the C-044
// repurpose warning to stderr. Operators reading docs to learn
// the new surface need to see the upcoming v0.2 flip once.
// @spec cli-framework-coverage
// @ac AC-11
func TestRunCoverage_FrameworkHelpEmitsWarning(t *testing.T) {
	t.Run("cli-framework-coverage/AC-11", func(t *testing.T) {})
	stdout, stderr := captureRunCLI(
		[]string{"coverage", "--framework", "cis_rhel9", "--help"},
		t,
	)
	if !strings.Contains(stderr, "v0.2") {
		t.Errorf("--framework --help should emit repurpose warning to stderr; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "mechanisms") {
		t.Errorf("warning should reference 'mechanisms'; got:\n%s", stderr)
	}
	// Help body itself reaches stdout; the warning is stderr-only
	// (doesn't pollute parseable help capture).
	if !strings.Contains(stdout, "framework-coverage report") &&
		!strings.Contains(stdout, "Report which controls") {
		t.Errorf("help body should reach stdout; got:\n%s", stdout)
	}
}

// TestPrintMechanismsCoverageHelp_AdvertisesNewSurface locks
// R2's P1.2 fix: `kensa coverage --help` (no --framework) must
// point operators at the new --framework surface so they can
// discover the C-045 report without already knowing about it.
// @spec cli-framework-coverage
// @ac AC-12
func TestPrintMechanismsCoverageHelp_AdvertisesNewSurface(t *testing.T) {
	t.Run("cli-framework-coverage/AC-12", func(t *testing.T) {})
	stdout, _ := captureRunCLI([]string{"coverage", "--help"}, t)
	if !strings.Contains(stdout, "AVAILABLE TODAY") {
		t.Errorf("alias --help should advertise the new --framework surface; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "--framework") {
		t.Errorf("alias --help should mention --framework; got:\n%s", stdout)
	}
}

// TestRunCoverageReport_HelpExitsZero locks the help path.
// @spec cli-framework-coverage
// @ac AC-13
func TestRunCoverageReport_HelpExitsZero(t *testing.T) {
	t.Run("cli-framework-coverage/AC-13", func(t *testing.T) {})
	for _, argv := range [][]string{
		{"coverage", "--framework", "cis_rhel9", "--help"},
		{"coverage", "--framework", "cis_rhel9", "-h"},
	} {
		got := runCLI(argv)
		if got != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, got)
		}
	}
}
