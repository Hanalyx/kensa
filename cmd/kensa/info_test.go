// Tests for the C-047 `kensa info` flow.
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRunInfo_RuleMode locks AC-01: --rule prints the rule's
// title, severity, and references.
// @spec cli-info
// @ac AC-01
func TestRunInfo_RuleMode(t *testing.T) {
	t.Run("cli-info/AC-01", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "--rule", "rule-a", "--rules-dir", dir},
		t,
	)
	if !strings.Contains(stdout, "Rule: rule-a") {
		t.Errorf("missing 'Rule: rule-a' header; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "severity:    low") {
		t.Errorf("expected 'severity: low'; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "5.1.12") {
		t.Errorf("expected CIS 5.1.12 reference; got:\n%s", stdout)
	}
}

// TestRunInfo_ControlMode locks AC-02.
// @spec cli-info
// @ac AC-02
func TestRunInfo_ControlMode(t *testing.T) {
	t.Run("cli-info/AC-02", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "--control", "cis_rhel9:5.1.12", "--rules-dir", dir},
		t,
	)
	if !strings.Contains(stdout, "Control: cis_rhel9:5.1.12") {
		t.Errorf("missing control header; got:\n%s", stdout)
	}
	// makeCoverageCorpus has rule-a and rule-b mapping cis_rhel9 5.1.12.
	if !strings.Contains(stdout, "rule-a") || !strings.Contains(stdout, "rule-b") {
		t.Errorf("expected rule-a + rule-b; got:\n%s", stdout)
	}
}

// TestRunInfo_ListControlsMode locks AC-03.
// @spec cli-info
// @ac AC-03
func TestRunInfo_ListControlsMode(t *testing.T) {
	t.Run("cli-info/AC-03", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "--list-controls", "nist_800_53", "--rules-dir", dir},
		t,
	)
	if !strings.Contains(stdout, "Framework: nist_800_53") {
		t.Errorf("missing framework header; got:\n%s", stdout)
	}
	// makeCoverageCorpus has nist_800_53 AC-1 (rule-a) and AC-2 (rule-c).
	if !strings.Contains(stdout, "AC-1") || !strings.Contains(stdout, "AC-2") {
		t.Errorf("expected AC-1 + AC-2; got:\n%s", stdout)
	}
}

// TestRunInfo_QueryMode locks AC-04: positional QUERY.
// @spec cli-info
// @ac AC-04
func TestRunInfo_QueryMode(t *testing.T) {
	t.Run("cli-info/AC-04", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	// makeCoverageCorpus rules all have title "Test rule" and
	// description "minimal rule". Query "test" should hit all 3.
	stdout, _ := captureRunCLI(
		[]string{"info", "test", "--rules-dir", dir},
		t,
	)
	if !strings.Contains(stdout, "3 hit(s)") {
		t.Errorf("expected '3 hit(s)' for 'test' query; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "rule-a") {
		t.Errorf("expected rule-a in hits; got:\n%s", stdout)
	}
}

// TestRunInfo_ModeMutualExclusion locks AC-05. Per peer-review-
// driven contract change, ALL four mode selectors are pairwise
// exclusive: --rule, --control, --list-controls, AND positional
// QUERY. The earlier spec text claimed --rule + QUERY composes,
// but the implementation never honored it — the spec was lying
// about behavior. Resolved by rejecting every pair.
// @spec cli-info
// @ac AC-05
func TestRunInfo_ModeMutualExclusion(t *testing.T) {
	t.Run("cli-info/AC-05", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	cases := [][]string{
		// Mode-flag pairs:
		{"info", "--rule", "x", "--control", "y:z", "--rules-dir", dir},
		{"info", "--rule", "x", "--list-controls", "y", "--rules-dir", dir},
		{"info", "--control", "y:z", "--list-controls", "y", "--rules-dir", dir},
		// QUERY paired with mode flags:
		{"info", "--list-controls", "y", "--rules-dir", dir, "some-query"},
		{"info", "--rule", "rule-a", "--rules-dir", dir, "some-query"},
		{"info", "--control", "y:z", "--rules-dir", dir, "some-query"},
	}
	for _, args := range cases {
		exit := runCLI(args)
		if exit != 2 {
			t.Errorf("runCLI(%v) = %d, want 2", args, exit)
		}
	}
}

// TestRunInfo_NistRhelRejected locks the C-06 / spec note that
// --nist + --rhel produces a silent no-match (nist_800_53 is
// unversioned). Rejected with a usage error.
// @spec cli-info
// @ac AC-06
func TestRunInfo_NistRhelRejected(t *testing.T) {
	t.Run("cli-info/AC-06", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	exit := runCLI([]string{"info", "--nist", "--rhel", "9", "ssh", "--rules-dir", dir})
	if exit != 2 {
		t.Errorf("--nist + --rhel should exit 2; got %d", exit)
	}
	_, stderr := captureRunCLI([]string{"info", "--nist", "--rhel", "9", "ssh", "--rules-dir", dir}, t)
	if !strings.Contains(stderr, "unversioned") {
		t.Errorf("error should explain nist_800_53 is unversioned; got:\n%s", stderr)
	}
}

// TestRunInfo_NoRulesDirNoMode locks the coalesced error: if
// BOTH --rules-dir AND mode are missing, the error message
// names both so the operator doesn't have to retry to learn.
// @spec cli-info
// @ac AC-07
func TestRunInfo_NoRulesDirNoMode(t *testing.T) {
	t.Run("cli-info/AC-07", func(t *testing.T) {})
	_, stderr := captureRunCLI([]string{"info"}, t)
	if !strings.Contains(stderr, "missing --rules-dir") {
		t.Errorf("error should mention --rules-dir; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "mode") {
		t.Errorf("error should mention mode; got:\n%s", stderr)
	}
}

// TestRunInfo_LimitClampsSearch locks the --limit truncation
// in search mode. makeCoverageCorpus has 3 rules; --limit 1
// should produce 1 hit row + truncation footer.
// @spec cli-info
// @ac AC-08
func TestRunInfo_LimitClampsSearch(t *testing.T) {
	t.Run("cli-info/AC-08", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "test", "--rules-dir", dir, "--limit", "1"},
		t,
	)
	if !strings.Contains(stdout, "showing first 1 of 3") {
		t.Errorf("expected truncation footer 'showing first 1 of 3'; got:\n%s", stdout)
	}
}

// TestRunInfo_LimitZeroUnlimited locks the 0=unlimited contract.
// @spec cli-info
// @ac AC-09
func TestRunInfo_LimitZeroUnlimited(t *testing.T) {
	t.Run("cli-info/AC-09", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "test", "--rules-dir", dir, "--limit", "0"},
		t,
	)
	if strings.Contains(stdout, "showing first") {
		t.Errorf("--limit 0 should never truncate; got:\n%s", stdout)
	}
}

// TestRunInfo_LimitNegativeRejected locks the validator.
// @spec cli-info
// @ac AC-10
func TestRunInfo_LimitNegativeRejected(t *testing.T) {
	t.Run("cli-info/AC-10", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	exit := runCLI([]string{"info", "test", "--rules-dir", dir, "--limit", "-1"})
	if exit != 2 {
		t.Errorf("--limit -1 should exit 2; got %d", exit)
	}
}

// TestRunInfo_PlatformAnyVersion locks the unbounded-platform
// rendering: max=0 must NOT appear in operator-facing output;
// it should render as "any version" / ">= N" depending on
// MinVersion.
// @spec cli-info
// @ac AC-11
func TestRunInfo_PlatformAnyVersion(t *testing.T) {
	t.Run("cli-info/AC-11", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	// makeCoverageCorpus rules use "rhel" min_version=8 max=0.
	// Expected rendering: "rhel >= 8".
	stdout, _ := captureRunCLI(
		[]string{"info", "--rule", "rule-a", "--rules-dir", dir},
		t,
	)
	if strings.Contains(stdout, "max=0") {
		t.Errorf("text output should not show 'max=0' (should render as unbounded); got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "rhel >= 8") {
		t.Errorf("expected 'rhel >= 8' rendering; got:\n%s", stdout)
	}
}

// TestRunInfo_QueryWithFamilyFilter locks the QUERY + family
// compose path (R1 P2 #4 — was unexercised). makeCoverageCorpus
// rule-a maps cis_rhel9; rule-b maps cis_rhel9; rule-c maps
// nist_800_53 only. Search "test" + --cis should yield rule-a
// and rule-b; rule-c filtered out.
// @spec cli-info
// @ac AC-12
func TestRunInfo_QueryWithFamilyFilter(t *testing.T) {
	t.Run("cli-info/AC-12", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "test", "--cis", "--rules-dir", dir},
		t,
	)
	if !strings.Contains(stdout, "rule-a") || !strings.Contains(stdout, "rule-b") {
		t.Errorf("expected rule-a + rule-b under --cis filter; got:\n%s", stdout)
	}
	if strings.Contains(stdout, "rule-c") {
		t.Errorf("rule-c maps only nist_800_53; should be filtered out by --cis; got:\n%s", stdout)
	}
}

// TestRunInfo_FamilyMutualExclusion locks AC-06: --cis + --stig
// rejected.
// @spec cli-info
// @ac AC-13
func TestRunInfo_FamilyMutualExclusion(t *testing.T) {
	t.Run("cli-info/AC-13", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	exit := runCLI([]string{"info", "--cis", "--stig", "--rules-dir", dir})
	if exit != 2 {
		t.Errorf("--cis + --stig should exit 2; got %d", exit)
	}
}

// TestRunInfo_RhelValidation locks AC-07.
// @spec cli-info
// @ac AC-14
func TestRunInfo_RhelValidation(t *testing.T) {
	t.Run("cli-info/AC-14", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	for _, v := range []string{"7", "11", "100", "0"} {
		exit := runCLI([]string{"info", "test", "--rhel", v, "--rules-dir", dir})
		// 0 falls through (no filter) and is valid; 7/11/100 reject.
		if v == "0" {
			if exit != 0 {
				t.Errorf("--rhel 0 should pass through; got exit %d", exit)
			}
			continue
		}
		if exit != 2 {
			t.Errorf("--rhel %s should exit 2; got %d", v, exit)
		}
	}
}

// TestRunInfo_NotFoundExitCode locks AC-08: unknown rule and
// unknown control return exit 1 (runtime), NOT exit 2 (usage).
// @spec cli-info
// @ac AC-15
func TestRunInfo_NotFoundExitCode(t *testing.T) {
	t.Run("cli-info/AC-15", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	cases := [][]string{
		{"info", "--rule", "no-such-rule", "--rules-dir", dir},
		{"info", "--control", "nist_800_53:ZZ-99", "--rules-dir", dir},
		{"info", "--list-controls", "no_such_framework", "--rules-dir", dir},
	}
	for _, args := range cases {
		exit := runCLI(args)
		if exit != 1 {
			t.Errorf("runCLI(%v) = %d, want 1 (runtime error); got %d", args, exit, exit)
		}
	}
}

// TestRunInfo_JSONShape locks AC-09: snake_case JSON via
// --format json. Each mode emits its own shape; we sample
// rule-mode for the structural assertion.
// @spec cli-info
// @ac AC-16
func TestRunInfo_JSONShape(t *testing.T) {
	t.Run("cli-info/AC-16", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "--rule", "rule-a", "--rules-dir", dir, "--format", "json"},
		t,
	)
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json unmarshal: %v\nstdout:\n%s", err, stdout)
	}
	for _, want := range []string{"id", "title", "severity", "framework_refs", "platforms"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected JSON field %q in:\n%s", want, stdout)
		}
	}
	// Snake_case sanity check.
	for _, snake := range []string{`"framework_refs":`, `"min_version":`} {
		if !strings.Contains(stdout, snake) {
			t.Errorf("expected %q in JSON output:\n%s", snake, stdout)
		}
	}
}

// TestRunInfo_NoMode requires the operator to pick a mode.
func TestRunInfo_NoMode(t *testing.T) {
	dir := makeCoverageCorpus(t)
	exit := runCLI([]string{"info", "--rules-dir", dir})
	if exit != 2 {
		t.Errorf("no mode + no query should exit 2; got %d", exit)
	}
}

// TestRunInfo_MissingRulesDir locks --rules-dir requirement.
func TestRunInfo_MissingRulesDir(t *testing.T) {
	exit := runCLI([]string{"info", "anything"})
	if exit != 2 {
		t.Errorf("missing --rules-dir should exit 2; got %d", exit)
	}
}

// TestRunInfo_BadFormat.
func TestRunInfo_BadFormat(t *testing.T) {
	dir := makeCoverageCorpus(t)
	exit := runCLI([]string{"info", "--rule", "rule-a", "--rules-dir", dir, "--format", "yaml"})
	if exit != 2 {
		t.Errorf("bad format should exit 2; got %d", exit)
	}
}

// TestRunInfo_HelpExitsZero.
func TestRunInfo_HelpExitsZero(t *testing.T) {
	for _, argv := range [][]string{
		{"info", "--help"},
		{"info", "-h"},
	} {
		got := runCLI(argv)
		if got != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, got)
		}
	}
}

// TestRunInfo_BadControlSpec locks the FRAMEWORK:ID format
// validation.
func TestRunInfo_BadControlSpec(t *testing.T) {
	dir := makeCoverageCorpus(t)
	for _, spec := range []string{"no-colon", ":missing-fw", "missing-id:"} {
		exit := runCLI([]string{"info", "--control", spec, "--rules-dir", dir})
		if exit != 2 {
			t.Errorf("--control %q should exit 2; got %d", spec, exit)
		}
	}
}
