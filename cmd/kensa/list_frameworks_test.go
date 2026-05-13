// Tests for the C-046 `kensa list frameworks` flow.
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRunListFrameworks_Basic locks AC-01: --rules-dir DIR
// produces a header + per-framework table covering the fixtures
// in the C-045 makeCoverageCorpus (rule-a + rule-b: cis_rhel9,
// rule-a + rule-c: nist_800_53). Two frameworks expected.
// @spec cli-list-frameworks
// @ac AC-01
func TestRunListFrameworks_Basic(t *testing.T) {
	t.Run("cli-list-frameworks/AC-01", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"list", "frameworks", "--rules-dir", dir},
		t,
	)
	if !strings.Contains(stdout, "kensa list frameworks") {
		t.Errorf("missing header in stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "2 framework(s)") {
		t.Errorf("expected '2 framework(s)' header; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "cis_rhel9") {
		t.Errorf("expected cis_rhel9 row; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "nist_800_53") {
		t.Errorf("expected nist_800_53 row; got:\n%s", stdout)
	}
}

// TestRunListFrameworks_MissingRulesDir locks the C-01
// validation: --rules-dir is required.
// @spec cli-list-frameworks
// @ac AC-02
func TestRunListFrameworks_MissingRulesDir(t *testing.T) {
	t.Run("cli-list-frameworks/AC-02", func(t *testing.T) {})
	exit := runCLI([]string{"list", "frameworks"})
	if exit != 2 {
		t.Errorf("missing --rules-dir should exit 2; got %d", exit)
	}
}

// TestRunList_UnknownSubject locks AC-04: unknown subject
// rejected with usage error mentioning available subjects.
// @spec cli-list-frameworks
// @ac AC-03
func TestRunList_UnknownSubject(t *testing.T) {
	t.Run("cli-list-frameworks/AC-03", func(t *testing.T) {})
	_, stderr := captureRunCLI([]string{"list", "widgets"}, t)
	if !strings.Contains(stderr, "frameworks") {
		t.Errorf("error should list available subjects; got:\n%s", stderr)
	}
	exit := runCLI([]string{"list", "widgets"})
	if exit != 2 {
		t.Errorf("unknown subject should exit 2; got %d", exit)
	}
}

// TestRunList_HelpExitsZero locks AC-07: --help/-h forms exit 0.
// The `kensa list` (no args) case is INTENTIONALLY excluded —
// see TestRunList_NoArgsIsUsageError for the script-footgun
// rationale.
// @spec cli-list-frameworks
// @ac AC-04
func TestRunList_HelpExitsZero(t *testing.T) {
	t.Run("cli-list-frameworks/AC-04", func(t *testing.T) {})
	for _, argv := range [][]string{
		{"list", "--help"},
		{"list", "-h"},
		{"list", "frameworks", "--help"},
		{"list", "frameworks", "-h"},
	} {
		got := runCLI(argv)
		if got != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, got)
		}
	}
}

// TestRunList_NoArgsIsUsageError closes the CI-script footgun:
// `kensa list` with no subject is a usage error (exit 2), not a
// help-on-stdout-and-exit-0. Two reviewers independently flagged
// this — a script of the form `kensa list frameworks --rules-dir
// $D | jq …` would silently no-op if the subject is dropped by
// a templating bug. Subject-less invocation is now an error;
// `--help` / `-h` remains exit 0 for true help requests.
// @spec cli-list-frameworks
// @ac AC-05
func TestRunList_NoArgsIsUsageError(t *testing.T) {
	t.Run("cli-list-frameworks/AC-05", func(t *testing.T) {})
	exit := runCLI([]string{"list"})
	if exit != 2 {
		t.Errorf("kensa list (no subject) should exit 2; got %d", exit)
	}
	_, stderr := captureRunCLI([]string{"list"}, t)
	if !strings.Contains(stderr, "frameworks") {
		t.Errorf("stderr should list available subjects; got:\n%s", stderr)
	}
}

// TestRunList_FlagBeforeSubjectHints locks the operator-confused-
// intent guard: `kensa list --rules-dir DIR` (forgot subject)
// produces a usage error containing "did you mean" and the
// suggested rewrite.
// @spec cli-list-frameworks
// @ac AC-06
func TestRunList_FlagBeforeSubjectHints(t *testing.T) {
	t.Run("cli-list-frameworks/AC-06", func(t *testing.T) {})
	_, stderr := captureRunCLI([]string{"list", "--rules-dir", "/x"}, t)
	if !strings.Contains(stderr, "did you mean") {
		t.Errorf("flag-before-subject should hint 'did you mean'; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "frameworks") {
		t.Errorf("hint should suggest 'frameworks'; got:\n%s", stderr)
	}
	if exit := runCLI([]string{"list", "--rules-dir", "/x"}); exit != 2 {
		t.Errorf("flag-before-subject should exit 2; got %d", exit)
	}
}

// TestRunListFrameworks_BadFormat locks AC-05.
// @spec cli-list-frameworks
// @ac AC-07
func TestRunListFrameworks_BadFormat(t *testing.T) {
	t.Run("cli-list-frameworks/AC-07", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	exit := runCLI([]string{"list", "frameworks", "--rules-dir", dir, "--format", "yaml"})
	if exit != 2 {
		t.Errorf("bad --format should exit 2; got %d", exit)
	}
}

// TestRunListFrameworks_JSONShape locks AC-06: snake_case
// fields under a top-level `frameworks` envelope (so future
// fields can be added additively without breaking consumers).
// @spec cli-list-frameworks
// @ac AC-08
func TestRunListFrameworks_JSONShape(t *testing.T) {
	t.Run("cli-list-frameworks/AC-08", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"list", "frameworks", "--rules-dir", dir, "--format", "json"},
		t,
	)
	type envelope struct {
		Frameworks []struct {
			FrameworkID string `json:"framework_id"`
			Controls    int    `json:"controls"`
			Rules       int    `json:"rules"`
		} `json:"frameworks"`
	}
	var got envelope
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json unmarshal: %v\nstdout:\n%s", err, stdout)
	}
	if len(got.Frameworks) != 2 {
		t.Fatalf("expected 2 frameworks; got %d (%+v)", len(got.Frameworks), got)
	}
	// Snake_case sanity check on raw bytes.
	for _, want := range []string{`"framework_id":`, `"controls":`, `"rules":`, `"frameworks":`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("expected %q in JSON output:\n%s", want, stdout)
		}
	}
}

// TestRunListFrameworks_QuietSuppressesStdout locks --quiet
// behavior parity with other body-emitting subcommands.
// @spec cli-list-frameworks
// @ac AC-09
func TestRunListFrameworks_QuietSuppressesStdout(t *testing.T) {
	t.Run("cli-list-frameworks/AC-09", func(t *testing.T) {})
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"list", "frameworks", "--rules-dir", dir, "--quiet"},
		t,
	)
	if stdout != "" {
		t.Errorf("--quiet should produce empty stdout; got:\n%s", stdout)
	}
}

// TestRunListFrameworks_TextHasLegend locks the column header
// rewording + footer legend (peer review caught the misread
// where `nist_800_53 ... 516 rules` reads as "we have 516 NIST
// rules" rather than "516 corpus rules reference nist_800_53").
func TestRunListFrameworks_TextHasLegend(t *testing.T) {
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"list", "frameworks", "--rules-dir", dir},
		t,
	)
	// Column header reworded.
	if !strings.Contains(stdout, "rules ref'g") {
		t.Errorf("column header should say 'rules ref'g'; got:\n%s", stdout)
	}
	// Footer legend disambiguates the count.
	if !strings.Contains(stdout, "distinct rules in the corpus referencing") {
		t.Errorf("footer legend missing; got:\n%s", stdout)
	}
}
