// Tests for `kensa mechanisms`.
//
// `coverage` was an alias for this command while the two were being
// separated. It is not one now: it reports framework coverage, and its tests
// live in coverage_report_test.go and coverage_finalization_test.go.
package main

import (
	"strings"
	"testing"
)

// TestRunMechanisms_Basic locks AC-01 — the canonical name produces
// the mechanism listing on stdout and exits 0.
// @spec cli-coverage-mechanisms-rename
// @ac AC-01
func TestRunMechanisms_Basic(t *testing.T) {
	t.Run("cli-coverage-mechanisms-rename/AC-01", func(t *testing.T) {})
	stdout, _ := captureRunCLI([]string{"mechanisms"}, t)
	if !strings.Contains(stdout, "Registered mechanisms") {
		t.Errorf("missing header in stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "file_permissions") {
		t.Errorf("expected file_permissions in listing:\n%s", stdout)
	}
}

// TestRunMechanisms_NoWarning locks AC-04 — the canonical name does
// NOT emit a repurpose / deprecation warning. Both substrings are
// checked because the warning text uses "repurpose" and we want to
// also catch any future regression that adds a "deprecated" notice.
// @spec cli-coverage-mechanisms-rename
// @ac AC-04
func TestRunMechanisms_NoWarning(t *testing.T) {
	t.Run("cli-coverage-mechanisms-rename/AC-04", func(t *testing.T) {})
	_, stderr := captureRunCLI([]string{"mechanisms"}, t)
	for _, banned := range []string{"deprecated", "repurpose", "v0.2", "change meaning"} {
		if strings.Contains(stderr, banned) {
			t.Errorf("kensa mechanisms must not emit %q; got stderr:\n%s", banned, stderr)
		}
	}
}

// TestRunMechanisms_HelpExitsZero checks both --help forms exit 0 and print
// usage to stdout.
//
// It carries no mapping: the historical AC-07 required BOTH subcommands to do
// this, and this exercises one. Coverage's side is
// cli-coverage-command-finalization AC-02. Kept as a unit regression.
func TestRunMechanisms_HelpExitsZero(t *testing.T) {
	for _, argv := range [][]string{
		{"mechanisms", "--help"},
		{"mechanisms", "-h"},
	} {
		got := runCLI(argv)
		if got != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, got)
		}
	}
}
