// Tests for the C-044 `kensa mechanisms` rename + `kensa coverage`
// deprecation alias.
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
// @ac AC-02
func TestRunMechanisms_NoWarning(t *testing.T) {
	t.Run("cli-coverage-mechanisms-rename/AC-02", func(t *testing.T) {})
	_, stderr := captureRunCLI([]string{"mechanisms"}, t)
	for _, banned := range []string{"deprecated", "repurpose", "v0.2", "change meaning"} {
		if strings.Contains(stderr, banned) {
			t.Errorf("kensa mechanisms must not emit %q; got stderr:\n%s", banned, stderr)
		}
	}
}

// TestRunMechanisms_HelpExitsZero locks AC-07 — both --help forms
// exit 0 and print usage to stdout.
// @spec cli-coverage-mechanisms-rename
// @ac AC-03
func TestRunMechanisms_HelpExitsZero(t *testing.T) {
	t.Run("cli-coverage-mechanisms-rename/AC-03", func(t *testing.T) {})
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

// TestRunCoverageDeprecated_EnvSuppresses locks AC-05 —
// KENSA_NO_REPURPOSE_WARNINGS=1 silences the repurpose warning.
// Note: this is a SEPARATE knob from KENSA_NO_DEPRECATION_WARNINGS
// (see TestRunCoverageDeprecated_DeprecationEnvDoesNotSilence).
// @spec cli-coverage-mechanisms-rename
// @ac AC-06
func TestRunCoverageDeprecated_EnvSuppresses(t *testing.T) {
	t.Run("cli-coverage-mechanisms-rename/AC-06", func(t *testing.T) {})
	t.Setenv("KENSA_NO_REPURPOSE_WARNINGS", "1")
	_, stderr := captureRunCLI([]string{"coverage"}, t)
	if strings.Contains(stderr, "v0.2") || strings.Contains(stderr, "mechanisms") {
		t.Errorf("KENSA_NO_REPURPOSE_WARNINGS=1 should silence the warning; got stderr:\n%s", stderr)
	}
}
