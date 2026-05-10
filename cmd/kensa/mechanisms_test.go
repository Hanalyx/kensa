// Tests for the C-044 `kensa mechanisms` rename + `kensa coverage`
// deprecation alias.
package main

import (
	"strings"
	"testing"
)

// TestRunMechanisms_Basic locks AC-01 — the canonical name produces
// the mechanism listing on stdout and exits 0.
func TestRunMechanisms_Basic(t *testing.T) {
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
func TestRunMechanisms_NoWarning(t *testing.T) {
	_, stderr := captureRunCLI([]string{"mechanisms"}, t)
	for _, banned := range []string{"deprecated", "repurpose", "v0.2", "change meaning"} {
		if strings.Contains(stderr, banned) {
			t.Errorf("kensa mechanisms must not emit %q; got stderr:\n%s", banned, stderr)
		}
	}
}

// TestRunMechanisms_HelpExitsZero locks AC-07 — both --help forms
// exit 0 and print usage to stdout.
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

// TestRunCoverageDeprecated_StillWorks locks AC-02 — the deprecated
// alias produces the same listing as the canonical name during the
// deprecation window.
func TestRunCoverageDeprecated_StillWorks(t *testing.T) {
	mechStdout, _ := captureRunCLI([]string{"mechanisms"}, t)
	covStdout, _ := captureRunCLI([]string{"coverage"}, t)
	if mechStdout != covStdout {
		t.Errorf("coverage and mechanisms must produce identical stdout during the deprecation window\n  mechanisms:\n%s\n  coverage:\n%s",
			mechStdout, covStdout)
	}
}

// TestRunCoverageDeprecated_EmitsWarning locks AC-03 — the alias
// writes a warning to stderr that conveys (a) the v0.2 semantic
// flip ("change meaning" / "repurpose"), (b) the migration target
// ("mechanisms"), and (c) the version target ("v0.2"). The reword
// from "deprecated/removed" to "repurposed" matters: an operator
// reading "removed" mistakes a name-flip for a feature-gone, and
// fails to migrate before v0.2 produces silently-different output.
func TestRunCoverageDeprecated_EmitsWarning(t *testing.T) {
	_, stderr := captureRunCLI([]string{"coverage"}, t)
	if !strings.Contains(stderr, "v0.2") {
		t.Errorf("coverage warning should disclose v0.2 target; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "mechanisms") {
		t.Errorf("coverage warning should point at mechanisms; got:\n%s", stderr)
	}
	// The warning must convey semantic-flip — "change meaning"
	// is the primary phrase; we accept "repurpose" too so future
	// reword latitude doesn't break the contract.
	semFlipPhrases := []string{"change meaning", "repurpose"}
	hit := false
	for _, p := range semFlipPhrases {
		if strings.Contains(stderr, p) {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("coverage warning should convey semantic flip (one of %v); got:\n%s",
			semFlipPhrases, stderr)
	}
	// And it must NOT say "removed" — that's the misread we're
	// preventing.
	if strings.Contains(stderr, "removed") {
		t.Errorf("coverage warning must not say 'removed' (the name is being repurposed, not removed); got:\n%s", stderr)
	}
}

// TestRunCoverageDeprecated_EnvSuppresses locks AC-05 —
// KENSA_NO_REPURPOSE_WARNINGS=1 silences the repurpose warning.
// Note: this is a SEPARATE knob from KENSA_NO_DEPRECATION_WARNINGS
// (see TestRunCoverageDeprecated_DeprecationEnvDoesNotSilence).
func TestRunCoverageDeprecated_EnvSuppresses(t *testing.T) {
	t.Setenv("KENSA_NO_REPURPOSE_WARNINGS", "1")
	_, stderr := captureRunCLI([]string{"coverage"}, t)
	if strings.Contains(stderr, "v0.2") || strings.Contains(stderr, "mechanisms") {
		t.Errorf("KENSA_NO_REPURPOSE_WARNINGS=1 should silence the warning; got stderr:\n%s", stderr)
	}
}

// TestRunCoverageDeprecated_EnvOnlySilencesOnExactValue mirrors the
// existing flag-deprecation guarantee — only "1" silences; "true",
// "yes", etc., do NOT.
func TestRunCoverageDeprecated_EnvOnlySilencesOnExactValue(t *testing.T) {
	t.Setenv("KENSA_NO_REPURPOSE_WARNINGS", "true")
	_, stderr := captureRunCLI([]string{"coverage"}, t)
	if !strings.Contains(stderr, "v0.2") {
		t.Errorf("env=\"true\" should NOT silence; got:\n%s", stderr)
	}
}

// TestRunCoverageDeprecated_DeprecationEnvDoesNotSilence locks the
// two-knob contract: an operator who silenced flag warnings months
// ago (KENSA_NO_DEPRECATION_WARNINGS=1) MUST still see the louder
// repurpose warning. Coupling the two switches would auto-silence
// the semantic-flip signal, defeating its purpose.
func TestRunCoverageDeprecated_DeprecationEnvDoesNotSilence(t *testing.T) {
	t.Setenv("KENSA_NO_DEPRECATION_WARNINGS", "1")
	_, stderr := captureRunCLI([]string{"coverage"}, t)
	if !strings.Contains(stderr, "v0.2") {
		t.Errorf("KENSA_NO_DEPRECATION_WARNINGS=1 must NOT silence the repurpose warning; got:\n%s", stderr)
	}
}

// TestRunCoverageDeprecated_HelpAlsoDeprecation verifies that asking
// for help on the alias discloses the upcoming rename + repurpose
// in the help body itself — operators reading docs should see the
// planned semantic flip BEFORE the flag list.
func TestRunCoverageDeprecated_HelpAlsoDeprecation(t *testing.T) {
	stdout, _ := captureRunCLI([]string{"coverage", "--help"}, t)
	if !strings.Contains(stdout, "WARNING") {
		t.Errorf("kensa coverage --help should lead with WARNING; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "mechanisms") {
		t.Errorf("kensa coverage --help should point at mechanisms; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "v0.2") {
		t.Errorf("kensa coverage --help should disclose v0.2 target; got:\n%s", stdout)
	}
	// WARNING block must precede the Flags: list.
	warnIdx := strings.Index(stdout, "WARNING")
	flagsIdx := strings.Index(stdout, "Flags:")
	if warnIdx < 0 || flagsIdx < 0 || warnIdx >= flagsIdx {
		t.Errorf("WARNING block must precede 'Flags:' in help output; warn=%d flags=%d\n%s",
			warnIdx, flagsIdx, stdout)
	}
}

// TestPrintUsage_AdvertisesMechanisms locks AC-06 — top-level help
// lists mechanisms canonically and tags coverage with the v0.2
// repurpose disclosure.
func TestPrintUsage_AdvertisesMechanisms(t *testing.T) {
	stdout, _ := captureRunCLI([]string{"--help"}, t)
	if !strings.Contains(stdout, "mechanisms") {
		t.Errorf("kensa --help should list 'mechanisms'; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "coverage") {
		t.Errorf("kensa --help should still list 'coverage' (with v0.2 disclosure); got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "v0.2") {
		t.Errorf("kensa --help should disclose v0.2 repurposing for 'coverage'; got:\n%s", stdout)
	}
}
