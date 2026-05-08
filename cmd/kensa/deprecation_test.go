// Tests for the --format / --oscal deprecation warnings (C-020).
//
// Strategy: invoke runCLI with the deprecated flag set, capture
// stderr, assert the warning string appears. Contrast: invoke
// without the flag, assert the warning does NOT appear (so the
// warning fires only when explicitly set, not when the default
// fires).
package main

import (
	"os"
	"strings"
	"testing"
)

// TestDeprecation_FormatFlag_DetectFires asserts the warning
// emits when --format is explicitly passed to detect. Uses a bad
// host to fail fast (we don't need the SSH path; just need to
// reach warnDeprecatedFlag's call site, which is post-flag-parse
// and pre-transport-dial).
//
// The test passes "--format json" and a non-resolvable host; the
// SSH connect fails, but the deprecation warning fires before
// that error path.
func TestDeprecation_FormatFlag_DetectFires(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"detect", "--host", "127.0.0.1", "--port", "1", "--format", "json"},
		t,
	)
	if !strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("expected deprecation warning on stderr; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--output FORMAT[:PATH]") {
		t.Errorf("expected replacement guidance; got:\n%s", stderr)
	}
}

// TestDeprecation_FormatFlag_DetectQuiet asserts the warning STILL
// fires under --quiet. Per spec, --quiet silences stdout body
// output; deprecation warnings are stderr-bound diagnostics that
// operators must see during the deprecation window.
func TestDeprecation_FormatFlag_DetectQuiet(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"detect", "--host", "127.0.0.1", "--port", "1", "--format", "json", "--quiet"},
		t,
	)
	if !strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("--quiet must NOT silence deprecation warnings; got stderr:\n%s", stderr)
	}
}

// TestDeprecation_FormatFlag_DefaultDoesNotFire: when the operator
// does NOT pass --format, the default "table" fires but the
// warning must NOT emit. Catches a regression to "always-warn"
// which would spam every legacy script.
func TestDeprecation_FormatFlag_DefaultDoesNotFire(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"detect", "--host", "127.0.0.1", "--port", "1"},
		t,
	)
	if strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("--format default should not trigger deprecation warning; got stderr:\n%s", stderr)
	}
}

// TestDeprecation_FormatFlag_CheckFires: same coverage on check.
func TestDeprecation_FormatFlag_CheckFires(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"check", "--host", "127.0.0.1", "--port", "1", "--format", "json", "--rules-dir", t.TempDir()},
		t,
	)
	if !strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("expected deprecation warning on stderr; got:\n%s", stderr)
	}
}

// TestDeprecation_FormatFlag_RemediateFires: same coverage on remediate.
func TestDeprecation_FormatFlag_RemediateFires(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"remediate", "--host", "127.0.0.1", "--port", "1", "--format", "json", "--rules-dir", t.TempDir()},
		t,
	)
	if !strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("expected deprecation warning on stderr; got:\n%s", stderr)
	}
}

// TestDeprecation_OscalFlag_RemediateFires: --oscal joins
// --format's deprecation cycle (same v0.2 removal target).
func TestDeprecation_OscalFlag_RemediateFires(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"remediate", "--host", "127.0.0.1", "--port", "1", "--oscal", "/tmp/x.json", "--rules-dir", t.TempDir()},
		t,
	)
	if !strings.Contains(stderr, "--oscal is deprecated") {
		t.Errorf("expected --oscal deprecation warning; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--output oscal:PATH") {
		t.Errorf("expected --output oscal:PATH guidance; got:\n%s", stderr)
	}
}

// TestDeprecation_HistoryFormatDoesNotWarn: history's --format
// flag is NOT deprecated (history doesn't use -o because of the
// QueryResult-shape concern documented in C-013/C-016 reviews).
// Catches a regression where history accidentally inherits the
// warning.
func TestDeprecation_HistoryFormatDoesNotWarn(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"
	_, stderr := captureRunCLI(
		[]string{"--db", dbPath, "history", "--format", "json"},
		t,
	)
	if strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("history --format should not warn (no -o equivalent); got:\n%s", stderr)
	}
}

// TestDeprecation_PlanFormatDoesNotWarn: plan's --format is also
// not deprecated; engine.FormatPlan owns the format vocabulary
// for plan output.
func TestDeprecation_PlanFormatDoesNotWarn(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"
	_, stderr := captureRunCLI(
		[]string{"--db", dbPath, "plan", "--host", "127.0.0.1", "--port", "1", "--format", "json", "/nonexistent.yml"},
		t,
	)
	if strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("plan --format should not warn (engine-internal vocabulary); got:\n%s", stderr)
	}
}

// TestDeprecation_FormatFlag_ShortFormFires: -f (short form of
// --format) also triggers the warning. fs.Changed reports true
// for the long name regardless of whether the short or long form
// was used on argv.
func TestDeprecation_FormatFlag_ShortFormFires(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"detect", "--host", "127.0.0.1", "--port", "1", "-f", "json"},
		t,
	)
	if !strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("-f short form should trigger same warning as --format; got:\n%s", stderr)
	}
}

// TestDeprecation_V02RemovalMarker locks AC-08: the warning text
// includes the "will be removed in v0.2" string so operators see
// the concrete release where their script will break. Catches a
// regression that drops the marker (e.g., a future refactor that
// emits a generic "is deprecated" without the version target).
func TestDeprecation_V02RemovalMarker(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"detect", "--host", "127.0.0.1", "--port", "1", "--format", "json"},
		t,
	)
	if !strings.Contains(stderr, "will be removed in v0.2") {
		t.Errorf("warning missing v0.2 removal marker; got:\n%s", stderr)
	}
}

// TestDeprecation_ChangelogContent locks AC-09: CHANGELOG.md exists
// at the repo root with operator-facing migration content. Reads
// the file and asserts the deprecation section + both flag names +
// the replacement guidance + the v0.2 marker are all present.
//
// Without this test, a future PR could delete the deprecation
// section from CHANGELOG.md and ship without a CI signal.
func TestDeprecation_ChangelogContent(t *testing.T) {
	body, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v (run from repo root or adjust path)", err)
	}
	for _, want := range []string{
		"### Deprecated",
		"--format",
		"--oscal",
		"--output",
		"v0.2",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("CHANGELOG.md missing %q", want)
		}
	}
}

// TestDeprecation_EnvVarOptOut locks the
// KENSA_NO_DEPRECATION_WARNINGS=1 escape hatch. Operators who have
// planned the migration but can't migrate immediately set the env
// var to silence the warning without resorting to `2>/dev/null`
// (which would silence real errors too).
func TestDeprecation_EnvVarOptOut(t *testing.T) {
	t.Setenv("KENSA_NO_DEPRECATION_WARNINGS", "1")
	_, stderr := captureRunCLI(
		[]string{"detect", "--host", "127.0.0.1", "--port", "1", "--format", "json"},
		t,
	)
	if strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("KENSA_NO_DEPRECATION_WARNINGS=1 should silence the warning; got:\n%s", stderr)
	}
}

// TestDeprecation_EnvVarOnlySilencesOnExactValue confirms the
// env-var check is exact-match on "1" — accidental values like
// "true" or "yes" do NOT silence the warning. Conservative
// design: explicit opt-in only, so an env var leaked from a
// parent process can't silently disable the migration signal.
func TestDeprecation_EnvVarOnlySilencesOnExactValue(t *testing.T) {
	t.Setenv("KENSA_NO_DEPRECATION_WARNINGS", "true")
	_, stderr := captureRunCLI(
		[]string{"detect", "--host", "127.0.0.1", "--port", "1", "--format", "json"},
		t,
	)
	if !strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("KENSA_NO_DEPRECATION_WARNINGS=\"true\" should NOT silence (only \"1\" silences); got:\n%s", stderr)
	}
}

// TestDeprecation_FormatPlusOutputFlag confirms the warning still
// fires when `-o` is also set. -o doesn't accidentally suppress
// the deprecation signal (which would happen if a future refactor
// moved warnDeprecatedFlag inside the `len(outputs) == 0` branch).
func TestDeprecation_FormatPlusOutputFlag(t *testing.T) {
	_, stderr := captureRunCLI(
		[]string{"detect", "--host", "127.0.0.1", "--port", "1",
			"--format", "json", "-o", "text"},
		t,
	)
	if !strings.Contains(stderr, "--format is deprecated") {
		t.Errorf("warning should fire even when -o is also set; got:\n%s", stderr)
	}
}
