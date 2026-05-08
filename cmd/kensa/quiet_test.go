// Tests for the --quiet / -q flag (deliverable C-018).
//
// The flag is plumbed through every subcommand that produces a
// default human-readable result body (detect, check, remediate,
// rollback, history, plan). When --quiet is set, the body bytes
// land on io.Discard rather than os.Stdout; errors and warnings
// continue to emit on os.Stderr.
//
// These tests focus on the dispatch wiring (bodyOut helper, flag
// parsing) since the SSH-dependent subcommand code paths require
// a transport mock to test end-to-end.
package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestBodyOut covers the helper directly: when quiet is true, returns
// io.Discard; when false, returns os.Stdout. Locks the contract
// against a future refactor that might invert the bool or return a
// nil writer.
func TestBodyOut(t *testing.T) {
	if got := bodyOut(false); got != os.Stdout {
		t.Errorf("bodyOut(false) = %v, want os.Stdout", got)
	}
	if got := bodyOut(true); got != io.Discard {
		t.Errorf("bodyOut(true) = %v, want io.Discard", got)
	}
}

// TestBodyOut_QuietActuallyDiscards confirms the io.Discard path
// silently consumes any bytes written to it without erroring (the
// stdlib contract). If a future refactor swapped io.Discard for a
// nil writer, the WriteX call sites would panic on first byte.
func TestBodyOut_QuietActuallyDiscards(t *testing.T) {
	w := bodyOut(true)
	n, err := w.Write([]byte("any number of bytes"))
	if err != nil {
		t.Errorf("io.Discard returned error: %v", err)
	}
	if n != len("any number of bytes") {
		t.Errorf("io.Discard accepted %d bytes, want %d", n, len("any number of bytes"))
	}
}

// TestQuietFlag_DetectHelp confirms --quiet appears in detect's --help
// output. (We can't easily exercise the SSH path; help output is the
// proxy for "the flag was registered.")
func TestQuietFlag_DetectHelp(t *testing.T) {
	requireFlagInHelp(t, "detect", []string{"--quiet", "-q"})
}

func TestQuietFlag_CheckHelp(t *testing.T) {
	requireFlagInHelp(t, "check", []string{"--quiet", "-q"})
}

func TestQuietFlag_RemediateHelp(t *testing.T) {
	requireFlagInHelp(t, "remediate", []string{"--quiet", "-q"})
}

func TestQuietFlag_RollbackHelp(t *testing.T) {
	requireFlagInHelp(t, "rollback", []string{"--quiet", "-q"})
}

func TestQuietFlag_HistoryHelp(t *testing.T) {
	requireFlagInHelp(t, "history", []string{"--quiet", "-q"})
}

func TestQuietFlag_PlanHelp(t *testing.T) {
	requireFlagInHelp(t, "plan", []string{"--quiet", "-q"})
}

// TestQuietFlag_NotInVersion: --quiet should NOT be on `version` —
// the operator explicitly asked for the version banner; suppressing
// it would be surprising.
func TestQuietFlag_NotInVersion(t *testing.T) {
	stdout, _ := captureRunCLI([]string{"version", "--help"}, t)
	if strings.Contains(stdout, "--quiet") || strings.Contains(stdout, "-q ") {
		t.Errorf("kensa version --help should not advertise --quiet; got:\n%s", stdout)
	}
}

// TestQuietFlag_NotInCoverage: same reasoning as version.
func TestQuietFlag_NotInCoverage(t *testing.T) {
	stdout, _ := captureRunCLI([]string{"coverage", "--help"}, t)
	if strings.Contains(stdout, "--quiet") || strings.Contains(stdout, "-q ") {
		t.Errorf("kensa coverage --help should not advertise --quiet; got:\n%s", stdout)
	}
}

// TestQuietFlag_BadValueRejected: --quiet takes no value; passing
// `--quiet=garbage` should fail at parse time (pflag handles this
// for bool flags). Catches a regression to a string-typed quiet flag.
func TestQuietFlag_BadValueRejected(t *testing.T) {
	exit := runCLI([]string{"detect", "--host", "h", "--quiet=garbage"})
	if exit != 2 {
		t.Errorf("--quiet=garbage should produce exit 2 (usage error); got %d", exit)
	}
}

// TestQuiet_HistoryProducesEmptyStdout is the end-to-end lock for
// AC-07: when --quiet is set, the body-emitting subcommand produces
// zero bytes on stdout. We use `kensa history` because it requires
// only a SQLite store (no SSH transport), so it's the only body-
// emitting subcommand we can exercise in a unit test today.
//
// The test creates an empty store via runCLI's --db flag and runs
// `history --quiet`. The store has zero rows, but with --quiet the
// "0 of 0 transactions shown" trailer is also suppressed (it goes
// through bodyOut for the text writer path). End-to-end stdout
// must be empty.
//
// Without this test, AC-07 is verified only by code inspection
// plus manual host runs — not enough to catch a refactor that
// silently routes a WriteX call through os.Stdout instead of
// bodyOut.
func TestQuiet_HistoryProducesEmptyStdout(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"
	stdout, _ := captureRunCLI(
		[]string{"--db", dbPath, "history", "--quiet"},
		t,
	)
	if stdout != "" {
		t.Errorf("history --quiet produced %d bytes on stdout (want empty):\n%q",
			len(stdout), stdout)
	}
}

// TestQuiet_HistoryWithoutQuietProducesOutput is the contrast: same
// invocation without --quiet produces the trailer line. Confirms
// the test above isn't trivially passing because history-against-
// empty-db produces no output anyway.
func TestQuiet_HistoryWithoutQuietProducesOutput(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"
	stdout, _ := captureRunCLI(
		[]string{"--db", dbPath, "history"},
		t,
	)
	if stdout == "" {
		t.Error("history without --quiet should produce output (trailer line at minimum); got empty")
	}
}

// TestShortLetterTable_QuietRegistered locks ShortQuiet's value; a
// future move from "q" to a different letter requires updating both
// the constant and this test (and would be a breaking change for any
// operator with -q in their scripts).
func TestShortLetterTable_QuietRegistered(t *testing.T) {
	if ShortQuiet != "q" {
		t.Errorf("ShortQuiet = %q, want \"q\" (GNU/POSIX convention)", ShortQuiet)
	}
}

// requireFlagInHelp invokes `kensa <cmd> --help` and asserts that
// each token in `wantTokens` appears in stdout. Used to verify a
// flag was registered without exercising its runtime behavior.
func requireFlagInHelp(t *testing.T, cmd string, wantTokens []string) {
	t.Helper()
	stdout, _ := captureRunCLI([]string{cmd, "--help"}, t)
	for _, tok := range wantTokens {
		if !strings.Contains(stdout, tok) {
			t.Errorf("kensa %s --help missing %q; got:\n%s", cmd, tok, stdout)
		}
	}
}

// captureRunCLI runs the CLI dispatcher with the given argv and
// returns the captured stdout. stderr is consumed but not returned
// (callers can extend if needed). The actual exit code is dropped —
// this helper exists to inspect output, not to assert on exit.
func captureRunCLI(argv []string, t *testing.T) (stdout, stderr string) {
	t.Helper()
	oldOut := os.Stdout
	oldErr := os.Stderr

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	done := make(chan struct{})
	var outBuf, errBuf bytes.Buffer
	go func() {
		_, _ = outBuf.ReadFrom(rOut)
		_, _ = errBuf.ReadFrom(rErr)
		close(done)
	}()

	_ = runCLI(argv)
	_ = wOut.Close()
	_ = wErr.Close()
	<-done

	os.Stdout = oldOut
	os.Stderr = oldErr
	return outBuf.String(), errBuf.String()
}
