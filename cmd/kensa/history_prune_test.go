// Tests for the C-043 `kensa history --prune` workflow.
package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/store"
)

// makeStoreFile returns a fresh temp DB path and ensures the store
// migration has run (so the schema exists for runHistoryPrune's
// PruneSessions call). Returns the path.
func makeStoreFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = s.Close()
	return path
}

// TestRunHistoryPrune_RejectsNonPositiveDays locks AC-07.
// @spec cli-history-prune
// @ac AC-01
func TestRunHistoryPrune_RejectsNonPositiveDays(t *testing.T) {
	t.Run("cli-history-prune/AC-01", func(t *testing.T) {})
	path := makeStoreFile(t)

	for _, days := range []int{0, -1, -7} {
		err := runHistoryPrune(context.Background(), path, days, true /* force */, true /* quiet */, nil, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil {
			t.Errorf("--prune %d should error", days)
			continue
		}
		if !IsUsageError(err) {
			t.Errorf("--prune %d should be UsageError; got %v", days, err)
		}
		if !strings.Contains(err.Error(), "positive integer") {
			t.Errorf("error message should mention 'positive integer'; got %q", err.Error())
		}
	}
}

// TestRunHistoryPrune_RejectsTooManyDays locks the typo-protection
// upper bound (pruneDaysMax = 100 years), well below the
// time.Duration overflow boundary.
// @spec cli-history-prune
// @ac AC-02
func TestRunHistoryPrune_RejectsTooManyDays(t *testing.T) {
	t.Run("cli-history-prune/AC-02", func(t *testing.T) {})
	path := makeStoreFile(t)
	// pruneDaysMax+1 must reject; far above is the realistic
	// typo case ("100000" instead of "10000").
	for _, days := range []int{pruneDaysMax + 1, 100000, 1 << 30} {
		err := runHistoryPrune(context.Background(), path, days, true, true, nil, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil {
			t.Errorf("--prune %d should error", days)
			continue
		}
		if !IsUsageError(err) {
			t.Errorf("--prune %d should be UsageError; got %v", days, err)
		}
		if !strings.Contains(err.Error(), "typo") {
			t.Errorf("error should mention 'typo'; got %q", err.Error())
		}
	}
}

// TestRunHistoryPrune_NonTTYWithoutForce locks AC-08.
// @spec cli-history-prune
// @ac AC-03
func TestRunHistoryPrune_NonTTYWithoutForce(t *testing.T) {
	t.Run("cli-history-prune/AC-03", func(t *testing.T) {})
	path := makeStoreFile(t)
	// stdin is a *bytes.Buffer, not *os.File — IsTerminal returns false.
	stdin := bytes.NewBufferString("")
	err := runHistoryPrune(context.Background(), path, 7, false, true, stdin, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("non-TTY without --force should error")
	}
	if !IsUsageError(err) {
		t.Errorf("expected UsageError; got %v", err)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error should direct operator to --force; got %q", err.Error())
	}
}

// TestRunHistoryPrune_ForceBypassesPrompt locks the happy-path with
// --force on an empty store.
// @spec cli-history-prune
// @ac AC-04
func TestRunHistoryPrune_ForceBypassesPrompt(t *testing.T) {
	t.Run("cli-history-prune/AC-04", func(t *testing.T) {})
	path := makeStoreFile(t)
	var stdout, stderr bytes.Buffer
	err := runHistoryPrune(context.Background(), path, 7, true, false, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("force prune on empty store: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("prune should not write to stdout; got %q", stdout.String())
	}
	out := stderr.String()
	for _, want := range []string{
		"kensa history --prune 7",
		"sessions:",
		"transactions:",
		"steps:",
		"pre_states:",
		"framework_refs:",
		"rollback_evts:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in stderr summary:\n%s", want, out)
		}
	}
}

// TestRunHistoryPrune_QuietStillEmitsAuditSummary documents that the
// audit summary goes to stderr regardless of --quiet (destructive
// op needs a trail visible to the operator).
// @spec cli-history-prune
// @ac AC-05
func TestRunHistoryPrune_QuietStillEmitsAuditSummary(t *testing.T) {
	t.Run("cli-history-prune/AC-05", func(t *testing.T) {})
	path := makeStoreFile(t)
	var stdout, stderr bytes.Buffer
	err := runHistoryPrune(context.Background(), path, 7, true, true, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("force prune: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("--quiet must keep stdout silent; got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "kensa history --prune 7") {
		t.Errorf("audit summary should print to stderr even with --quiet; got %q", stderr.String())
	}
}

// TestConfirmedYes locks the parser for the TTY confirmation gate.
// The confirmedYes helper requires a trailing newline so Ctrl-D
// mid-input (EOF after typing "y" without Enter) does NOT confirm.
// @spec cli-history-prune
// @ac AC-06
func TestConfirmedYes(t *testing.T) {
	t.Run("cli-history-prune/AC-06", func(t *testing.T) {})
	cases := map[string]bool{
		"y\n":   true,
		"Y\n":   true,
		"yes\n": true,
		"YES\n": true,
		"  y\n": true,
		"":      false,
		"y":     false, // no newline = Ctrl-D mid-input, NOT confirmed
		"yes":   false, // no newline = Ctrl-D mid-input, NOT confirmed
		"n\n":   false,
		"no\n":  false,
		"  \n":  false,
		"yo\n":  false,
	}
	for in, want := range cases {
		if got := confirmedYes(in); got != want {
			t.Errorf("confirmedYes(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestRunHistory_PruneInvalidDays drives runHistory through runCLI to
// confirm the dispatch routes flag-validation errors out as usage
// errors (exit code 2). Re-locks AC-07 at the dispatch boundary.
// @spec cli-history-prune
// @ac AC-07
func TestRunHistory_PruneInvalidDays(t *testing.T) {
	t.Run("cli-history-prune/AC-07", func(t *testing.T) {})
	path := makeStoreFile(t)
	for _, days := range []string{"0", "-1"} {
		argv := []string{"--db", path, "history", "--prune", days, "--force"}
		got := runCLI(argv)
		if got != 2 {
			t.Errorf("runCLI(--prune %s) = %d, want 2", days, got)
		}
	}
}

// TestRunHistory_PruneNonNumericDays verifies pflag's own type
// validation kicks in before our positive-integer check, also exit 2.
// @spec cli-history-prune
// @ac AC-08
func TestRunHistory_PruneNonNumericDays(t *testing.T) {
	t.Run("cli-history-prune/AC-08", func(t *testing.T) {})
	path := makeStoreFile(t)
	argv := []string{"--db", path, "history", "--prune", "abc", "--force"}
	got := runCLI(argv)
	if got != 2 {
		t.Errorf("runCLI(--prune abc) = %d, want 2", got)
	}
}

// TestRunHistory_PruneMutualExclusion locks AC-09 — combining --prune
// with any of the query flags is a usage error.
// @spec cli-history-prune
// @ac AC-09
func TestRunHistory_PruneMutualExclusion(t *testing.T) {
	t.Run("cli-history-prune/AC-09", func(t *testing.T) {})
	path := makeStoreFile(t)
	cases := [][]string{
		{"history", "--prune", "7", "--force", "--stats"},
		{"history", "--prune", "7", "--force", "--aggregate", "by_host"},
		{"history", "--prune", "7", "--force", "--txn", "8c3a1e2b-9999-4444-aaaa-bbbbccccdddd"},
		{"history", "--prune", "7", "--force", "-H", "host-x"},
		{"history", "--prune", "7", "--force", "-R", "rule-y"},
		{"history", "--prune", "7", "--force", "-S", "24h"},
		{"history", "--prune", "7", "--force", "-n", "10"},
		{"history", "--prune", "7", "--force", "--format", "json"},
	}
	for _, args := range cases {
		argv := append([]string{"--db", path}, args...)
		got := runCLI(argv)
		if got != 2 {
			t.Errorf("runCLI(%v) = %d, want 2", args, got)
		}
	}
}

// TestRunHistory_ForceWithoutPruneRejected verifies --force without
// --prune is a usage error (operator-confused-intent guard).
// @spec cli-history-prune
// @ac AC-10
func TestRunHistory_ForceWithoutPruneRejected(t *testing.T) {
	t.Run("cli-history-prune/AC-10", func(t *testing.T) {})
	path := makeStoreFile(t)
	argv := []string{"--db", path, "history", "--force"}
	got := runCLI(argv)
	if got != 2 {
		t.Errorf("runCLI(--force) = %d, want 2", got)
	}
}
