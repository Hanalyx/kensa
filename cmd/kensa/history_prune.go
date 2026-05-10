package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Hanalyx/kensa-go/internal/store"
)

// pruneDaysMax bounds the --prune DAYS argument at 100 years.
// Far past any realistic retention horizon, but far below the
// time.Duration overflow boundary (~106751 days). The point is
// catching operator typos (`--prune 100000` for "10000") before
// the cutoff arithmetic produces a meaningless past-time.
const pruneDaysMax = 36500

// runHistoryPrune executes the C-043 destructive-cleanup path
// for `kensa history --prune DAYS`. Long-only flag (no short
// letter): destructive workflow demands the operator type the
// long form. --force bypasses the TTY confirmation; without
// --force on a non-TTY stdin the command errors out (silent
// default-yes would be unsafe in CI; silent default-no would
// make the flag useless in cron).
//
// Validation runs before the store is opened so failure-modes
// like `--prune 0` cost nothing.
//
// The prune summary is written to stderr regardless of --quiet:
// destructive operations need an audit trail visible to the
// operator even when they redirected stdout. (--quiet's contract
// is "no default human output," not "swallow audit-relevant
// telemetry.")
func runHistoryPrune(
	ctx context.Context,
	dbPath string,
	days int,
	force bool,
	quiet bool,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) error {
	_ = stdout // reserved for future structured-output paths; today the report goes to stderr
	if days <= 0 {
		return NewUsageError(fmt.Sprintf("--prune DAYS must be a positive integer (got %d)", days))
	}
	if days > pruneDaysMax {
		return NewUsageError(fmt.Sprintf("--prune DAYS must be ≤ %d (got %d); is this a typo?", pruneDaysMax, days))
	}

	if !force {
		// TTY-confirmation gate. The operator MUST acknowledge
		// the destructive action interactively. Non-TTY stdin
		// cannot prompt; tell the operator how to proceed.
		stdinFile, _ := stdin.(*os.File)
		if stdinFile == nil || !term.IsTerminal(int(stdinFile.Fd())) {
			return NewUsageError("--prune is destructive; pass --force to confirm in non-interactive runs")
		}
		fmt.Fprintf(stderr,
			"This will delete sessions older than %d day(s) and cascade through transactions, steps, pre_states, framework_refs, rollback_events.\n",
			days)
		fmt.Fprint(stderr, "Proceed? [y/N]: ")
		reader := bufio.NewReader(stdin)
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("read confirmation: %w", err)
		}
		// confirmedYes requires a trailing newline. EOF before
		// newline (Ctrl-D after typing "y") is treated as not-
		// confirmed: the operator's input is truncated and we
		// won't proceed with a destructive op on partial input.
		if err == io.EOF || !confirmedYes(line) {
			return NewUsageError("aborted: confirmation not received")
		}
	}

	// time.Now().AddDate(0, 0, -days) uses calendar arithmetic
	// and avoids the time.Duration multiplication that overflows
	// int64 nanoseconds for very large day counts.
	cutoff := time.Now().AddDate(0, 0, -days)

	s, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	report, err := s.PruneSessions(ctx, cutoff)
	if err != nil {
		return fmt.Errorf("prune: %w", err)
	}

	// Audit trail goes to stderr regardless of --quiet. Per
	// C-018 convention "warnings still go to stderr"; for a
	// destructive op, the operator MUST be able to see what
	// got deleted even when stdout is redirected or silenced.
	_ = quiet
	writePruneReport(stderr, report, days)
	return nil
}

// confirmedYes returns true iff the operator typed "y" or
// "yes" (case-insensitive) AND pressed Enter. Empty / "n" /
// anything else is treated as "no" — the safe default for a
// destructive op. Requires a trailing newline so Ctrl-D (EOF)
// after a partial token does NOT confirm: the caller has also
// already gated on err == io.EOF and treats EOF as not-
// confirmed, but defense-in-depth is cheap.
func confirmedYes(line string) bool {
	if !strings.HasSuffix(line, "\n") {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(line))
	return v == "y" || v == "yes"
}

// writePruneReport renders the C-043 prune summary. The
// "transactions: N (orphans: M)" line discloses how many of
// the deleted transactions were pre-Phase-4 NULL-session
// orphans — operator-auditable telemetry per spec C-04.
func writePruneReport(w io.Writer, r store.PruneReport, days int) {
	fmt.Fprintf(w, "kensa history --prune %d\n", days)
	fmt.Fprintf(w, "  sessions:       %d\n", r.SessionsDeleted)
	if r.OrphanTransactionsDeleted > 0 {
		fmt.Fprintf(w, "  transactions:   %d (orphans: %d)\n", r.TransactionsDeleted, r.OrphanTransactionsDeleted)
	} else {
		fmt.Fprintf(w, "  transactions:   %d\n", r.TransactionsDeleted)
	}
	fmt.Fprintf(w, "  steps:          %d\n", r.StepsDeleted)
	fmt.Fprintf(w, "  pre_states:     %d\n", r.PreStatesDeleted)
	fmt.Fprintf(w, "  framework_refs: %d\n", r.FrameworkRefsDeleted)
	fmt.Fprintf(w, "  rollback_evts:  %d\n", r.RollbackEventsDeleted)
}
