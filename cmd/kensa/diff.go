package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/internal/diff"
	"github.com/Hanalyx/kensa-go/internal/output"
	"github.com/Hanalyx/kensa-go/internal/store"
)

// runDiff handles `kensa diff SESSION1 SESSION2 [flags]` (C-048).
// Compares two stored sessions and emits the per-rule drift
// report. The two positional UUID args are required; flags
// govern presentation.
//
// Exit-code contract:
//   - bad invocation                → 2 (UsageError)
//   - either session not found      → 1 (runtime; mirrors C-047 ErrNotFound)
//   - success                       → 0
func runDiff(ctx context.Context, dbPath string, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"format": true, "show-unchanged": true,
	})

	fs := pflag.NewFlagSet("diff", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp      bool
		format        string
		showUnchanged bool
		quiet         bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text or json")
	fs.BoolVar(&showUnchanged, "show-unchanged", false, "include rules whose status is identical between the two sessions")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printDiffUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa diff --help'", err)
	}
	if showHelp {
		printDiffUsage(os.Stdout, fs)
		return nil
	}

	switch format {
	case "text", "json":
	default:
		return NewUsageError(fmt.Sprintf("--format %q: must be 'text' or 'json'", format))
	}

	posArgs := fs.Args()
	if len(posArgs) != 2 {
		return NewUsageError(fmt.Sprintf(
			"kensa diff requires exactly 2 positional session UUID arguments (got %d)", len(posArgs)))
	}

	id1, err := uuid.Parse(posArgs[0])
	if err != nil {
		return WrapUsageError(fmt.Sprintf("first SESSION_ID %q", posArgs[0]), err)
	}
	id2, err := uuid.Parse(posArgs[1])
	if err != nil {
		return WrapUsageError(fmt.Sprintf("second SESSION_ID %q", posArgs[1]), err)
	}

	s, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	sess1, err := s.GetSession(ctx, id1)
	if err != nil {
		return cleanSessionLookupError(id1, err)
	}
	sess2, err := s.GetSession(ctx, id2)
	if err != nil {
		return cleanSessionLookupError(id2, err)
	}

	txns1, err := s.TransactionsForSession(ctx, id1)
	if err != nil {
		return fmt.Errorf("load transactions for %s: %w", id1, err)
	}
	txns2, err := s.TransactionsForSession(ctx, id2)
	if err != nil {
		return fmt.Errorf("load transactions for %s: %w", id2, err)
	}

	added, removed, changed, unchanged := diff.ComputeSessionDiff(txns1, txns2)
	// JSON shape is always populated; --show-unchanged governs
	// only text rendering. Initialize empty slices (not nil) so
	// JSON consumers always see arrays.
	if added == nil {
		added = []diff.RuleChange{}
	}
	if removed == nil {
		removed = []diff.RuleChange{}
	}
	if changed == nil {
		changed = []diff.RuleChange{}
	}
	if unchanged == nil {
		unchanged = []diff.RuleChange{}
	}
	report := diff.SessionDiff{
		SessionIDFrom: sess1.ID.String(),
		SessionIDTo:   sess2.ID.String(),
		HostnameFrom:  sess1.Hostname,
		HostnameTo:    sess2.Hostname,
		Added:         added,
		Removed:       removed,
		Changed:       changed,
		Unchanged:     unchanged,
	}

	// Cross-hostname note (C-05): informational, not an error.
	// Goes to stderr so the JSON output (or piped text) isn't
	// corrupted. Empty hostnames (legacy backfill / inventory
	// mode) are NOT flagged — only mismatch when both sides
	// have a real hostname.
	if sess1.Hostname != "" && sess2.Hostname != "" && sess1.Hostname != sess2.Hostname {
		fmt.Fprintf(os.Stderr,
			"kensa diff: note: comparing across hostnames %q → %q (different hosts)\n",
			sess1.Hostname, sess2.Hostname)
	}

	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		return jw.WriteJSONValue(out, report)
	}
	writeDiffText(out, &report, showUnchanged)
	return nil
}

// writeDiffText renders the operator-facing drift report.
// Sections are emitted in fixed order (Changed first since
// that's the most-actionable signal, then Added, Removed,
// Unchanged when --show-unchanged). Each section is omitted
// when empty so the output stays tight on small diffs.
func writeDiffText(w io.Writer, r *diff.SessionDiff, showUnchanged bool) {
	fmt.Fprintln(w, "kensa diff")
	if r.HostnameFrom != "" || r.HostnameTo != "" {
		fmt.Fprintf(w, "  from: %s on %s\n", r.SessionIDFrom, hostOrUnknown(r.HostnameFrom))
		fmt.Fprintf(w, "  to:   %s on %s\n", r.SessionIDTo, hostOrUnknown(r.HostnameTo))
	} else {
		fmt.Fprintf(w, "  from: %s\n", r.SessionIDFrom)
		fmt.Fprintf(w, "  to:   %s\n", r.SessionIDTo)
	}
	fmt.Fprintf(w, "  changed:   %d\n", len(r.Changed))
	fmt.Fprintf(w, "  added:     %d\n", len(r.Added))
	fmt.Fprintf(w, "  removed:   %d\n", len(r.Removed))
	if showUnchanged {
		fmt.Fprintf(w, "  unchanged: %d\n", len(r.Unchanged))
	}

	if len(r.Changed) > 0 {
		fmt.Fprintln(w, "\n  changed (RULE_ID    BEFORE -> AFTER):")
		for _, c := range r.Changed {
			fmt.Fprintf(w, "    %s    %s -> %s\n", c.RuleID, c.FromStatus, c.ToStatus)
		}
	}
	if len(r.Added) > 0 {
		fmt.Fprintln(w, "\n  added:")
		for _, c := range r.Added {
			fmt.Fprintf(w, "    %s    %s\n", c.RuleID, c.ToStatus)
		}
	}
	if len(r.Removed) > 0 {
		fmt.Fprintln(w, "\n  removed:")
		for _, c := range r.Removed {
			fmt.Fprintf(w, "    %s    %s\n", c.RuleID, c.FromStatus)
		}
	}
	if showUnchanged && len(r.Unchanged) > 0 {
		fmt.Fprintln(w, "\n  unchanged:")
		for _, c := range r.Unchanged {
			fmt.Fprintf(w, "    %s    %s\n", c.RuleID, c.FromStatus)
		}
	}
}

// cleanSessionLookupError replaces the noisy GetSession-via-
// sql.ErrNoRows wrap with an operator-actionable message
// pointing at `kensa list sessions`. Peer review caught the
// leak: the raw error reads "store: GetSession: sql: no rows
// in result set" — internals an operator shouldn't have to
// parse to know "I typed a session ID that isn't in the
// store".
func cleanSessionLookupError(id uuid.UUID, err error) error {
	// store.GetSession wraps sql.ErrNoRows; either match works
	// today, but errors.Is(err, sql.ErrNoRows) is the durable
	// invariant.
	if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "no rows") {
		return fmt.Errorf("session %s not found in store (try 'kensa list sessions' to find candidate IDs)", id)
	}
	return fmt.Errorf("session %s: %w", id, err)
}

// hostOrUnknown returns the hostname or "(unknown)" when
// empty. Empty hostname appears for legacy-backfill sessions
// (per C-040 BackfillSessions), so the placeholder makes the
// session header readable without forcing the operator to
// trace why a string is blank.
func hostOrUnknown(h string) string {
	if h == "" {
		return "(unknown)"
	}
	return h
}

func printDiffUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa diff SESSION_ID_1 SESSION_ID_2 [flags]

Compare two stored sessions and emit the per-rule drift report:
status changes, rules added (in SESSION_ID_2 only), and rules
removed (in SESSION_ID_1 only). Pass --show-unchanged to also
list rules whose status is identical between the two sessions.

The "from" → "to" direction follows git diff convention:
SESSION_ID_1 is the earlier ("before") snapshot; SESSION_ID_2
is the later ("after"). Reversing the args inverts the report.

Comparing across hostnames is allowed (a stderr note discloses
the cross-host scope). To find candidate session IDs run:

  kensa list sessions

Flags:
%s
Examples:
  kensa list sessions                          # find session IDs first
  kensa diff <id1> <id2>                       # compact drift report
  kensa diff <id1> <id2> --show-unchanged      # include rules with no status change
  kensa diff <id1> <id2> --format json         # programmatic output
`, fs.FlagUsages())
}
