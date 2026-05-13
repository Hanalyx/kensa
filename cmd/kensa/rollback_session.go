package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/output"
	"github.com/Hanalyx/kensa-go/internal/store"
	"github.com/Hanalyx/kensa-go/pkg/kensa"
)

// runRollbackList implements `kensa rollback --list` (C-049):
// surfaces sessions whose committed-transaction count is > 0.
// Read-only — does not require --host or any transport flags.
//
// `--detail` adds the per-rule rule_id + status breakdown for
// each session inline, which gets verbose on large fleets but
// is the right shape for "I want to see exactly what would
// revert" audits.
func runRollbackList(ctx context.Context, dbPath string, detail bool, format string, quiet bool) error {
	s, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	sessions, err := s.RollbackableSessions(ctx, 0)
	if err != nil {
		return err
	}

	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		envelope := struct {
			Sessions []listSessionRow `json:"sessions"`
		}{Sessions: toListSessionRows(ctx, s, sessions, detail)}
		return jw.WriteJSONValue(out, envelope)
	}
	writeRollbackListText(ctx, s, out, sessions, detail)
	return nil
}

// listSessionRow is the JSON shape for `--list`. When detail
// is set, Transactions is populated; otherwise it's omitted.
type listSessionRow struct {
	ID           string              `json:"id"`
	StartedAt    string              `json:"started_at"`
	Hostname     string              `json:"hostname"`
	Subcommand   string              `json:"subcommand"`
	TxnCommitted int                 `json:"txn_committed"`
	TxnTotal     int                 `json:"txn_total"`
	Transactions []listSessionRowTxn `json:"transactions,omitempty"`
}

type listSessionRowTxn struct {
	RuleID string `json:"rule_id"`
	Status string `json:"status"`
}

func toListSessionRows(ctx context.Context, s *store.SQLite, sessions []*store.Session, detail bool) []listSessionRow {
	out := make([]listSessionRow, 0, len(sessions))
	for _, sess := range sessions {
		row := listSessionRow{
			ID:           sess.ID.String(),
			StartedAt:    sess.StartedAt.UTC().Format(time.RFC3339),
			Hostname:     sess.Hostname,
			Subcommand:   sess.Subcommand,
			TxnCommitted: sess.TxnCommitted,
			TxnTotal:     sess.TxnTotal,
		}
		if detail {
			txns, err := s.TransactionsForSession(ctx, sess.ID)
			if err != nil {
				continue // best-effort; one session's load failure shouldn't abort the listing
			}
			for _, t := range txns {
				row.Transactions = append(row.Transactions, listSessionRowTxn{
					RuleID: t.RuleID, Status: t.Status,
				})
			}
		}
		out = append(out, row)
	}
	return out
}

func writeRollbackListText(ctx context.Context, s *store.SQLite, w io.Writer, sessions []*store.Session, detail bool) {
	fmt.Fprintln(w, "kensa rollback --list")
	if len(sessions) == 0 {
		fmt.Fprintln(w, "  (no rollback-able sessions in the store — none have committed transactions)")
		return
	}
	fmt.Fprintf(w, "  %d rollback-able session(s)\n\n", len(sessions))
	fmt.Fprintln(w, "  started_at            hostname           committed  session_id")
	fmt.Fprintln(w, "  --------------------  -----------------  ---------  ------------------------------------")
	for _, sess := range sessions {
		host := sess.Hostname
		if host == "" {
			host = "(unknown)"
		}
		fmt.Fprintf(w, "  %-20s  %-17s  %9d  %s\n",
			sess.StartedAt.UTC().Format("2006-01-02 15:04:05"),
			host, sess.TxnCommitted, sess.ID.String())
		if detail {
			txns, err := s.TransactionsForSession(ctx, sess.ID)
			if err != nil {
				fmt.Fprintf(w, "    (failed to load transactions: %v)\n", err)
				continue
			}
			for _, t := range txns {
				fmt.Fprintf(w, "    - %-40s %s\n", t.RuleID, t.Status)
			}
		}
	}
}

// runRollbackInfo implements `kensa rollback --info SESSION_ID`
// (C-049): single-session detail. Read-only.
func runRollbackInfo(ctx context.Context, dbPath string, sessID uuid.UUID, detail bool, format string, quiet bool) error {
	s, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	sess, err := s.GetSession(ctx, sessID)
	if err != nil {
		return cleanRollbackSessionLookupError(sessID, err)
	}
	txns, err := s.TransactionsForSession(ctx, sessID)
	if err != nil {
		return err
	}

	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		envelope := struct {
			Session      listSessionRow      `json:"session"`
			Transactions []listSessionRowTxn `json:"transactions"`
		}{
			Session: listSessionRow{
				ID:           sess.ID.String(),
				StartedAt:    sess.StartedAt.UTC().Format(time.RFC3339),
				Hostname:     sess.Hostname,
				Subcommand:   sess.Subcommand,
				TxnCommitted: sess.TxnCommitted,
				TxnTotal:     sess.TxnTotal,
			},
		}
		for _, t := range txns {
			envelope.Transactions = append(envelope.Transactions, listSessionRowTxn{
				RuleID: t.RuleID, Status: t.Status,
			})
		}
		return jw.WriteJSONValue(out, envelope)
	}
	writeRollbackInfoText(out, sess, txns, detail)
	return nil
}

func writeRollbackInfoText(w io.Writer, sess *store.Session, txns []store.SessionTxn, detail bool) {
	fmt.Fprintf(w, "Session: %s\n", sess.ID)
	host := sess.Hostname
	if host == "" {
		host = "(unknown)"
	}
	fmt.Fprintf(w, "  hostname:      %s\n", host)
	fmt.Fprintf(w, "  subcommand:    %s\n", sess.Subcommand)
	fmt.Fprintf(w, "  started_at:    %s\n", sess.StartedAt.UTC().Format(time.RFC3339))
	if !sess.FinishedAt.IsZero() && !sess.FinishedAt.Equal(sess.StartedAt) {
		fmt.Fprintf(w, "  finished_at:   %s\n", sess.FinishedAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(w, "  committed:     %d / %d total\n", sess.TxnCommitted, sess.TxnTotal)
	fmt.Fprintf(w, "  rolled_back:   %d\n", sess.TxnRolled)
	if sess.TxnFailed > 0 {
		fmt.Fprintf(w, "  failed:        %d\n", sess.TxnFailed)
	}
	if len(txns) == 0 {
		fmt.Fprintln(w, "\n  (no transactions attached)")
		return
	}
	if detail {
		fmt.Fprintln(w, "\n  transactions (per-rule, latest first):")
	} else {
		fmt.Fprintln(w, "\n  transactions:")
	}
	for _, t := range txns {
		fmt.Fprintf(w, "    %-40s %s\n", t.RuleID, t.Status)
	}
}

// rollbackStartResult is the JSON shape returned by --start.
type rollbackStartResult struct {
	SessionID string                  `json:"session_id"`
	Attempted int                     `json:"attempted"`
	Succeeded int                     `json:"succeeded"`
	Failed    int                     `json:"failed"`
	PerTxn    []rollbackStartTxnEntry `json:"per_txn"`
}

type rollbackStartTxnEntry struct {
	RuleID  string `json:"rule_id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// runRollbackStart implements `kensa rollback --start
// SESSION_ID` (C-049). Iterates committed transactions in the
// session (earliest-first via store.CommittedTxnIDs) and rolls
// each back via svc.Rollback. Continues on per-txn failure;
// final exit code is 0 if all succeeded, 1 if any failed.
//
// Hostname guard: if session.Hostname is non-empty and !=
// hostCfg.Hostname, rejects with a usage error. Rolling back
// host-A's session against host-B is almost never what the
// operator meant.
func runRollbackStart(ctx context.Context, dbPath string, sessID uuid.UUID, hostCfg api.HostConfig, format string, quiet bool) error {
	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()

	// Parallel store handle for session-aware queries (the
	// kensa.Default service exposes only the LogQuery
	// interface, not GetSession / CommittedTxnIDs). modernc/
	// sqlite's WAL mode handles read concurrency cleanly.
	s, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store for session lookup: %w", err)
	}
	defer func() { _ = s.Close() }()

	sess, err := s.GetSession(ctx, sessID)
	if err != nil {
		return cleanRollbackSessionLookupError(sessID, err)
	}
	// Defense-in-depth: peer review caught that
	// `kensa check --store` sessions write committed for
	// "rule passed" without capturing pre-state. Calling
	// svc.Rollback on those would silently report success
	// while doing nothing. RollbackableSessions filters
	// these out of --list, but a direct `--start <check-id>`
	// would still reach this path. Reject explicitly.
	if sess.Subcommand != "remediate" {
		return NewUsageError(fmt.Sprintf(
			"session %s was created by 'kensa %s', not 'remediate' — only remediate sessions have pre-state to roll back",
			sessID, sess.Subcommand))
	}
	// Hostname guard. Reject the cross-host case AND the
	// empty-hostname case (legacy backfill / unknown host).
	// Without this, a backfilled session with empty hostname
	// would silently execute against ANY --host the operator
	// names — exactly the wrong-state-on-wrong-host risk
	// C-03 names as a usage error. R1 peer review.
	if sess.Hostname == "" {
		return NewUsageError(fmt.Sprintf(
			"session %s has no recorded hostname (legacy backfill?); cannot safely target it for rollback",
			sessID))
	}
	if sess.Hostname != hostCfg.Hostname {
		return NewUsageError(fmt.Sprintf(
			"hostname mismatch: session was on %q but --host is %q (rolling back across hosts is rejected)",
			sess.Hostname, hostCfg.Hostname))
	}

	txnRefs, err := s.CommittedTxnIDs(ctx, sessID)
	if err != nil {
		return err
	}

	result := rollbackStartResult{SessionID: sessID.String()}
	for _, ref := range txnRefs {
		result.Attempted++
		if _, err := svc.Rollback(ctx, hostCfg, ref.TxnID); err != nil {
			result.Failed++
			result.PerTxn = append(result.PerTxn, rollbackStartTxnEntry{
				RuleID: ref.RuleID, Success: false, Error: err.Error(),
			})
			fmt.Fprintf(os.Stderr, "kensa rollback --start: %s rollback failed: %v\n", ref.RuleID, err)
			continue
		}
		result.Succeeded++
		result.PerTxn = append(result.PerTxn, rollbackStartTxnEntry{
			RuleID: ref.RuleID, Success: true,
		})
	}

	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		if err := jw.WriteJSONValue(out, result); err != nil {
			return err
		}
	} else {
		writeRollbackStartText(out, &result)
	}

	if result.Failed > 0 {
		return fmt.Errorf("%d/%d transaction rollback(s) failed", result.Failed, result.Attempted)
	}
	return nil
}

func writeRollbackStartText(w io.Writer, r *rollbackStartResult) {
	fmt.Fprintf(w, "kensa rollback --start %s\n", r.SessionID)
	fmt.Fprintf(w, "  attempted:  %d\n", r.Attempted)
	fmt.Fprintf(w, "  succeeded:  %d\n", r.Succeeded)
	fmt.Fprintf(w, "  failed:     %d\n", r.Failed)
	if r.Failed > 0 {
		fmt.Fprintln(w, "\n  failures:")
		for _, e := range r.PerTxn {
			if !e.Success {
				fmt.Fprintf(w, "    %s: %s\n", e.RuleID, e.Error)
			}
		}
	}
}

// cleanRollbackSessionLookupError mirrors the C-048
// cleanSessionLookupError fix: replace SQL-leaky errors with
// an actionable message pointing at the discovery command.
func cleanRollbackSessionLookupError(id uuid.UUID, err error) error {
	if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "no rows") {
		return fmt.Errorf("session %s not found in store (try 'kensa rollback --list' or 'kensa list sessions')", id)
	}
	return fmt.Errorf("session %s: %w", id, err)
}
