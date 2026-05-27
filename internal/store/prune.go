package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PruneReport summarizes the rows deleted by PruneSessions.
// Returned to the CLI so `kensa history --prune` can print
// an operator-facing audit summary.
//
// OrphanTransactionsDeleted is a sub-count of TransactionsDeleted
// — it counts transactions that had session_id IS NULL at prune
// time (legacy sessionless / unmigrated rows). Operators auditing the
// summary can tell whether the deleted rows came from real
// session-grouped runs or legacy backfill territory.
type PruneReport struct {
	SessionsDeleted           int
	TransactionsDeleted       int
	OrphanTransactionsDeleted int
	StepsDeleted              int
	PreStatesDeleted          int
	FrameworkRefsDeleted      int
	RollbackEventsDeleted     int
}

// PruneSessions deletes sessions whose started_at is strictly
// before cutoff, plus the cascade of child rows: attached
// transactions, steps, pre_states, framework_refs,
// rollback_events. Legacy NULL-session transactions
// older than cutoff (by their own started_at) are also pruned;
// operators with a long-running legacy store don't need to run
// `kensa migrate` first to shed old data (C-04 in spec).
//
// All work runs in a single SQLite transaction (C-02 in spec):
// an interrupt mid-run leaves the store either fully pruned or
// unchanged.
func (s *SQLite) PruneSessions(ctx context.Context, cutoff time.Time) (PruneReport, error) {
	report := PruneReport{}

	cutoffStr := cutoff.UTC().Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer func() { _ = tx.Rollback() }()

	// Collect transaction IDs to delete: (a) attached to a
	// session whose started_at < cutoff, (b) NULL-session
	// orphans whose own started_at < cutoff. Both arms feed
	// into the same cascade DELETEs. The is_orphan flag is
	// surfaced in PruneReport so operators can audit the
	// sessionless-row backfill share.
	rows, err := tx.QueryContext(ctx, `
        SELECT t.id, (t.session_id IS NULL) AS is_orphan FROM transactions t
        LEFT JOIN sessions s ON s.id = t.session_id
        WHERE
            (t.session_id IS NOT NULL AND s.started_at < ?)
         OR (t.session_id IS NULL     AND t.started_at < ?)`,
		cutoffStr, cutoffStr,
	)
	if err != nil {
		return report, fmt.Errorf("query prune candidates: %w", err)
	}
	type cand struct {
		id     string
		orphan bool
	}
	var cands []cand
	for rows.Next() {
		var (
			id       string
			isOrphan int
		)
		if err := rows.Scan(&id, &isOrphan); err != nil {
			rows.Close()
			return report, fmt.Errorf("scan prune candidate: %w", err)
		}
		cands = append(cands, cand{id: id, orphan: isOrphan != 0})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return report, err
	}

	// Cascade DELETEs: per-txn rather than per-id-list to
	// avoid a giant IN(...) clause for large prune sets.
	// SQLite handles this in WAL with no per-row commit.
	//
	// Scaling note: this is O(N) round-trips with 5 DELETEs
	// per txn. Acceptable for typical operator stores
	// (≤ low-thousands of txns per prune run); a follow-up
	// can chunk into batched IN-clauses if real-world
	// telemetry shows the whole-WAL hold becomes a problem.
	// The single-tx atomicity guarantee (C-02) is the cost
	// driver here, not the per-statement overhead.
	for _, c := range cands {
		n, err := txDelete(ctx, tx, `DELETE FROM steps           WHERE transaction_id = ?`, c.id)
		if err != nil {
			return report, err
		}
		report.StepsDeleted += n
		n, err = txDelete(ctx, tx, `DELETE FROM pre_states      WHERE transaction_id = ?`, c.id)
		if err != nil {
			return report, err
		}
		report.PreStatesDeleted += n
		n, err = txDelete(ctx, tx, `DELETE FROM framework_refs  WHERE transaction_id = ?`, c.id)
		if err != nil {
			return report, err
		}
		report.FrameworkRefsDeleted += n
		n, err = txDelete(ctx, tx, `DELETE FROM rollback_events WHERE transaction_id = ?`, c.id)
		if err != nil {
			return report, err
		}
		report.RollbackEventsDeleted += n
		n, err = txDelete(ctx, tx, `DELETE FROM transactions    WHERE id = ?`, c.id)
		if err != nil {
			return report, err
		}
		report.TransactionsDeleted += n
		if c.orphan {
			report.OrphanTransactionsDeleted += n
		}
	}

	// Sessions themselves. Order inside the tx doesn't
	// matter — we already collected the txn IDs above.
	res, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE started_at < ?`, cutoffStr)
	if err != nil {
		return report, fmt.Errorf("delete sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return report, err
	}
	report.SessionsDeleted = int(n)

	if err := tx.Commit(); err != nil {
		return report, err
	}
	return report, nil
}

// txDelete runs a DELETE inside the given tx and returns the
// affected-row count as int. Wrapper to keep PruneSessions's
// per-table cascade loop readable.
func txDelete(ctx context.Context, tx *sql.Tx, query string, args ...any) (int, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("prune exec: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}
