package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BackfillReport summarizes the work BackfillSessions did.
// Returned to the CLI so `kensa migrate` can print an
// operator-facing summary instead of opaque success.
type BackfillReport struct {
	// SchemaVersion is the version of the store after migrate
	// runs (always the latest schemaVersion, since OpenSQLite
	// applies pending migrations).
	SchemaVersion int

	// SessionsCreated is the number of synthetic sessions the
	// backfill inserted, one per distinct host_id with NULL
	// session_id transactions.
	SessionsCreated int

	// TransactionsAttached is the total number of transactions
	// that gained a session_id during the backfill.
	TransactionsAttached int
}

// BackfillSessions walks transactions whose session_id is
// NULL (rows written before the session model, or without session
// bookkeeping) and groups them into synthetic sessions —
// one per distinct host_id. Each synthetic session's
// started_at / finished_at span the host's earliest and
// latest transaction timestamps; the subcommand is
// "legacy-backfill" so operators can distinguish them from
// real CLI-invocation sessions.
//
// Idempotent: a second call finds no NULL rows and returns
// a zeroed report. Safe to run on freshly-created stores
// (no transactions yet) — returns zero counts.
//
// The backfill runs inside a single SQLite transaction so an
// interrupt mid-run leaves no half-attached state.
func (s *SQLite) BackfillSessions(ctx context.Context) (BackfillReport, error) {
	report := BackfillReport{}
	current, err := s.currentSchemaVersion(ctx)
	if err != nil {
		return report, fmt.Errorf("read schema version: %w", err)
	}
	report.SchemaVersion = current

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer func() { _ = tx.Rollback() }()

	// Find distinct hosts with NULL-session transactions, plus
	// each host's time bounds so we can synthesize plausible
	// session timestamps.
	type hostRow struct {
		hostID        string
		minStartedAt  string
		maxFinishedAt string
		count         int
	}
	rows, err := tx.QueryContext(ctx, `
        SELECT host_id, MIN(started_at), MAX(finished_at), COUNT(*)
        FROM transactions
        WHERE session_id IS NULL
        GROUP BY host_id
        ORDER BY host_id`)
	if err != nil {
		return report, fmt.Errorf("query orphan transactions: %w", err)
	}
	var hosts []hostRow
	for rows.Next() {
		var h hostRow
		if err := rows.Scan(&h.hostID, &h.minStartedAt, &h.maxFinishedAt, &h.count); err != nil {
			rows.Close()
			return report, fmt.Errorf("scan host row: %w", err)
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return report, err
	}

	// One synthetic session per host. Subcommand="legacy-
	// backfill" lets operators tell these apart from real
	// CLI sessions in `kensa history --stats` etc.
	for _, h := range hosts {
		started, err := time.Parse(time.RFC3339Nano, h.minStartedAt)
		if err != nil {
			return report, fmt.Errorf("parse min started_at for %s: %w", h.hostID, err)
		}
		finished, err := time.Parse(time.RFC3339Nano, h.maxFinishedAt)
		if err != nil {
			return report, fmt.Errorf("parse max finished_at for %s: %w", h.hostID, err)
		}
		sessID := uuid.New()
		// Insert synthesized session. Counts are filled in
		// after the UPDATE so they reflect the attached set.
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO sessions (
                id, started_at, finished_at, hostname, subcommand, args_summary,
                txn_total, txn_committed, txn_rolled, txn_failed)
            VALUES (?, ?, ?, ?, 'legacy-backfill', '', 0, 0, 0, 0)`,
			sessID.String(),
			started.UTC().Format(time.RFC3339Nano),
			finished.UTC().Format(time.RFC3339Nano),
			h.hostID,
		); err != nil {
			return report, fmt.Errorf("insert backfill session for %s: %w", h.hostID, err)
		}

		// Attach this host's NULL-session transactions to the
		// synthetic session.
		res, err := tx.ExecContext(ctx, `
            UPDATE transactions
            SET session_id = ?
            WHERE host_id = ? AND session_id IS NULL`,
			sessID.String(), h.hostID,
		)
		if err != nil {
			return report, fmt.Errorf("attach transactions for %s: %w", h.hostID, err)
		}
		attached, err := res.RowsAffected()
		if err != nil {
			return report, err
		}

		// Refresh denormalized counts on the synthetic
		// session. Inlined COALESCE for the same reason as
		// FinishSession (SUM is NULL on empty set).
		if _, err := tx.ExecContext(ctx, `
            UPDATE sessions SET
                txn_total     = ?,
                txn_committed = (
                    SELECT COALESCE(SUM(CASE WHEN status = 'committed'   THEN 1 ELSE 0 END), 0)
                    FROM transactions WHERE session_id = ?),
                txn_rolled    = (
                    SELECT COALESCE(SUM(CASE WHEN status = 'rolled_back' THEN 1 ELSE 0 END), 0)
                    FROM transactions WHERE session_id = ?),
                txn_failed    = (
                    SELECT COALESCE(SUM(CASE WHEN status NOT IN ('committed','rolled_back') THEN 1 ELSE 0 END), 0)
                    FROM transactions WHERE session_id = ?)
            WHERE id = ?`,
			attached,
			sessID.String(), sessID.String(), sessID.String(),
			sessID.String(),
		); err != nil {
			return report, fmt.Errorf("refresh counts for session %s: %w", sessID, err)
		}

		report.SessionsCreated++
		report.TransactionsAttached += int(attached)
	}

	if err := tx.Commit(); err != nil {
		return report, err
	}
	return report, nil
}

// CurrentSchemaVersion exposes the schema version for callers
// that want to surface it (e.g., kensa migrate's report).
// Wraps the package-private currentSchemaVersion.
func (s *SQLite) CurrentSchemaVersion(ctx context.Context) (int, error) {
	v, err := s.currentSchemaVersion(ctx)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	return v, nil
}
