package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Session is a CLI-invocation grouping over transactions.
// Phase 4 / C-039 introduced this layer so `kensa diff`,
// `kensa history --stats`, and the session-aware rollback
// workflow have a stable handle for "everything that ran
// from one operator command."
type Session struct {
	ID           uuid.UUID
	StartedAt    time.Time
	FinishedAt   time.Time
	Hostname     string // empty for inventory mode (per-host transactions carry it)
	Subcommand   string // "check" | "remediate" | future
	ArgsSummary  string // operator-visible summary of flags; not the full argv
	TxnTotal     int
	TxnCommitted int
	TxnRolled    int
	TxnFailed    int
}

// CreateSession inserts a new session row. The caller is
// responsible for setting StartedAt; FinishedAt and the
// counts are populated by FinishSession at the end of the
// run. Returns the session ID for subsequent attaches.
//
// Pre-Phase-4 callers can ignore this entirely — sessions
// are optional. Transactions written without an attached
// session will have NULL session_id, treated as legacy.
func (s *SQLite) CreateSession(ctx context.Context, sess *Session) error {
	if sess == nil {
		return errors.New("store: CreateSession requires non-nil session")
	}
	if sess.ID == uuid.Nil {
		return errors.New("store: CreateSession requires non-nil session ID")
	}
	if sess.StartedAt.IsZero() {
		return errors.New("store: CreateSession requires StartedAt")
	}
	finishedAt := sess.FinishedAt
	if finishedAt.IsZero() {
		// Use StartedAt as a placeholder; FinishSession overwrites
		// when the run wraps. NOT NULL on the column means we need
		// a value; using StartedAt makes "finished == started" the
		// "run still in progress" sentinel.
		finishedAt = sess.StartedAt
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO sessions (
            id, started_at, finished_at, hostname, subcommand, args_summary,
            txn_total, txn_committed, txn_rolled, txn_failed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID.String(),
		sess.StartedAt.UTC().Format(time.RFC3339Nano),
		finishedAt.UTC().Format(time.RFC3339Nano),
		sess.Hostname, sess.Subcommand, sess.ArgsSummary,
		sess.TxnTotal, sess.TxnCommitted, sess.TxnRolled, sess.TxnFailed,
	)
	if err != nil {
		return fmt.Errorf("store: insert session: %w", err)
	}
	return nil
}

// FinishSession records run-end timestamp and refreshes the
// denormalized counts by querying the transactions table.
// Idempotent: callers can invoke multiple times (e.g., once
// per inventory-host fan-out completion).
func (s *SQLite) FinishSession(ctx context.Context, sessID uuid.UUID, finishedAt time.Time) error {
	if sessID == uuid.Nil {
		return errors.New("store: FinishSession requires non-nil session ID")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var total, committed, rolled, failed int
	// COALESCE wraps the SUMs so an empty session (no
	// transactions yet attached) returns 0 instead of NULL —
	// SQLite's SUM is NULL on the empty set.
	if err := tx.QueryRowContext(ctx, `
        SELECT
            COUNT(*),
            COALESCE(SUM(CASE WHEN status = 'committed'   THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status = 'rolled_back' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN status NOT IN ('committed','rolled_back') THEN 1 ELSE 0 END), 0)
        FROM transactions WHERE session_id = ?`,
		sessID.String(),
	).Scan(&total, &committed, &rolled, &failed); err != nil {
		return fmt.Errorf("store: count transactions for session: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
        UPDATE sessions SET
            finished_at   = ?,
            txn_total     = ?,
            txn_committed = ?,
            txn_rolled    = ?,
            txn_failed    = ?
        WHERE id = ?`,
		finishedAt.UTC().Format(time.RFC3339Nano),
		total, committed, rolled, failed,
		sessID.String(),
	); err != nil {
		return fmt.Errorf("store: update session: %w", err)
	}
	return tx.Commit()
}

// AttachTransaction sets the session_id on an existing
// transaction. Used by callers that persist the result first
// (PersistResult writes session_id=NULL) then attach to the
// session as part of session bookkeeping. Idempotent — re-
// attaching to the same session is a no-op.
//
// Pre-Phase-4 transactions with NULL session_id can be
// retroactively attached by the kensa-migrate tool (C-040)
// using a synthetic backfilled session.
func (s *SQLite) AttachTransaction(ctx context.Context, txnID, sessID uuid.UUID) error {
	if txnID == uuid.Nil || sessID == uuid.Nil {
		return errors.New("store: AttachTransaction requires non-nil IDs")
	}
	res, err := s.db.ExecContext(ctx, `
        UPDATE transactions SET session_id = ? WHERE id = ?`,
		sessID.String(), txnID.String(),
	)
	if err != nil {
		return fmt.Errorf("store: attach transaction: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: AttachTransaction: no transaction with id %s", txnID)
	}
	return nil
}

// GetSession returns the session row for sessID. Returns
// sql.ErrNoRows wrapped when not found.
func (s *SQLite) GetSession(ctx context.Context, sessID uuid.UUID) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, started_at, finished_at, hostname, subcommand, args_summary,
               txn_total, txn_committed, txn_rolled, txn_failed
        FROM sessions WHERE id = ?`,
		sessID.String(),
	)
	return scanSession(row)
}

// ListSessions returns sessions ordered by started_at descending,
// optionally filtered by hostname (empty = all hosts) and capped
// at limit (zero = no cap).
func (s *SQLite) ListSessions(ctx context.Context, hostname string, limit int) ([]*Session, error) {
	q := `
        SELECT id, started_at, finished_at, hostname, subcommand, args_summary,
               txn_total, txn_committed, txn_rolled, txn_failed
        FROM sessions`
	args := []any{}
	if hostname != "" {
		q += ` WHERE hostname = ?`
		args = append(args, hostname)
	}
	q += ` ORDER BY started_at DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query sessions: %w", err)
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// rowScanner abstracts over *sql.Row and *sql.Rows for the
// shared scanSession helper.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanSession(r rowScanner) (*Session, error) {
	var (
		id, hostname, subcommand, argsSummary string
		startedAt, finishedAt                 string
		total, committed, rolled, failed      int
	)
	if err := r.Scan(&id, &startedAt, &finishedAt, &hostname, &subcommand, &argsSummary,
		&total, &committed, &rolled, &failed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("store: GetSession: %w", err)
		}
		return nil, fmt.Errorf("store: scan session: %w", err)
	}
	sessID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("store: parse session id %q: %w", id, err)
	}
	startedT, err := time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse session started_at %q: %w", startedAt, err)
	}
	finishedT, err := time.Parse(time.RFC3339Nano, finishedAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse session finished_at %q: %w", finishedAt, err)
	}
	return &Session{
		ID:           sessID,
		StartedAt:    startedT,
		FinishedAt:   finishedT,
		Hostname:     hostname,
		Subcommand:   subcommand,
		ArgsSummary:  argsSummary,
		TxnTotal:     total,
		TxnCommitted: committed,
		TxnRolled:    rolled,
		TxnFailed:    failed,
	}, nil
}
