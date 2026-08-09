package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/redact"
)

// SQLite is the durable [Store] implementation backed by a SQLite
// database. Per transaction-log spec C-02, all writes use synchronous
// FULL so pre-state persistence completes before the engine proceeds.
type SQLite struct {
	db *sql.DB
	// path is the database location as the operator gave it, kept so a
	// contention error can name the file it is contending for.
	path string
}

// storePragmas are carried in the DSN rather than issued after opening.
//
// PRAGMAs are per-connection state. Issued through database/sql they bind only
// to whichever pooled connection happened to run them, so a replacement
// connection comes up with SQLite's defaults: foreign_keys OFF, so referential
// integrity stops being enforced, and busy_timeout 0, so a contended write
// fails instead of waiting. In the DSN the driver applies them in its own
// connection constructor, which every connection goes through. It also sorts
// busy_timeout first, so the remaining pragmas inherit the wait.
//
// journal_mode is here for completeness; WAL is recorded in the database file
// and would survive reconnection on its own.
var storePragmas = []string{
	"busy_timeout(5000)",
	"journal_mode(WAL)",
	"synchronous(FULL)",
	"foreign_keys(1)",
}

// dsn appends the store's pragmas to a database path.
//
// The driver accepts query parameters on a plain filename as well as on a
// file: URI, and strips them from the path itself when there is no file:
// prefix, so this is safe for `/var/lib/kensa/results.db` and `:memory:` alike.
// A path that already carries parameters keeps them.
func dsn(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	parts := make([]string, 0, len(storePragmas))
	for _, p := range storePragmas {
		parts = append(parts, "_pragma="+url.QueryEscape(p))
	}
	return path + sep + strings.Join(parts, "&")
}

// OpenSQLite opens or creates a SQLite database at path and runs any
// pending schema migrations. The connection is configured with
// PRAGMA synchronous=FULL and PRAGMA journal_mode=WAL.
//
// The parent directory is auto-created (B4 fix, 2026-05-13). Pre-fix,
// the default path `.kensa/results.db` failed to open on first run
// because the `.kensa/` directory didn't exist; operators had to
// mkdir manually before kensa would work. The mkdir uses mode 0755
// so the dir is operator-readable; the DB file itself gets the
// default umask from sql.Open. Skipped for in-memory paths (`:memory:`,
// `file::memory:?...`) which SQLite handles internally.
func OpenSQLite(ctx context.Context, path string) (*SQLite, error) {
	if path != "" && !strings.HasPrefix(path, ":memory:") && !strings.Contains(path, "mode=memory") {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("store: ensure parent dir %s: %w", dir, err)
			}
		}
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// modernc/sqlite handles concurrency at the connection level;
	// limit to 1 to avoid SQLITE_BUSY on the embedded WAL.
	db.SetMaxOpenConns(1)

	s := &SQLite{db: db, path: path}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *SQLite) Close() error { return s.db.Close() }

// ErrLedgerBusy means the ledger was locked by another client for longer than
// the busy timeout. It is a contention condition, not corruption: the write did
// not happen, and retrying against an uncontended ledger will succeed.
var ErrLedgerBusy = errors.New("store: ledger is busy")

// busy annotates a lock-contention failure with the database it is contending
// for and the flag that separates clients.
//
// Without this the caller reports whichever rule it happened to be working on,
// so several clients sharing one ledger look like several broken rules. That
// misdirection was the whole of the reported harm in KN-KN-022: seventeen rules
// appeared to fail at once and the investigation went to the rule corpus.
func (s *SQLite) busy(err error) error {
	if err == nil {
		return nil
	}
	// modernc/sqlite reports the condition in the message rather than as a
	// typed error, so matching the text is the portable check.
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "database is locked") && !strings.Contains(msg, "sqlite_busy") {
		return err
	}
	return fmt.Errorf(
		"%w: %s is locked by another kensa client. Give each concurrent client its "+
			"own ledger with the top-level --db flag, for example "+
			"`kensa --db /tmp/run-1.db remediate ...`: %w",
		ErrLedgerBusy, s.path, err)
}

// migrate applies pending migrations in order. Idempotent
// (transaction-log spec AC-08).
func (s *SQLite) migrate(ctx context.Context) error {
	current, err := s.currentSchemaVersion(ctx)
	if err != nil {
		return err
	}
	for v := current; v < schemaVersion; v++ {
		if _, err := s.db.ExecContext(ctx, migrations[v]); err != nil {
			return fmt.Errorf("store: migration %d failed: %w", v+1, err)
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR REPLACE INTO schema_version(version) VALUES (?)`, v+1); err != nil {
			return fmt.Errorf("store: recording migration %d failed: %w", v+1, err)
		}
	}
	return nil
}

// currentSchemaVersion returns the highest migration applied, or 0
// if the database has no schema_version table yet.
func (s *SQLite) currentSchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v)
	if err != nil {
		// modernc/sqlite returns the missing-table condition as a
		// string error; pattern-match is the portable check.
		if strings.Contains(err.Error(), "no such table") {
			return 0, nil
		}
		return 0, err
	}
	return v, nil
}

// PersistPreStates writes the pre-state bundle for txnID. Synchronous
// (transaction-log spec AC-01).
func (s *SQLite) PersistPreStates(ctx context.Context, txnID uuid.UUID, preStates []api.PreState) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return s.busy(err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, p := range preStates {
		dataJSON, err := json.Marshal(p.Data)
		if err != nil {
			return fmt.Errorf("store: marshal pre-state %d: %w", p.StepIndex, err)
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT OR REPLACE INTO pre_states
                (transaction_id, step_index, mechanism, capturable, state_json, captured_at)
            VALUES (?, ?, ?, ?, ?, ?)`,
			txnID.String(), p.StepIndex, p.Mechanism, boolToInt(p.Capturable),
			string(dataJSON), p.CapturedAt.UTC().Format(time.RFC3339Nano),
		); err != nil {
			return s.busy(fmt.Errorf("store: insert pre-state %d: %w", p.StepIndex, err))
		}
	}
	return s.busy(tx.Commit())
}

// PersistResult writes the terminal transaction record plus its
// per-step results, framework refs, and rollback events.
func (s *SQLite) PersistResult(ctx context.Context, result *api.TransactionResult) error {
	if result == nil || result.Envelope == nil {
		return errors.New("store: PersistResult requires non-nil result and envelope")
	}
	// Scrub credential values from the envelope's captured-state bundles
	// before it hits the log. Signed envelopes were already redacted (and
	// signed) over the same content by evidence.Sign, so re-redaction is
	// idempotent and leaves the signature valid; this call additionally
	// covers the unsigned errored path, which persists an envelope without
	// going through Sign. The separate pre_states table is left verbatim —
	// it is the rollback restoration source, not an audit surface.
	for i := range result.Envelope.PreStateBundle {
		redact.Tree(result.Envelope.PreStateBundle[i].Data)
	}
	for i := range result.Envelope.PostStateBundle {
		redact.Tree(result.Envelope.PostStateBundle[i].Data)
	}
	envJSON, err := json.Marshal(result.Envelope)
	if err != nil {
		return fmt.Errorf("store: marshal envelope: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return s.busy(err)
	}
	defer func() { _ = tx.Rollback() }()

	var committedAt, rolledBackAt sql.NullString
	if result.CommittedAt != nil {
		committedAt = sql.NullString{String: result.CommittedAt.UTC().Format(time.RFC3339Nano), Valid: true}
	}
	if result.RolledBackAt != nil {
		rolledBackAt = sql.NullString{String: result.RolledBackAt.UTC().Format(time.RFC3339Nano), Valid: true}
	}
	var errText sql.NullString
	if result.Error != nil {
		errText = sql.NullString{String: result.Error.Error(), Valid: true}
	}

	// envelope_sig is NOT NULL. An unsigned errored/demoted transaction carries
	// an empty signature; a nil []byte would bind as SQL NULL and violate the
	// constraint, dropping the errored row from the audit log. Coerce nil to an
	// empty (non-null) BLOB so every terminal outcome is durably recorded — the
	// "evidence written to the transaction log" guarantee must hold for errored
	// transactions too, not just committed ones.
	envSig := result.Envelope.Signature
	if envSig == nil {
		envSig = []byte{}
	}

	if _, err := tx.ExecContext(ctx, `
        INSERT OR REPLACE INTO transactions (
            id, rule_id, host_id, fleet_id, status, transactional, severity,
            started_at, finished_at, committed_at, rolled_back_at,
            envelope_json, envelope_sig, error_text)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.TransactionID.String(),
		result.Envelope.RuleID,
		result.Envelope.HostID,
		result.Envelope.FleetID,
		string(result.Status),
		boolToInt(true), // engine populates result.Envelope; transactional comes from the transaction itself, recorded later
		result.Envelope.Severity,
		result.StartedAt.UTC().Format(time.RFC3339Nano),
		result.FinishedAt.UTC().Format(time.RFC3339Nano),
		committedAt, rolledBackAt,
		string(envJSON),
		envSig,
		errText,
	); err != nil {
		return s.busy(fmt.Errorf("store: insert transaction: %w", err))
	}

	for _, step := range result.Steps {
		if _, err := tx.ExecContext(ctx, `
            INSERT OR REPLACE INTO steps
                (transaction_id, step_index, mechanism, capturable, success, stranded, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
			result.TransactionID.String(),
			step.StepIndex, step.Mechanism,
			boolToInt(step.Capturable), boolToInt(step.Success), boolToInt(step.Stranded),
			step.Detail,
		); err != nil {
			return fmt.Errorf("store: insert step %d: %w", step.StepIndex, err)
		}
	}

	for _, ref := range result.Envelope.FrameworkRefs {
		if _, err := tx.ExecContext(ctx, `
            INSERT OR REPLACE INTO framework_refs (transaction_id, framework_id, control_id)
            VALUES (?, ?, ?)`,
			result.TransactionID.String(), ref.FrameworkID, ref.ControlID,
		); err != nil {
			return fmt.Errorf("store: insert framework_ref %s/%s: %w", ref.FrameworkID, ref.ControlID, err)
		}
	}

	return s.busy(tx.Commit())
}

// PersistRollback records that txnID was deliberately rolled back at
// rolledBackAt: it flips the transaction's status to rolled_back and sets
// rolled_back_at, writes one rollback_events row per step result, and
// refreshes the owning session's committed/rolled counters so the session
// stops appearing in `rollback --list`. All in one transaction. It is the
// write path that closes the gap where a rollback reverted the host but the
// transaction log kept reporting the transaction committed.
func (s *SQLite) PersistRollback(ctx context.Context, txnID uuid.UUID, results []api.RollbackResult, rolledBackAt time.Time) error {
	if txnID == uuid.Nil {
		return errors.New("store: PersistRollback requires a non-nil transaction id")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return s.busy(err)
	}
	defer func() { _ = tx.Rollback() }()

	ts := rolledBackAt.UTC().Format(time.RFC3339Nano)

	res, err := tx.ExecContext(ctx, `
        UPDATE transactions SET status = 'rolled_back', rolled_back_at = ?
        WHERE id = ?`, ts, txnID.String())
	if err != nil {
		return s.busy(fmt.Errorf("store: mark transaction rolled back: %w", err))
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: PersistRollback: no transaction with id %s", txnID)
	}

	for _, r := range results {
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO rollback_events
                (transaction_id, step_index, source, executed_at, success, detail)
            VALUES (?, ?, ?, ?, ?, ?)`,
			txnID.String(), r.StepIndex, r.Source,
			r.ExecutedAt.UTC().Format(time.RFC3339Nano),
			boolToInt(r.Success), r.Detail,
		); err != nil {
			return fmt.Errorf("store: insert rollback event (step %d): %w", r.StepIndex, err)
		}
	}

	// Refresh the owning session's denormalized counters from the live
	// transaction statuses. This MUST recompute ALL FOUR counters with the
	// exact formula FinishSession uses (internal/store/sessions.go) — not just
	// committed/rolled. The legacy `kensa rollback --txn` path applies no
	// status filter (unlike --start, which is gated to committed txns), so it
	// can roll back a `partially_applied`/`errored` transaction; that row was
	// counted in txn_failed and must leave it. Recomputing only committed/
	// rolled would strand txn_failed and make the session's denormalized
	// counters internally inconsistent. No-op when the transaction has no
	// session (legacy / --txn without a session).
	var sessID sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT session_id FROM transactions WHERE id = ?`, txnID.String(),
	).Scan(&sessID); err != nil {
		return fmt.Errorf("store: read session for rolled-back txn: %w", err)
	}
	if sessID.Valid && sessID.String != "" {
		if _, err := tx.ExecContext(ctx, `
            UPDATE sessions SET
                txn_total     = (SELECT COUNT(*) FROM transactions WHERE session_id = ?),
                txn_committed = (SELECT COALESCE(SUM(CASE WHEN status = 'committed'   THEN 1 ELSE 0 END), 0) FROM transactions WHERE session_id = ?),
                txn_rolled    = (SELECT COALESCE(SUM(CASE WHEN status = 'rolled_back' THEN 1 ELSE 0 END), 0) FROM transactions WHERE session_id = ?),
                txn_failed    = (SELECT COALESCE(SUM(CASE WHEN status NOT IN ('committed','rolled_back','staged') THEN 1 ELSE 0 END), 0) FROM transactions WHERE session_id = ?)
            WHERE id = ?`,
			sessID.String, sessID.String, sessID.String, sessID.String, sessID.String,
		); err != nil {
			return fmt.Errorf("store: refresh session counters after rollback: %w", err)
		}
	}

	return s.busy(tx.Commit())
}

// LoadPreStates returns the pre-state bundle for txnID, ordered by
// step_index ascending.
func (s *SQLite) LoadPreStates(ctx context.Context, txnID uuid.UUID) ([]api.PreState, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT step_index, mechanism, capturable, state_json, captured_at
        FROM pre_states
        WHERE transaction_id = ?
        ORDER BY step_index`, txnID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []api.PreState
	for rows.Next() {
		var (
			idx        int
			mech       string
			capturable int
			stateJSON  string
			capturedAt string
		)
		if err := rows.Scan(&idx, &mech, &capturable, &stateJSON, &capturedAt); err != nil {
			return nil, err
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(stateJSON), &data); err != nil {
			return nil, fmt.Errorf("store: unmarshal pre-state %d: %w", idx, err)
		}
		ts, err := time.Parse(time.RFC3339Nano, capturedAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse captured_at: %w", err)
		}
		out = append(out, api.PreState{
			StepIndex:  idx,
			Mechanism:  mech,
			Capturable: capturable != 0,
			Data:       data,
			CapturedAt: ts,
		})
	}
	return out, rows.Err()
}

// boolToInt returns 1 for true, 0 for false. SQLite has no boolean
// type; INTEGER 0/1 is the standard mapping.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
