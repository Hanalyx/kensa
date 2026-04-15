package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/Hanalyx/kensa-go/api"
)

// SQLite is the durable [Store] implementation backed by a SQLite
// database. Per transaction-log spec C-02, all writes use synchronous
// FULL so pre-state persistence completes before the engine proceeds.
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens or creates a SQLite database at path and runs any
// pending schema migrations. The connection is configured with
// PRAGMA synchronous=FULL and PRAGMA journal_mode=WAL.
func OpenSQLite(ctx context.Context, path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// modernc/sqlite handles concurrency at the connection level;
	// limit to 1 to avoid SQLITE_BUSY on the embedded WAL.
	db.SetMaxOpenConns(1)

	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = FULL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	}
	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: %s: %w", pragma, err)
		}
	}

	s := &SQLite{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *SQLite) Close() error { return s.db.Close() }

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
		return err
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
			return fmt.Errorf("store: insert pre-state %d: %w", p.StepIndex, err)
		}
	}
	return tx.Commit()
}

// PersistResult writes the terminal transaction record plus its
// per-step results, framework refs, and rollback events.
func (s *SQLite) PersistResult(ctx context.Context, result *api.TransactionResult) error {
	if result == nil || result.Envelope == nil {
		return errors.New("store: PersistResult requires non-nil result and envelope")
	}
	envJSON, err := json.Marshal(result.Envelope)
	if err != nil {
		return fmt.Errorf("store: marshal envelope: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
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

	severity := ""
	for _, ref := range result.Envelope.FrameworkRefs {
		_ = ref // reserved for future severity-from-rule lookup
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
		severity,
		result.StartedAt.UTC().Format(time.RFC3339Nano),
		result.FinishedAt.UTC().Format(time.RFC3339Nano),
		committedAt, rolledBackAt,
		string(envJSON),
		result.Envelope.Signature,
		errText,
	); err != nil {
		return fmt.Errorf("store: insert transaction: %w", err)
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

	return tx.Commit()
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
