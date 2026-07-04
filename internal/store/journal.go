package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// PrepareTransaction writes the crash-recovery journal entry AND the
// captured pre-states in ONE atomic SQLite commit, synchronously
// (synchronous=FULL). This is the write-ahead barrier: the intent and the
// pre-state are durable on disk BEFORE the engine mutates the host, so a
// crash mid-apply leaves a recoverable record. It replaces the standalone
// PersistPreStates write on the prepared path.
func (s *SQLite) PrepareTransaction(ctx context.Context, entry api.JournalEntry, preStates []api.PreState) error {
	intentJSON, err := json.Marshal(entry.Intent)
	if err != nil {
		return fmt.Errorf("store: marshal journal intent: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
        INSERT OR REPLACE INTO recover_journal
            (txn_id, host_id, rule_id, transactional, session_id, phase, cursor, intent_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.TxnID.String(), entry.HostID, entry.RuleID, boolToInt(entry.Transactional),
		nullString(entry.SessionID), entry.Phase, entry.Cursor, string(intentJSON),
		entry.CreatedAt.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("store: insert journal entry: %w", err)
	}

	for _, p := range preStates {
		dataJSON, err := json.Marshal(p.Data)
		if err != nil {
			return fmt.Errorf("store: marshal pre-state %d: %w", p.StepIndex, err)
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT OR REPLACE INTO pre_states
                (transaction_id, step_index, mechanism, capturable, state_json, captured_at)
            VALUES (?, ?, ?, ?, ?, ?)`,
			entry.TxnID.String(), p.StepIndex, p.Mechanism, boolToInt(p.Capturable),
			string(dataJSON), p.CapturedAt.UTC().Format(time.RFC3339Nano),
		); err != nil {
			return fmt.Errorf("store: insert pre-state %d: %w", p.StepIndex, err)
		}
	}
	return tx.Commit()
}

// AdvanceJournalCursor durably records, WRITE-AHEAD of the step it guards, the
// highest step index whose mutation may have begun. The cursor is FORENSIC:
// recovery (engine.recoverRollback) compensates every captured pre-state in
// reverse order regardless of the cursor, so a stale or missing cursor cannot
// make recovery skip a step. The write-ahead ordering is maintained for
// forensic fidelity and so a future cursor-bounded recovery could rely on it;
// until then nothing reads the cursor to make a recovery decision.
func (s *SQLite) AdvanceJournalCursor(ctx context.Context, txnID uuid.UUID, cursor int) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE recover_journal SET cursor = ?, phase = 'applying' WHERE txn_id = ?`,
		cursor, txnID.String(),
	); err != nil {
		return fmt.Errorf("store: advance journal cursor: %w", err)
	}
	return nil
}

// LoadOpenJournalEntries returns every journal entry whose transaction never
// reached a terminal status — i.e. a row in recover_journal with no
// corresponding transactions row. These are the recovery targets: a
// transaction the engine started (intent durable, pre-state captured) but
// crashed before writing its terminal record.
func (s *SQLite) LoadOpenJournalEntries(ctx context.Context) ([]api.JournalEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT rj.txn_id, rj.host_id, rj.rule_id, rj.transactional,
               rj.session_id, rj.phase, rj.cursor, rj.intent_json, rj.created_at
        FROM recover_journal rj
        LEFT JOIN transactions t ON t.id = rj.txn_id
        WHERE t.id IS NULL
        ORDER BY rj.created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: query open journal entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []api.JournalEntry
	for rows.Next() {
		var (
			idStr, hostID, ruleID, phase, intentJSON, createdAt string
			sessionID                                           sql.NullString
			transactional, cursor                               int
		)
		if err := rows.Scan(&idStr, &hostID, &ruleID, &transactional,
			&sessionID, &phase, &cursor, &intentJSON, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan journal entry: %w", err)
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse journal txn_id %q: %w", idStr, err)
		}
		var intent []api.Step
		if err := json.Unmarshal([]byte(intentJSON), &intent); err != nil {
			return nil, fmt.Errorf("store: unmarshal journal intent for %s: %w", idStr, err)
		}
		created, _ := time.Parse(time.RFC3339Nano, createdAt)
		out = append(out, api.JournalEntry{
			TxnID:         id,
			HostID:        hostID,
			RuleID:        ruleID,
			Transactional: transactional != 0,
			SessionID:     sessionID.String,
			Phase:         phase,
			Cursor:        cursor,
			Intent:        intent,
			CreatedAt:     created,
		})
	}
	return out, rows.Err()
}

// ClearJournalEntry deletes a journal entry once its transaction has reached
// a terminal status (the persisted result is the commit marker). Deleting a
// non-existent entry is not an error.
func (s *SQLite) ClearJournalEntry(ctx context.Context, txnID uuid.UUID) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM recover_journal WHERE txn_id = ?`, txnID.String(),
	); err != nil {
		return fmt.Errorf("store: clear journal entry: %w", err)
	}
	return nil
}

// nullString maps "" to a SQL NULL so session_id stays NULL for sessionless
// invocations rather than the empty string.
func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
