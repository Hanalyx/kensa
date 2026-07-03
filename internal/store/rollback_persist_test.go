package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// committedRemediateTxn persists a committed remediate transaction attached
// to a fresh session and finishes the session, so the session is
// rollback-able. Returns the session and transaction IDs.
func committedRemediateTxn(t *testing.T, s *SQLite, host string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	sess := &Session{ID: uuid.New(), StartedAt: now, Hostname: host, Subcommand: "remediate"}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	txnID := uuid.New()
	res := &api.TransactionResult{
		TransactionID: txnID,
		Status:        api.StatusCommitted,
		StartedAt:     now,
		FinishedAt:    now.Add(time.Second),
		CommittedAt:   &now,
		Steps:         []api.StepResult{{StepIndex: 0, Mechanism: "mount_option_set", Capturable: true, Success: true}},
		Envelope: &api.EvidenceEnvelope{
			SchemaVersion: "v1", TransactionID: txnID, RuleID: "mount-var-nosuid",
			HostID: host, StartedAt: now, FinishedAt: now.Add(time.Second),
			Decision: api.StatusCommitted, SigningKeyID: "noop", Signature: []byte{},
		},
	}
	if err := s.PersistResult(ctx, res); err != nil {
		t.Fatalf("PersistResult: %v", err)
	}
	if err := s.AttachTransaction(ctx, txnID, sess.ID); err != nil {
		t.Fatalf("AttachTransaction: %v", err)
	}
	if err := s.FinishSession(ctx, sess.ID, now.Add(2*time.Second)); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}
	return sess.ID, txnID
}

func hasSession(sessions []*Session, id uuid.UUID) bool {
	for _, s := range sessions {
		if s.ID == id {
			return true
		}
	}
	return false
}

// TestPersistRollback_MarksStatusAndDropsSession proves the Finding-B write
// path: a rollback flips the transaction to rolled_back with rolled_back_at,
// records a rollback_events row per step, and refreshes the session so it
// stops appearing in RollbackableSessions.
//
// @spec cli-rollback-session-aware
// @ac AC-15
func TestPersistRollback_MarksStatusAndDropsSession(t *testing.T) {
	t.Run("cli-rollback-session-aware/AC-15", func(t *testing.T) {})
	t.Log("// @spec cli-rollback-session-aware")
	t.Log("// @ac AC-15")

	s := openTestStore(t)
	ctx := context.Background()
	sessID, txnID := committedRemediateTxn(t, s, "192.168.1.211")

	// Precondition: before rollback the session IS rollback-able.
	rb, err := s.RollbackableSessions(ctx, 0)
	if err != nil {
		t.Fatalf("RollbackableSessions: %v", err)
	}
	if !hasSession(rb, sessID) {
		t.Fatal("precondition failed: committed remediate session should be rollback-able")
	}

	rbAt := time.Now().UTC().Truncate(time.Microsecond)
	results := []api.RollbackResult{
		{StepIndex: 0, Mechanism: "mount_option_set", Success: true, Source: "manual", ExecutedAt: rbAt},
	}
	if err := s.PersistRollback(ctx, txnID, results, rbAt); err != nil {
		t.Fatalf("PersistRollback: %v", err)
	}

	// 1. Transaction is rolled_back with rolled_back_at set.
	var status string
	var rolledAt sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT status, rolled_back_at FROM transactions WHERE id = ?`, txnID.String(),
	).Scan(&status, &rolledAt); err != nil {
		t.Fatalf("read transaction: %v", err)
	}
	if status != "rolled_back" {
		t.Errorf("status = %q, want rolled_back", status)
	}
	if !rolledAt.Valid || rolledAt.String == "" {
		t.Error("rolled_back_at was not set")
	}

	// 2. A rollback_events row was written.
	var events int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM rollback_events WHERE transaction_id = ?`, txnID.String(),
	).Scan(&events); err != nil {
		t.Fatalf("count rollback_events: %v", err)
	}
	if events != 1 {
		t.Errorf("rollback_events rows = %d, want 1", events)
	}

	// 3. The session is no longer rollback-able (no double rollback).
	rb2, err := s.RollbackableSessions(ctx, 0)
	if err != nil {
		t.Fatalf("RollbackableSessions after: %v", err)
	}
	if hasSession(rb2, sessID) {
		t.Error("session still rollback-able after its only transaction was rolled back")
	}

	// And the denormalized counters moved committed -> rolled.
	got, err := s.GetSession(ctx, sessID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.TxnCommitted != 0 || got.TxnRolled != 1 {
		t.Errorf("session counters: committed=%d rolled=%d, want 0 and 1", got.TxnCommitted, got.TxnRolled)
	}
}

// TestPersistRollback_RecomputesAllCounters proves that rolling back a
// NON-committed transaction (reachable via the legacy `--txn` path, which
// applies no status filter) refreshes all four session counters — in
// particular txn_failed must decrement, not strand. With a committed→rolled
// transition this is invisible; an errored→rolled transition exposes a
// partial recompute.
//
// @spec cli-rollback-session-aware
// @ac AC-15
func TestPersistRollback_RecomputesAllCounters(t *testing.T) {
	t.Run("cli-rollback-session-aware/AC-15", func(t *testing.T) {})
	t.Log("// @spec cli-rollback-session-aware")
	t.Log("// @ac AC-15")

	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	sess := &Session{ID: uuid.New(), StartedAt: now, Hostname: "h", Subcommand: "remediate"}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	txnID := uuid.New()
	res := &api.TransactionResult{
		TransactionID: txnID, Status: api.StatusErrored,
		StartedAt: now, FinishedAt: now.Add(time.Second),
		Steps: []api.StepResult{{StepIndex: 0, Mechanism: "mount_option_set", Capturable: true, Success: true}},
		Envelope: &api.EvidenceEnvelope{
			SchemaVersion: "v1", TransactionID: txnID, RuleID: "r", HostID: "h",
			StartedAt: now, FinishedAt: now.Add(time.Second),
			Decision: api.StatusErrored, SigningKeyID: "noop", Signature: []byte{},
		},
	}
	if err := s.PersistResult(ctx, res); err != nil {
		t.Fatalf("PersistResult: %v", err)
	}
	if err := s.AttachTransaction(ctx, txnID, sess.ID); err != nil {
		t.Fatalf("AttachTransaction: %v", err)
	}
	if err := s.FinishSession(ctx, sess.ID, now.Add(2*time.Second)); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}
	if got, _ := s.GetSession(ctx, sess.ID); got.TxnFailed != 1 || got.TxnTotal != 1 {
		t.Fatalf("precondition: failed=%d total=%d, want 1 and 1", got.TxnFailed, got.TxnTotal)
	}

	if err := s.PersistRollback(ctx, txnID,
		[]api.RollbackResult{{StepIndex: 0, Success: true, Source: "manual", ExecutedAt: now.Add(3 * time.Second)}},
		now.Add(3*time.Second)); err != nil {
		t.Fatalf("PersistRollback: %v", err)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.TxnTotal != 1 || got.TxnCommitted != 0 || got.TxnRolled != 1 || got.TxnFailed != 0 {
		t.Errorf("counters after rolling back an errored txn: total=%d committed=%d rolled=%d failed=%d; want 1,0,1,0 (txn_failed must decrement)",
			got.TxnTotal, got.TxnCommitted, got.TxnRolled, got.TxnFailed)
	}
}

// TestPersistRollback_UnknownTxn errors rather than silently succeeding.
//
// @spec cli-rollback-session-aware
// @ac AC-15
func TestPersistRollback_UnknownTxn(t *testing.T) {
	t.Run("cli-rollback-session-aware/AC-15", func(t *testing.T) {})
	t.Log("// @spec cli-rollback-session-aware")
	t.Log("// @ac AC-15")

	s := openTestStore(t)
	err := s.PersistRollback(context.Background(), uuid.New(), nil, time.Now().UTC())
	if err == nil {
		t.Fatal("PersistRollback on an unknown transaction should error")
	}
}
