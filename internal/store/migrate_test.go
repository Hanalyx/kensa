// Tests for C-040 BackfillSessions.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// insertOrphanTxn inserts a transaction with NULL session_id —
// simulating a pre-Phase-4 row that the backfill should pick up.
func insertOrphanTxn(t *testing.T, store *SQLite, hostID string, started time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := store.db.Exec(`
        INSERT INTO transactions (
            id, rule_id, host_id, fleet_id, status, transactional, severity,
            started_at, finished_at,
            envelope_json, envelope_sig)
        VALUES (?, 'rule-x', ?, '', 'committed', 1, 'high',
                ?, ?,
                '{}', X'')`,
		id.String(), hostID,
		started.UTC().Format(time.RFC3339Nano),
		started.Add(time.Second).UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatalf("insert orphan: %v", err)
	}
	return id
}

func TestBackfillSessions_EmptyStore(t *testing.T) {
	store := openTestStore(t)
	report, err := store.BackfillSessions(context.Background())
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if report.SessionsCreated != 0 || report.TransactionsAttached != 0 {
		t.Errorf("expected zero counts on empty store; got %+v", report)
	}
	if report.SchemaVersion != schemaVersion {
		t.Errorf("schema version: got %d want %d", report.SchemaVersion, schemaVersion)
	}
}

func TestBackfillSessions_OneHostOneTxn(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	insertOrphanTxn(t, store, "host-a", time.Now().UTC().Truncate(time.Microsecond))

	report, err := store.BackfillSessions(ctx)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if report.SessionsCreated != 1 {
		t.Errorf("expected 1 session; got %d", report.SessionsCreated)
	}
	if report.TransactionsAttached != 1 {
		t.Errorf("expected 1 attached; got %d", report.TransactionsAttached)
	}

	// Confirm the synthetic session exists with the
	// "legacy-backfill" subcommand.
	sessions, err := store.ListSessions(ctx, "host-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session; got %d", len(sessions))
	}
	if sessions[0].Subcommand != "legacy-backfill" {
		t.Errorf("subcommand: got %q want legacy-backfill", sessions[0].Subcommand)
	}
	if sessions[0].TxnTotal != 1 || sessions[0].TxnCommitted != 1 {
		t.Errorf("counts wrong: %+v", sessions[0])
	}
}

func TestBackfillSessions_MultipleHosts(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	insertOrphanTxn(t, store, "host-a", now)
	insertOrphanTxn(t, store, "host-a", now.Add(time.Minute))
	insertOrphanTxn(t, store, "host-b", now.Add(2*time.Minute))

	report, err := store.BackfillSessions(ctx)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if report.SessionsCreated != 2 {
		t.Errorf("expected 2 sessions (one per host); got %d", report.SessionsCreated)
	}
	if report.TransactionsAttached != 3 {
		t.Errorf("expected 3 attached; got %d", report.TransactionsAttached)
	}
}

func TestBackfillSessions_Idempotent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	insertOrphanTxn(t, store, "host-a", time.Now().UTC().Truncate(time.Microsecond))

	first, err := store.BackfillSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.SessionsCreated != 1 {
		t.Fatal("first run should create 1 session")
	}

	second, err := store.BackfillSessions(ctx)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if second.SessionsCreated != 0 || second.TransactionsAttached != 0 {
		t.Errorf("second run should be no-op; got %+v", second)
	}
}

func TestBackfillSessions_PreservesPostPhase4Sessions(t *testing.T) {
	// A real Phase-4 session (manually created) must NOT be
	// counted as a candidate for backfill — its transactions
	// already have non-NULL session_id.
	store := openTestStore(t)
	ctx := context.Background()

	realSess := &Session{
		ID:         uuid.New(),
		StartedAt:  time.Now().UTC().Truncate(time.Microsecond),
		Hostname:   "host-real",
		Subcommand: "check",
	}
	if err := store.CreateSession(ctx, realSess); err != nil {
		t.Fatal(err)
	}

	// Insert a transaction attached to the real session.
	txnID := insertOrphanTxn(t, store, "host-real", realSess.StartedAt)
	if err := store.AttachTransaction(ctx, txnID, realSess.ID); err != nil {
		t.Fatal(err)
	}

	// Insert a separate orphan on a different host.
	insertOrphanTxn(t, store, "host-orphan", realSess.StartedAt)

	report, err := store.BackfillSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.SessionsCreated != 1 {
		t.Errorf("only host-orphan should produce a session; got %d", report.SessionsCreated)
	}
	if report.TransactionsAttached != 1 {
		t.Errorf("only the orphan txn should be attached; got %d", report.TransactionsAttached)
	}

	// The real session must still exist with its original metadata.
	got, err := store.GetSession(ctx, realSess.ID)
	if err != nil {
		t.Fatalf("real session lost: %v", err)
	}
	if got.Subcommand != "check" {
		t.Errorf("real session's subcommand changed: %q", got.Subcommand)
	}
}

func TestCurrentSchemaVersion(t *testing.T) {
	store := openTestStore(t)
	v, err := store.CurrentSchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v != schemaVersion {
		t.Errorf("got %d want %d", v, schemaVersion)
	}
}
