package kensa

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/store"
)

// TestRecordRemediateSession_GroupsCommittedTxns locks the fix for the
// NULL-session-id gap: the engine persists each remediation transaction with
// session_id=NULL, so without grouping they are invisible to the session-aware
// rollback workflow (`kensa list sessions`, `rollback --start`) and reachable
// only by `rollback --txn UUID`. RecordRemediateSession must create a session
// and attach the committed transactions so the workflow finds them.
func TestRecordRemediateSession_GroupsCommittedTxns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remediate.db")

	// Seed two committed transactions with NULL session_id — exactly the state
	// the engine's PersistResult leaves them in during a remediation. The seed
	// handle is closed (checkpointing the WAL) before the service opens, so the
	// rows are visible to the service's store handle.
	seed, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = seed.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	id1, id2 := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{id1, id2} {
		if _, err := db.ExecContext(context.Background(), `
            INSERT INTO transactions (
                id, rule_id, host_id, fleet_id, status, transactional, severity,
                started_at, finished_at, envelope_json, envelope_sig, session_id)
            VALUES (?, 'rule-x', 'host-a', '', 'committed', 1, 'low', ?, ?, '{}', X'', NULL)`,
			id.String(), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("seed txn: %v", err)
		}
	}
	_ = db.Close()

	svc, err := DefaultWithTransportFactory(context.Background(), path, &fakeFactory{})
	if err != nil {
		t.Fatalf("DefaultWithTransportFactory: %v", err)
	}

	result := &api.RemediationResult{
		HostID: "host-a",
		Transactions: []api.TransactionResult{
			{TransactionID: id1, Status: api.StatusCommitted, StartedAt: now},
			{TransactionID: id2, Status: api.StatusCommitted, StartedAt: now.Add(time.Second)},
		},
	}
	sessID, err := svc.RecordRemediateSession(context.Background(), "host-a", result)
	if err != nil {
		t.Fatalf("RecordRemediateSession: %v", err)
	}
	if sessID == uuid.Nil {
		t.Fatal("expected a non-nil session id")
	}
	_ = svc.Close() // checkpoint the attaches before re-reading

	verify, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer verify.Close()
	post, err := verify.RollbackableSessions(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(post) != 1 {
		t.Fatalf("expected 1 rollback-able session after grouping, got %d", len(post))
	}
	if post[0].ID != sessID || post[0].Subcommand != "remediate" {
		t.Errorf("session = {id:%s sub:%s}, want {id:%s sub:remediate}", post[0].ID, post[0].Subcommand, sessID)
	}
	if post[0].TxnCommitted != 2 {
		t.Errorf("TxnCommitted = %d, want 2 (both txns attached and counted)", post[0].TxnCommitted)
	}
}

// TestRecordRemediateSession_NoTransactions is a no-op for an empty result —
// nothing to group, no session created, no error.
func TestRecordRemediateSession_NoTransactions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	svc, err := DefaultWithTransportFactory(context.Background(), path, &fakeFactory{})
	if err != nil {
		t.Fatalf("DefaultWithTransportFactory: %v", err)
	}
	defer func() { _ = svc.Close() }()

	sessID, err := svc.RecordRemediateSession(context.Background(), "host-a", &api.RemediationResult{})
	if err != nil {
		t.Fatalf("RecordRemediateSession on empty result: %v", err)
	}
	if sessID != uuid.Nil {
		t.Errorf("expected uuid.Nil for empty result, got %s", sessID)
	}
}
