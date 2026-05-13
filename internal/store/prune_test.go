// Tests for the C-043 prune workflow.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// insertPruneFixture seeds a session row + a transaction row attached
// to it, plus one row in each child table, all with the given
// started_at timestamp on the session AND the transaction. Returns
// the txn ID so callers can also assert post-prune.
//
// All test fixtures use direct INSERTs rather than PersistResult /
// CreateSession so the prune-test set-up is independent of the
// higher-level write path's evolution.
func insertPruneFixture(t *testing.T, store *SQLite, sessID uuid.UUID, hostID string, when time.Time) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	whenStr := when.UTC().Format(time.RFC3339Nano)

	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO sessions (
            id, started_at, finished_at, hostname, subcommand, args_summary,
            txn_total, txn_committed, txn_rolled, txn_failed)
        VALUES (?, ?, ?, ?, 'check', '', 0, 0, 0, 0)`,
		sessID.String(), whenStr, whenStr, hostID); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	txnID := uuid.New()
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO transactions (
            id, rule_id, host_id, fleet_id, status, transactional, severity,
            started_at, finished_at, envelope_json, envelope_sig, session_id)
        VALUES (?, 'rule-x', ?, '', 'committed', 1, 'high', ?, ?, '{}', X'', ?)`,
		txnID.String(), hostID, whenStr, whenStr, sessID.String()); err != nil {
		t.Fatalf("insert transaction: %v", err)
	}

	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO steps (transaction_id, step_index, mechanism, capturable, success, detail)
        VALUES (?, 0, 'check', 1, 1, 'ok')`, txnID.String()); err != nil {
		t.Fatalf("insert step: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO pre_states (transaction_id, step_index, mechanism, capturable, state_json, captured_at)
        VALUES (?, 0, 'check', 1, '{}', ?)`, txnID.String(), whenStr); err != nil {
		t.Fatalf("insert pre_state: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO framework_refs (transaction_id, framework_id, control_id)
        VALUES (?, 'cis_rhel9', '5.1.1')`, txnID.String()); err != nil {
		t.Fatalf("insert framework_ref: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO rollback_events (transaction_id, step_index, source, executed_at, success, detail)
        VALUES (?, 0, 'engine', ?, 1, '')`, txnID.String(), whenStr); err != nil {
		t.Fatalf("insert rollback_event: %v", err)
	}

	return txnID
}

// insertOrphanTransaction inserts a transaction with NULL session_id
// at the given timestamp. Models pre-Phase-4 / unmigrated rows.
func insertOrphanTransaction(t *testing.T, store *SQLite, hostID string, when time.Time) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	whenStr := when.UTC().Format(time.RFC3339Nano)

	txnID := uuid.New()
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO transactions (
            id, rule_id, host_id, fleet_id, status, transactional, severity,
            started_at, finished_at, envelope_json, envelope_sig)
        VALUES (?, 'rule-orphan', ?, '', 'committed', 1, 'low', ?, ?, '{}', X'')`,
		txnID.String(), hostID, whenStr, whenStr); err != nil {
		t.Fatalf("insert orphan transaction: %v", err)
	}
	// Add one step too so the cascade has something to delete.
	if _, err := store.db.ExecContext(ctx, `
        INSERT INTO steps (transaction_id, step_index, mechanism, capturable, success, detail)
        VALUES (?, 0, 'check', 1, 1, 'ok-orphan')`, txnID.String()); err != nil {
		t.Fatalf("insert orphan step: %v", err)
	}
	return txnID
}

// countTable returns SELECT COUNT(*) FROM table for assertions.
func countTable(t *testing.T, store *SQLite, table string) int {
	t.Helper()
	var n int
	row := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table) //nolint:gosec // table name is hardcoded in test
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestPruneSessions_Basic(t *testing.T) {
	t.Run("store-session-schema/AC-10", func(t *testing.T) {})
	t.Run("store-session-schema/AC-01", func(t *testing.T) {})
	store := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	old := now.Add(-30 * 24 * time.Hour)
	cutoff := now.Add(-7 * 24 * time.Hour)

	insertPruneFixture(t, store, uuid.New(), "host-old", old)

	report, err := store.PruneSessions(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.SessionsDeleted != 1 {
		t.Errorf("SessionsDeleted: got %d want 1", report.SessionsDeleted)
	}
	if report.TransactionsDeleted != 1 {
		t.Errorf("TransactionsDeleted: got %d want 1", report.TransactionsDeleted)
	}

	if got := countTable(t, store, "sessions"); got != 0 {
		t.Errorf("sessions remaining: %d", got)
	}
	if got := countTable(t, store, "transactions"); got != 0 {
		t.Errorf("transactions remaining: %d", got)
	}
}

func TestPruneSessions_EmptyStore(t *testing.T) {
	t.Run("store-session-schema/AC-02", func(t *testing.T) {})
	store := openTestStore(t)
	report, err := store.PruneSessions(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.SessionsDeleted != 0 ||
		report.TransactionsDeleted != 0 ||
		report.StepsDeleted != 0 ||
		report.PreStatesDeleted != 0 ||
		report.FrameworkRefsDeleted != 0 ||
		report.RollbackEventsDeleted != 0 {
		t.Errorf("empty store should produce zero counts; got %+v", report)
	}
}

func TestPruneSessions_CascadeAllTables(t *testing.T) {
	t.Run("store-session-schema/AC-03", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := now.Add(-30 * 24 * time.Hour)
	cutoff := now.Add(-7 * 24 * time.Hour)

	insertPruneFixture(t, store, uuid.New(), "host-a", old)

	report, err := store.PruneSessions(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.StepsDeleted != 1 {
		t.Errorf("StepsDeleted: got %d want 1", report.StepsDeleted)
	}
	if report.PreStatesDeleted != 1 {
		t.Errorf("PreStatesDeleted: got %d want 1", report.PreStatesDeleted)
	}
	if report.FrameworkRefsDeleted != 1 {
		t.Errorf("FrameworkRefsDeleted: got %d want 1", report.FrameworkRefsDeleted)
	}
	if report.RollbackEventsDeleted != 1 {
		t.Errorf("RollbackEventsDeleted: got %d want 1", report.RollbackEventsDeleted)
	}
	for _, tbl := range []string{"steps", "pre_states", "framework_refs", "rollback_events"} {
		if got := countTable(t, store, tbl); got != 0 {
			t.Errorf("%s should be empty post-prune; got %d", tbl, got)
		}
	}
}

func TestPruneSessions_OrphansPruned(t *testing.T) {
	t.Run("store-session-schema/AC-04", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := now.Add(-30 * 24 * time.Hour)
	recent := now.Add(-1 * time.Hour)
	cutoff := now.Add(-7 * 24 * time.Hour)

	oldOrphan := insertOrphanTransaction(t, store, "host-x", old)
	recentOrphan := insertOrphanTransaction(t, store, "host-x", recent)

	report, err := store.PruneSessions(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	// One orphan deleted; one preserved.
	if report.TransactionsDeleted != 1 {
		t.Errorf("TransactionsDeleted: got %d want 1", report.TransactionsDeleted)
	}
	if report.OrphanTransactionsDeleted != 1 {
		t.Errorf("OrphanTransactionsDeleted: got %d want 1", report.OrphanTransactionsDeleted)
	}

	// Explicit identity assertions (not "first row in the
	// result set"): the old orphan must be gone, the recent
	// orphan must remain.
	if got := countWhere(t, store, "transactions", "id", oldOrphan.String()); got != 0 {
		t.Errorf("oldOrphan should have been deleted; rows remaining: %d", got)
	}
	if got := countWhere(t, store, "transactions", "id", recentOrphan.String()); got != 1 {
		t.Errorf("recentOrphan should remain; rows: %d", got)
	}
}

// countWhere returns SELECT COUNT(*) FROM table WHERE col = ?.
// Used by orphan-prune assertions that need identity matching
// rather than "the first surviving row."
func countWhere(t *testing.T, store *SQLite, table, col, val string) int {
	t.Helper()
	var n int
	q := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s = ?`, table, col) //nolint:gosec // hardcoded test inputs
	row := store.db.QueryRow(q, val)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count where: %v", err)
	}
	return n
}

func TestPruneSessions_RecentPreserved(t *testing.T) {
	t.Run("store-session-schema/AC-05", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	cutoff := now.Add(-7 * 24 * time.Hour)
	recent := now.Add(-1 * time.Hour)

	sessID := uuid.New()
	insertPruneFixture(t, store, sessID, "host-recent", recent)

	report, err := store.PruneSessions(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.SessionsDeleted != 0 {
		t.Errorf("recent session should be preserved; deleted %d", report.SessionsDeleted)
	}
	if got := countTable(t, store, "sessions"); got != 1 {
		t.Errorf("sessions count: got %d want 1", got)
	}
	if got := countTable(t, store, "transactions"); got != 1 {
		t.Errorf("transactions count: got %d want 1", got)
	}
}

func TestPruneSessions_TransactionRollback(t *testing.T) {
	t.Run("store-session-schema/AC-06", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := now.Add(-30 * 24 * time.Hour)
	cutoff := now.Add(-7 * 24 * time.Hour)

	insertPruneFixture(t, store, uuid.New(), "host-a", old)

	// Cancel the context immediately to force a context-cancellation
	// failure inside PruneSessions. The deferred Rollback should
	// unwind any partial deletes.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.PruneSessions(ctx, cutoff)
	if err == nil {
		t.Fatal("expected error from canceled context")
	}

	// State must be unchanged: 1 session, 1 transaction, 1 step,
	// 1 pre_state, 1 framework_ref, 1 rollback_event.
	for _, tbl := range []string{"sessions", "transactions", "steps", "pre_states", "framework_refs", "rollback_events"} {
		if got := countTable(t, store, tbl); got != 1 {
			t.Errorf("%s after rollback: got %d want 1", tbl, got)
		}
	}
}

// TestPruneSessions_RollbackMidLoop strengthens AC-06 by
// canceling the context AFTER the prune has begun work. We
// pre-queue 3 fixtures + one context with a 0-deadline timeout
// — the prune begins (BeginTx succeeds since the deadline
// hasn't fired yet thanks to driver scheduling), then ExecContext
// inside the loop will eventually trip on the canceled deadline,
// and the deferred Rollback must unwind any partial deletes.
//
// This is a best-effort proxy for "interrupt mid-loop"; SQLite
// drivers vary in when exactly they observe ctx cancellation.
// The invariant we lock is: the post-error state is one of
// "fully pruned" or "fully unchanged" — never partial.
func TestPruneSessions_RollbackMidLoop(t *testing.T) {
	t.Run("store-session-schema/AC-07", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := now.Add(-30 * 24 * time.Hour)
	cutoff := now.Add(-7 * 24 * time.Hour)

	for i := 0; i < 5; i++ {
		insertPruneFixture(t, store, uuid.New(), fmt.Sprintf("host-%d", i), old)
	}

	// Very short deadline — likely fires inside the per-txn
	// DELETE loop after the first iteration.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	_, err := store.PruneSessions(ctx, cutoff)
	// Either the prune raced to completion (fast machine) or
	// it errored mid-loop. Both outcomes must leave atomic state.
	if err != nil {
		// Errored: full original state must remain.
		for _, tbl := range []string{"sessions", "transactions", "steps", "pre_states"} {
			if got := countTable(t, store, tbl); got != 5 {
				t.Errorf("post-error %s count: got %d want 5 (atomic rollback violated)", tbl, got)
			}
		}
	} else {
		// Succeeded: full prune must have completed.
		for _, tbl := range []string{"sessions", "transactions", "steps", "pre_states"} {
			if got := countTable(t, store, tbl); got != 0 {
				t.Errorf("post-success %s count: got %d want 0", tbl, got)
			}
		}
	}
}

// TestPruneSessions_CascadeCoversAllChildTables guards against
// schema drift: if a future migration adds a sixth child table
// referencing transaction_id and the cascade list in
// PruneSessions isn't updated, this test fails by enumerating
// the schema's transaction_id-bearing tables and comparing
// against the hardcoded cascade list.
//
// Without FK constraints (per transaction-log spec C-02), this
// is the only structural guard against the maintenance landmine.
func TestPruneSessions_CascadeCoversAllChildTables(t *testing.T) {
	t.Run("store-session-schema/AC-08", func(t *testing.T) {})
	store := openTestStore(t)
	rows, err := store.db.Query(`
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND sql LIKE '%transaction_id%'`)
	if err != nil {
		t.Fatalf("query schema: %v", err)
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		// transactions itself has an `id` column, not a
		// `transaction_id` column. Sessions don't reference
		// transaction_id either. The match here is only the
		// child tables that PruneSessions must cascade.
		if name == "transactions" || name == "sessions" || name == "schema_version" {
			continue
		}
		found = append(found, name)
	}
	// Hardcoded list must match the DELETE statements in
	// internal/store/prune.go.
	cascadeList := []string{"steps", "pre_states", "framework_refs", "rollback_events"}
	missing := []string{}
	for _, want := range found {
		if !containsStr(cascadeList, want) {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		t.Errorf("schema has transaction_id-bearing tables not in cascade list: %v\n"+
			"update internal/store/prune.go and this test together",
			missing)
	}
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func TestPruneSessions_MixedAttachedAndOrphan(t *testing.T) {
	t.Run("store-session-schema/AC-09", func(t *testing.T) {})
	// Verify the prune covers both worlds in a single call: an old
	// session-attached row AND an old orphan row both get removed,
	// while their recent counterparts stay.
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := now.Add(-30 * 24 * time.Hour)
	recent := now.Add(-1 * time.Hour)
	cutoff := now.Add(-7 * 24 * time.Hour)

	insertPruneFixture(t, store, uuid.New(), "host-a", old)
	insertPruneFixture(t, store, uuid.New(), "host-b", recent)
	insertOrphanTransaction(t, store, "host-c", old)
	insertOrphanTransaction(t, store, "host-d", recent)

	report, err := store.PruneSessions(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	// 1 old session + 2 old transactions (1 attached + 1 orphan)
	if report.SessionsDeleted != 1 {
		t.Errorf("SessionsDeleted: got %d want 1", report.SessionsDeleted)
	}
	if report.TransactionsDeleted != 2 {
		t.Errorf("TransactionsDeleted: got %d want 2", report.TransactionsDeleted)
	}
	// Sessions remaining: 1 (recent). Transactions remaining: 2
	// (1 recent attached + 1 recent orphan).
	if got := countTable(t, store, "sessions"); got != 1 {
		t.Errorf("sessions remaining: got %d want 1", got)
	}
	if got := countTable(t, store, "transactions"); got != 2 {
		t.Errorf("transactions remaining: got %d want 2", got)
	}
}

// Sanity: the package's own database/sql import is used. (Suppresses
// a stray unused-import warning if the file is ever pruned down.)
var _ = sql.ErrNoRows
