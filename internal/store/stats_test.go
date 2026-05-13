// Tests for the C-042 ComputeStats helper.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func insertTxn(t *testing.T, store *SQLite, hostID, status, severity string, started time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := store.db.Exec(`
        INSERT INTO transactions (
            id, rule_id, host_id, fleet_id, status, transactional, severity,
            started_at, finished_at,
            envelope_json, envelope_sig)
        VALUES (?, 'rule-x', ?, '', ?, 1, ?,
                ?, ?,
                '{}', X'')`,
		id.String(), hostID, status, severity,
		started.UTC().Format(time.RFC3339Nano),
		started.Add(time.Second).UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatalf("insert txn: %v", err)
	}
	return id
}

func TestComputeStats_EmptyStore(t *testing.T) {
	t.Run("store-session-schema/AC-01", func(t *testing.T) {})
	store := openTestStore(t)
	st, err := store.ComputeStats(context.Background(), StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if st.SessionsTotal != 0 || st.TransactionsTotal != 0 {
		t.Errorf("empty store should produce zero counts; got %+v", st)
	}
	if !st.EarliestStartedAt.IsZero() {
		t.Errorf("empty store should have zero EarliestStartedAt; got %v", st.EarliestStartedAt)
	}
}

func TestComputeStats_BasicCounts(t *testing.T) {
	t.Run("store-session-schema/AC-02", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertTxn(t, store, "host-a", "committed", "high", now)
	insertTxn(t, store, "host-a", "committed", "high", now.Add(time.Second))
	insertTxn(t, store, "host-b", "rolled_back", "critical", now.Add(2*time.Second))
	insertTxn(t, store, "host-b", "errored", "low", now.Add(3*time.Second))

	st, err := store.ComputeStats(context.Background(), StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if st.TransactionsTotal != 4 {
		t.Errorf("total: got %d want 4", st.TransactionsTotal)
	}
	if st.ByStatus["committed"] != 2 ||
		st.ByStatus["rolled_back"] != 1 ||
		st.ByStatus["errored"] != 1 {
		t.Errorf("by status wrong: %v", st.ByStatus)
	}
	if st.BySeverity["high"] != 2 ||
		st.BySeverity["critical"] != 1 ||
		st.BySeverity["low"] != 1 {
		t.Errorf("by severity wrong: %v", st.BySeverity)
	}
	if st.ByHost["host-a"] != 2 || st.ByHost["host-b"] != 2 {
		t.Errorf("by host wrong: %v", st.ByHost)
	}
}

func TestComputeStats_UnsetSeverityNormalized(t *testing.T) {
	t.Run("store-session-schema/AC-03", func(t *testing.T) {})
	store := openTestStore(t)
	insertTxn(t, store, "host-a", "committed", "", time.Now().UTC().Truncate(time.Microsecond))

	st, err := store.ComputeStats(context.Background(), StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if st.BySeverity["(unset)"] != 1 {
		t.Errorf("empty severity should normalize to (unset); got %v", st.BySeverity)
	}
	if _, hasEmpty := st.BySeverity[""]; hasEmpty {
		t.Errorf("empty-string key should be removed")
	}
}

func TestComputeStats_FilterByHost(t *testing.T) {
	t.Run("store-session-schema/AC-04", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertTxn(t, store, "host-a", "committed", "high", now)
	insertTxn(t, store, "host-b", "committed", "high", now.Add(time.Second))

	st, err := store.ComputeStats(context.Background(), StatsFilter{Host: "host-a"})
	if err != nil {
		t.Fatal(err)
	}
	if st.TransactionsTotal != 1 {
		t.Errorf("host filter should narrow; got %d", st.TransactionsTotal)
	}
	if _, ok := st.ByHost["host-b"]; ok {
		t.Errorf("host-b should not appear in filtered stats")
	}
}

func TestComputeStats_FilterBySince(t *testing.T) {
	t.Run("store-session-schema/AC-05", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertTxn(t, store, "host-a", "committed", "high", now.Add(-2*time.Hour))
	insertTxn(t, store, "host-a", "committed", "high", now)

	st, err := store.ComputeStats(context.Background(), StatsFilter{Since: now.Add(-1 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if st.TransactionsTotal != 1 {
		t.Errorf("since filter should narrow to 1; got %d", st.TransactionsTotal)
	}
}

func TestComputeStats_TopHostsRollup(t *testing.T) {
	t.Run("store-session-schema/AC-06", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	// Insert 5 hosts with descending transaction counts.
	for hostNum, count := range map[string]int{
		"host-a": 5,
		"host-b": 4,
		"host-c": 3,
		"host-d": 2,
		"host-e": 1,
	} {
		for i := 0; i < count; i++ {
			insertTxn(t, store, hostNum, "committed", "high",
				now.Add(time.Duration(i)*time.Second))
		}
	}
	st, err := store.ComputeStats(context.Background(), StatsFilter{TopHostsLimit: 3})
	if err != nil {
		t.Fatal(err)
	}
	// Top 3 by count: host-a (5), host-b (4), host-c (3).
	if st.ByHost["host-a"] != 5 || st.ByHost["host-b"] != 4 || st.ByHost["host-c"] != 3 {
		t.Errorf("top 3 wrong: %v", st.ByHost)
	}
	// host-d (2) + host-e (1) → (other) = 3.
	if st.ByHost["(other)"] != 3 {
		t.Errorf("rollup wrong: got (other)=%d want 3", st.ByHost["(other)"])
	}
	// host-d / host-e should NOT appear individually.
	if _, ok := st.ByHost["host-d"]; ok {
		t.Errorf("host-d should be rolled up")
	}
}

func TestComputeStats_TimeWindow(t *testing.T) {
	t.Run("store-session-schema/AC-07", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	insertTxn(t, store, "host-a", "committed", "high", now.Add(-time.Hour))
	insertTxn(t, store, "host-a", "committed", "high", now)

	st, err := store.ComputeStats(context.Background(), StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if st.EarliestStartedAt.IsZero() || st.LatestFinishedAt.IsZero() {
		t.Errorf("time window should be populated; got earliest=%v latest=%v",
			st.EarliestStartedAt, st.LatestFinishedAt)
	}
	if !st.EarliestStartedAt.Before(st.LatestFinishedAt) {
		t.Errorf("earliest %v should be before latest %v",
			st.EarliestStartedAt, st.LatestFinishedAt)
	}
}

// TestRollupTopN_TieBreakerAlphabetical exercises the
// tie-breaking branch of rollupTopN. C-04 specifies that
// hosts with equal counts resolve alphabetically; without a
// dedicated test the path was unexercised since the basic
// rollup test uses distinct counts.
func TestRollupTopN_TieBreakerAlphabetical(t *testing.T) {
	t.Run("store-session-schema/AC-08", func(t *testing.T) {})
	store := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	// Three hosts each with 2 transactions. Limit=2, so one
	// host rolls into (other).
	for _, h := range []string{"host-z", "host-a", "host-m"} {
		for i := 0; i < 2; i++ {
			insertTxn(t, store, h, "committed", "high",
				now.Add(time.Duration(i)*time.Second))
		}
	}
	st, err := store.ComputeStats(context.Background(), StatsFilter{TopHostsLimit: 2})
	if err != nil {
		t.Fatal(err)
	}
	// Alphabetical winners: host-a, host-m. host-z rolls up.
	if _, ok := st.ByHost["host-a"]; !ok {
		t.Errorf("host-a should win on alphabetical tiebreak; got %v", st.ByHost)
	}
	if _, ok := st.ByHost["host-m"]; !ok {
		t.Errorf("host-m should win on alphabetical tiebreak; got %v", st.ByHost)
	}
	if _, ok := st.ByHost["host-z"]; ok {
		t.Errorf("host-z should be rolled up; got %v", st.ByHost)
	}
	if st.ByHost["(other)"] != 2 {
		t.Errorf("(other) should hold 2; got %d", st.ByHost["(other)"])
	}
}

// TestComputeStats_SinceNarrowsBothTotals locks the AC-05 +
// AC-08 intersection: --since narrows both transaction count
// AND session count, not just transactions.
func TestComputeStats_SinceNarrowsBothTotals(t *testing.T) {
	t.Run("store-session-schema/AC-09", func(t *testing.T) {})
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Old session + transaction (before cutoff).
	oldSess := &Session{
		ID:        uuid.New(),
		StartedAt: now.Add(-2 * time.Hour),
		Hostname:  "host-a",
	}
	if err := store.CreateSession(ctx, oldSess); err != nil {
		t.Fatal(err)
	}
	insertTxn(t, store, "host-a", "committed", "high", now.Add(-2*time.Hour))

	// Recent session + transaction (after cutoff).
	recentSess := &Session{
		ID:        uuid.New(),
		StartedAt: now,
		Hostname:  "host-a",
	}
	if err := store.CreateSession(ctx, recentSess); err != nil {
		t.Fatal(err)
	}
	insertTxn(t, store, "host-a", "committed", "high", now)

	st, err := store.ComputeStats(ctx, StatsFilter{Since: now.Add(-1 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if st.TransactionsTotal != 1 {
		t.Errorf("--since should narrow transactions to 1; got %d", st.TransactionsTotal)
	}
	if st.SessionsTotal != 1 {
		t.Errorf("--since should narrow sessions to 1 too; got %d", st.SessionsTotal)
	}
}

func TestComputeStats_SessionsCounted(t *testing.T) {
	t.Run("store-session-schema/AC-10", func(t *testing.T) {})
	store := openTestStore(t)
	ctx := context.Background()

	sess := &Session{
		ID:        uuid.New(),
		StartedAt: time.Now().UTC().Truncate(time.Microsecond),
		Hostname:  "host-a",
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}

	st, err := store.ComputeStats(ctx, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if st.SessionsTotal != 1 {
		t.Errorf("expected 1 session; got %d", st.SessionsTotal)
	}
}
