// Tests for the C-049 `kensa rollback --list/--info/--start`
// session-aware modes.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/Hanalyx/kensa-go/internal/store"
)

// makeRollbackStore seeds a temp DB with one rollback-able
// session (host-a, 2 committed txns) and one with no committed
// txns (all rolled_back). Returns the db path and the
// rollback-able session ID for use in --info / --start tests.
func makeRollbackStore(t *testing.T) (path string, rollbackable uuid.UUID, empty uuid.UUID) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "rollback.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	rollbackable = uuid.New()
	empty = uuid.New()

	if err := s.CreateSession(context.Background(), &store.Session{
		ID: rollbackable, StartedAt: now.Add(-1 * time.Hour),
		Hostname: "host-a", Subcommand: "remediate",
		TxnTotal: 2, TxnCommitted: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(context.Background(), &store.Session{
		ID: empty, StartedAt: now,
		Hostname: "host-b", Subcommand: "check",
		TxnTotal: 1, TxnRolled: 1, // no committed
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	insert := func(sessID uuid.UUID, ruleID, status string, when time.Time) {
		whenStr := when.UTC().Format(time.RFC3339Nano)
		if _, err := db.ExecContext(context.Background(), `
            INSERT INTO transactions (
                id, rule_id, host_id, fleet_id, status, transactional, severity,
                started_at, finished_at, envelope_json, envelope_sig, session_id)
            VALUES (?, ?, 'host-a', '', ?, 1, 'high', ?, ?, '{}', X'', ?)`,
			uuid.New().String(), ruleID, status, whenStr, whenStr, sessID.String()); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insert(rollbackable, "rule-a", "committed", now.Add(-1*time.Hour))
	insert(rollbackable, "rule-b", "committed", now.Add(-1*time.Hour).Add(1*time.Second))
	insert(empty, "rule-c", "rolled_back", now)
	return path, rollbackable, empty
}

// TestRunRollback_ListMode locks AC-01.
func TestRunRollback_ListMode(t *testing.T) {
	path, rollbackable, _ := makeRollbackStore(t)
	stdout, _ := captureRunCLI([]string{"--db", path, "rollback", "--list"}, t)
	if !strings.Contains(stdout, "kensa rollback --list") {
		t.Errorf("missing header; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 rollback-able session(s)") {
		t.Errorf("expected '1 rollback-able session(s)' (the no-committed session must be excluded); got:\n%s", stdout)
	}
	if !strings.Contains(stdout, rollbackable.String()) {
		t.Errorf("expected rollback-able session UUID; got:\n%s", stdout)
	}
}

// TestRunRollback_ListExcludesCheckSessions locks the safety
// filter caught by peer review: a `kensa check --store` session
// with committed txns must NOT appear as rollback-able. Calling
// svc.Rollback on those would silently report success while
// doing nothing (no pre-state captured for check txns).
func TestRunRollback_ListExcludesCheckSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "check.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	checkSess := uuid.New()
	if err := s.CreateSession(context.Background(), &store.Session{
		ID: checkSess, StartedAt: now, Hostname: "host-a",
		Subcommand: "check", // CRITICAL: check, not remediate
		TxnTotal:   2, TxnCommitted: 2,
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	stdout, _ := captureRunCLI([]string{"--db", path, "rollback", "--list"}, t)
	if !strings.Contains(stdout, "no rollback-able sessions") {
		t.Errorf("check session must not appear as rollback-able; got:\n%s", stdout)
	}
	if strings.Contains(stdout, checkSess.String()) {
		t.Errorf("check session UUID should not appear; got:\n%s", stdout)
	}
}

// TestRunRollback_StartRejectsCheckSession locks the runner-
// level defense-in-depth: even if the operator targets a check
// session directly via --start <id>, the runner rejects it
// before invoking svc.Rollback.
func TestRunRollback_StartRejectsCheckSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "check-start.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	checkSess := uuid.New()
	if err := s.CreateSession(context.Background(), &store.Session{
		ID: checkSess, StartedAt: now, Hostname: "host-a",
		Subcommand: "check", TxnTotal: 1, TxnCommitted: 1,
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	exit := runCLI([]string{"--db", path, "rollback", "--start", checkSess.String(), "-H", "host-a"})
	if exit != 2 {
		t.Errorf("--start against check session should exit 2 (usage error); got %d", exit)
	}
	_, stderr := captureRunCLI(
		[]string{"--db", path, "rollback", "--start", checkSess.String(), "-H", "host-a"}, t,
	)
	if !strings.Contains(stderr, "remediate") {
		t.Errorf("error should explain only remediate sessions are rollback-able; got:\n%s", stderr)
	}
}

// TestRunRollback_StartRejectsEmptyHostname locks the empty-
// hostname guard (R1 peer review): legacy-backfill sessions
// with no recorded hostname can't safely target a host.
func TestRunRollback_StartRejectsEmptyHostname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-host.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	emptyHostSess := uuid.New()
	if err := s.CreateSession(context.Background(), &store.Session{
		ID: emptyHostSess, StartedAt: now,
		Hostname:   "", // legacy backfill
		Subcommand: "remediate", TxnTotal: 1, TxnCommitted: 1,
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	exit := runCLI([]string{"--db", path, "rollback", "--start", emptyHostSess.String(), "-H", "host-a"})
	if exit != 2 {
		t.Errorf("--start with empty session hostname should exit 2; got %d", exit)
	}
	_, stderr := captureRunCLI(
		[]string{"--db", path, "rollback", "--start", emptyHostSess.String(), "-H", "host-a"}, t,
	)
	if !strings.Contains(stderr, "no recorded hostname") {
		t.Errorf("error should explain the empty-hostname rejection; got:\n%s", stderr)
	}
}

// TestRunRollback_ListWithDetail locks AC-08 (compose with
// --detail).
func TestRunRollback_ListWithDetail(t *testing.T) {
	path, _, _ := makeRollbackStore(t)
	stdout, _ := captureRunCLI([]string{"--db", path, "rollback", "--list", "--detail"}, t)
	for _, want := range []string{"rule-a", "rule-b", "committed"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--detail should expose rule IDs + statuses; missing %q in:\n%s", want, stdout)
		}
	}
}

// TestRunRollback_InfoMode locks AC-02.
func TestRunRollback_InfoMode(t *testing.T) {
	path, sessID, _ := makeRollbackStore(t)
	stdout, _ := captureRunCLI([]string{
		"--db", path, "rollback", "--info", sessID.String(),
	}, t)
	if !strings.Contains(stdout, "Session: "+sessID.String()) {
		t.Errorf("missing session header; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "hostname:      host-a") {
		t.Errorf("missing hostname line; got:\n%s", stdout)
	}
	for _, want := range []string{"rule-a", "rule-b"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--info should list session txns; missing %q in:\n%s", want, stdout)
		}
	}
}

// TestRunRollback_ListJSONShape locks AC-09 for --list.
func TestRunRollback_ListJSONShape(t *testing.T) {
	path, _, _ := makeRollbackStore(t)
	stdout, _ := captureRunCLI([]string{
		"--db", path, "rollback", "--list", "--format", "json",
	}, t)
	var got struct {
		Sessions []struct {
			ID           string `json:"id"`
			Hostname     string `json:"hostname"`
			TxnCommitted int    `json:"txn_committed"`
			TxnTotal     int    `json:"txn_total"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, stdout)
	}
	if len(got.Sessions) != 1 {
		t.Errorf("expected 1 session; got %d", len(got.Sessions))
	}
	for _, snake := range []string{`"sessions":`, `"txn_committed":`, `"txn_total":`} {
		if !strings.Contains(stdout, snake) {
			t.Errorf("expected snake_case %q in:\n%s", snake, stdout)
		}
	}
}

// TestRunRollback_InfoJSONShape locks AC-09 for --info.
func TestRunRollback_InfoJSONShape(t *testing.T) {
	path, sessID, _ := makeRollbackStore(t)
	stdout, _ := captureRunCLI([]string{
		"--db", path, "rollback", "--info", sessID.String(), "--format", "json",
	}, t)
	var got struct {
		Session struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
		} `json:"session"`
		Transactions []struct {
			RuleID string `json:"rule_id"`
			Status string `json:"status"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, stdout)
	}
	if got.Session.ID != sessID.String() {
		t.Errorf("session ID: got %q want %q", got.Session.ID, sessID.String())
	}
	if len(got.Transactions) != 2 {
		t.Errorf("expected 2 transactions; got %d", len(got.Transactions))
	}
}

// TestRunRollback_ModeMutualExclusion locks AC-03.
func TestRunRollback_ModeMutualExclusion(t *testing.T) {
	path, sessID, _ := makeRollbackStore(t)
	cases := [][]string{
		{"--db", path, "rollback", "--list", "--info", sessID.String()},
		{"--db", path, "rollback", "--list", "--start", sessID.String()},
		{"--db", path, "rollback", "--info", sessID.String(), "--start", sessID.String()},
		{"--db", path, "rollback", "--list", "--txn", uuid.New().String()},
		{"--db", path, "rollback", "--info", sessID.String(), "--txn", uuid.New().String()},
		{"--db", path, "rollback", "--start", sessID.String(), "--txn", uuid.New().String()},
	}
	for _, args := range cases {
		exit := runCLI(args)
		if exit != 2 {
			t.Errorf("runCLI(%v) = %d, want 2", args, exit)
		}
	}
}

// TestRunRollback_NoMode locks AC-04.
func TestRunRollback_NoMode(t *testing.T) {
	path, _, _ := makeRollbackStore(t)
	exit := runCLI([]string{"--db", path, "rollback"})
	if exit != 2 {
		t.Errorf("no mode should exit 2; got %d", exit)
	}
	_, stderr := captureRunCLI([]string{"--db", path, "rollback"}, t)
	if !strings.Contains(stderr, "--list") || !strings.Contains(stderr, "--info") {
		t.Errorf("error should list available modes; got:\n%s", stderr)
	}
}

// TestRunRollback_MissingSessionExitCode locks AC-05.
func TestRunRollback_MissingSessionExitCode(t *testing.T) {
	path, _, _ := makeRollbackStore(t)
	missing := uuid.New()
	exit := runCLI([]string{"--db", path, "rollback", "--info", missing.String()})
	if exit != 1 {
		t.Errorf("missing session in --info should exit 1; got %d", exit)
	}
	_, stderr := captureRunCLI([]string{"--db", path, "rollback", "--info", missing.String()}, t)
	if strings.Contains(stderr, "no rows") {
		t.Errorf("error should not leak SQL internals; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "kensa rollback --list") && !strings.Contains(stderr, "kensa list sessions") {
		t.Errorf("error should suggest a discovery command; got:\n%s", stderr)
	}
}

// TestRunRollback_InfoBadUUID locks AC-06.
func TestRunRollback_InfoBadUUID(t *testing.T) {
	path, _, _ := makeRollbackStore(t)
	exit := runCLI([]string{"--db", path, "rollback", "--info", "not-a-uuid"})
	if exit != 2 {
		t.Errorf("bad UUID should exit 2; got %d", exit)
	}
}

// TestRunRollback_StartHostnameGuard locks AC-07.
func TestRunRollback_StartHostnameGuard(t *testing.T) {
	path, sessID, _ := makeRollbackStore(t) // session is on host-a
	// Missing --host:
	exit := runCLI([]string{"--db", path, "rollback", "--start", sessID.String()})
	if exit != 2 {
		t.Errorf("--start without --host should exit 2; got %d", exit)
	}
	// Mismatched --host:
	exit = runCLI([]string{"--db", path, "rollback", "--start", sessID.String(), "-H", "host-b"})
	if exit != 2 {
		t.Errorf("--start hostname mismatch should exit 2; got %d", exit)
	}
	_, stderr := captureRunCLI([]string{"--db", path, "rollback", "--start", sessID.String(), "-H", "host-b"}, t)
	if !strings.Contains(stderr, "hostname mismatch") {
		t.Errorf("error should explain mismatch; got:\n%s", stderr)
	}
}

// TestRunRollback_DetailFlagComposition locks AC-08.
func TestRunRollback_DetailFlagComposition(t *testing.T) {
	path, sessID, _ := makeRollbackStore(t)
	// --detail + --start rejected.
	exit := runCLI([]string{"--db", path, "rollback", "--start", sessID.String(),
		"-H", "host-a", "--detail"})
	if exit != 2 {
		t.Errorf("--detail + --start should exit 2; got %d", exit)
	}
	// --detail + --txn rejected.
	exit = runCLI([]string{"--db", path, "rollback", "--txn", uuid.New().String(),
		"-H", "host-a", "--detail"})
	if exit != 2 {
		t.Errorf("--detail + --txn should exit 2; got %d", exit)
	}
}

// TestRunRollback_BadFormat.
func TestRunRollback_BadFormat(t *testing.T) {
	path, _, _ := makeRollbackStore(t)
	exit := runCLI([]string{"--db", path, "rollback", "--list", "--format", "yaml"})
	if exit != 2 {
		t.Errorf("bad format should exit 2; got %d", exit)
	}
}

// TestRunRollback_HelpExitsZero.
func TestRunRollback_HelpExitsZero(t *testing.T) {
	for _, argv := range [][]string{
		{"rollback", "--help"},
		{"rollback", "-h"},
	} {
		got := runCLI(argv)
		if got != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, got)
		}
	}
}

// TestRunRollback_LegacyTxnFlow: legacy --txn path should
// still validate flags correctly. Doesn't test the actual
// rollback execution (no live host); just exercises the
// usage error paths. Renamed to match spec AC-10's Locked-by
// reference.
func TestRunRollback_LegacyTxnFlow(t *testing.T) {
	path, _, _ := makeRollbackStore(t)
	// --txn without --host.
	exit := runCLI([]string{"--db", path, "rollback", "--txn", uuid.New().String()})
	if exit != 2 {
		t.Errorf("legacy --txn without --host should exit 2; got %d", exit)
	}
	// --txn with bad UUID.
	exit = runCLI([]string{"--db", path, "rollback", "--txn", "not-a-uuid", "-H", "host-a"})
	if exit != 2 {
		t.Errorf("legacy --txn with bad UUID should exit 2; got %d", exit)
	}
}

// TestRunRollback_StartJSONShape locks the JSON shape for the
// --start path (R1 peer review caught this gap; AC-09 named
// only --list and --info). Uses a remediate session with zero
// committed txns so the runner returns Attempted=0 + empty
// PerTxn without invoking svc.Rollback (which would need a
// live host). The struct shape is what we're locking.
func TestRunRollback_StartJSONShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "start-json.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	sessID := uuid.New()
	if err := s.CreateSession(context.Background(), &store.Session{
		ID: sessID, StartedAt: now, Hostname: "host-a",
		Subcommand: "remediate", TxnTotal: 0, TxnCommitted: 0,
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	stdout, _ := captureRunCLI([]string{
		"--db", path, "rollback", "--start", sessID.String(), "-H", "host-a", "--format", "json",
	}, t)
	var got struct {
		SessionID string `json:"session_id"`
		Attempted int    `json:"attempted"`
		Succeeded int    `json:"succeeded"`
		Failed    int    `json:"failed"`
		PerTxn    []any  `json:"per_txn"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal: %v\nstdout:\n%s", err, stdout)
	}
	if got.SessionID != sessID.String() {
		t.Errorf("session_id: got %q want %q", got.SessionID, sessID.String())
	}
	if got.Attempted != 0 || got.Succeeded != 0 || got.Failed != 0 {
		t.Errorf("zero-committed session: got attempted=%d succeeded=%d failed=%d",
			got.Attempted, got.Succeeded, got.Failed)
	}
	for _, snake := range []string{`"session_id":`, `"attempted":`, `"succeeded":`, `"failed":`, `"per_txn":`} {
		if !strings.Contains(stdout, snake) {
			t.Errorf("expected snake_case %q in JSON:\n%s", snake, stdout)
		}
	}
}

// TestRunRollback_EmptyStoreList: no committed txns anywhere
// produces a clean "no rollback-able sessions" message rather
// than a confusing "0 sessions" with empty output.
func TestRunRollback_EmptyStoreList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	stdout, _ := captureRunCLI([]string{"--db", path, "rollback", "--list"}, t)
	if !strings.Contains(stdout, "no rollback-able sessions") {
		t.Errorf("empty store should show 'no rollback-able sessions'; got:\n%s", stdout)
	}
}
