// Tests for the C-048 `kensa diff` flow.
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

	"github.com/Hanalyx/kensa/internal/store"
)

// makeDiffStore creates a temp DB and seeds two sessions with
// per-rule transactions matching the canonical fixture used by
// most tests below. Returns the db path and the two session IDs.
//
// Session1 (host-a, "before"):
//   - rule-removed: committed
//   - rule-changed: committed
//   - rule-unchanged: committed
//
// session2 (hostname2 / "after"):
//   - rule-added: rolled_back
//   - rule-changed: rolled_back
//   - rule-unchanged: committed
func makeDiffStore(t *testing.T, hostname2 string) (path string, sess1, sess2 uuid.UUID) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "diff.db")
	// Apply migrations via the public OpenSQLite path; close
	// before opening a parallel handle for inserts.
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	sess1 = uuid.New()
	sess2 = uuid.New()
	if err := s.CreateSession(context.Background(), &store.Session{
		ID:        sess1,
		StartedAt: now.Add(-1 * time.Hour),
		Hostname:  "host-a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(context.Background(), &store.Session{
		ID:        sess2,
		StartedAt: now,
		Hostname:  hostname2,
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	// Open a parallel raw-SQL handle to insert minimal
	// transaction rows (no envelope, no signing). Same DB
	// file; modernc/sqlite serializes via the WAL.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
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
			t.Fatalf("insert txn %s/%s: %v", ruleID, status, err)
		}
	}
	insert(sess1, "rule-removed", "committed", now.Add(-1*time.Hour))
	insert(sess1, "rule-changed", "committed", now.Add(-1*time.Hour))
	insert(sess1, "rule-unchanged", "committed", now.Add(-1*time.Hour))
	insert(sess2, "rule-added", "rolled_back", now)
	insert(sess2, "rule-changed", "rolled_back", now)
	insert(sess2, "rule-unchanged", "committed", now)
	return path, sess1, sess2
}

// TestRunDiff_Basic locks AC-01: two valid session IDs print
// the drift report end-to-end.
// @spec cli-session-diff
// @ac AC-01
// @ac AC-14
func TestRunDiff_Basic(t *testing.T) {
	t.Run("cli-session-diff/AC-01", func(t *testing.T) {})
	t.Run("cli-session-diff/AC-14", func(t *testing.T) {})
	path, sess1, sess2 := makeDiffStore(t, "host-a")
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "diff", sess1.String(), sess2.String()},
		t,
	)
	for _, want := range []string{
		"kensa diff",
		"changed:   1",
		"added:     1",
		"removed:   1",
		"rule-changed",
		"rule-added",
		"rule-removed",
		"committed -> rolled_back",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("missing %q in stdout:\n%s", want, stdout)
		}
	}
	// Default suppresses unchanged.
	if strings.Contains(stdout, "rule-unchanged") {
		t.Errorf("default should suppress unchanged; got:\n%s", stdout)
	}
}

// TestRunDiff_ShowUnchanged locks AC-10.
// @spec cli-session-diff
// @ac AC-02
// @ac AC-15
func TestRunDiff_ShowUnchanged(t *testing.T) {
	t.Run("cli-session-diff/AC-02", func(t *testing.T) {})
	t.Run("cli-session-diff/AC-15", func(t *testing.T) {})
	path, sess1, sess2 := makeDiffStore(t, "host-a")
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "diff", sess1.String(), sess2.String(), "--show-unchanged"},
		t,
	)
	if !strings.Contains(stdout, "unchanged: 1") {
		t.Errorf("--show-unchanged should report 'unchanged: 1'; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "rule-unchanged") {
		t.Errorf("--show-unchanged should list rule-unchanged; got:\n%s", stdout)
	}
}

// TestRunDiff_JSONShape locks AC-09.
// @spec cli-session-diff
// @ac AC-03
func TestRunDiff_JSONShape(t *testing.T) {
	t.Run("cli-session-diff/AC-03", func(t *testing.T) {})
	path, sess1, sess2 := makeDiffStore(t, "host-a")
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "diff", sess1.String(), sess2.String(), "--format", "json"},
		t,
	)
	var got struct {
		SessionIDFrom string `json:"session_id_from"`
		SessionIDTo   string `json:"session_id_to"`
		HostnameFrom  string `json:"hostname_from"`
		HostnameTo    string `json:"hostname_to"`
		Added         []any  `json:"added"`
		Removed       []any  `json:"removed"`
		Changed       []any  `json:"changed"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal: %v\nstdout:\n%s", err, stdout)
	}
	if got.SessionIDFrom != sess1.String() || got.SessionIDTo != sess2.String() {
		t.Errorf("session IDs: got from=%s to=%s", got.SessionIDFrom, got.SessionIDTo)
	}
	if len(got.Added) != 1 || len(got.Removed) != 1 || len(got.Changed) != 1 {
		t.Errorf("counts: got added=%d removed=%d changed=%d",
			len(got.Added), len(got.Removed), len(got.Changed))
	}
}

// TestRunDiff_CrossHostnameNote locks AC-08: cross-hostname
// diff emits a stderr informational note (not a usage error).
// @spec cli-session-diff
// @ac AC-04
func TestRunDiff_CrossHostnameNote(t *testing.T) {
	t.Run("cli-session-diff/AC-04", func(t *testing.T) {})
	path, sess1, sess2 := makeDiffStore(t, "host-b") // different from session1's "host-a"
	stdout, stderr := captureRunCLI(
		[]string{"--db", path, "diff", sess1.String(), sess2.String()},
		t,
	)
	if !strings.Contains(stderr, "cross") || !strings.Contains(stderr, "host") {
		t.Errorf("stderr should contain cross-hostname note; got:\n%s", stderr)
	}
	// stdout still emits the report.
	if !strings.Contains(stdout, "kensa diff") {
		t.Errorf("stdout should still emit report despite cross-host note; got:\n%s", stdout)
	}
	exit := runCLI([]string{"--db", path, "diff", sess1.String(), sess2.String()})
	if exit != 0 {
		t.Errorf("cross-hostname diff is informational; should exit 0; got %d", exit)
	}
}

// TestRunDiff_BadArgCount locks AC-03.
// @spec cli-session-diff
// @ac AC-05
func TestRunDiff_BadArgCount(t *testing.T) {
	t.Run("cli-session-diff/AC-05", func(t *testing.T) {})
	dbPath := filepath.Join(t.TempDir(), "test.db")
	cases := [][]string{
		{"--db", dbPath, "diff"},
		{"--db", dbPath, "diff", uuid.New().String()},
		{"--db", dbPath, "diff", uuid.New().String(), uuid.New().String(), uuid.New().String()},
	}
	for _, args := range cases {
		exit := runCLI(args)
		if exit != 2 {
			t.Errorf("runCLI(%v) = %d, want 2", args, exit)
		}
	}
}

// TestRunDiff_BadUUID locks AC-04.
// @spec cli-session-diff
// @ac AC-06
func TestRunDiff_BadUUID(t *testing.T) {
	t.Run("cli-session-diff/AC-06", func(t *testing.T) {})
	dbPath := filepath.Join(t.TempDir(), "test.db")
	exit := runCLI([]string{"--db", dbPath, "diff", "not-a-uuid", uuid.New().String()})
	if exit != 2 {
		t.Errorf("bad first UUID should exit 2; got %d", exit)
	}
	exit = runCLI([]string{"--db", dbPath, "diff", uuid.New().String(), "not-a-uuid"})
	if exit != 2 {
		t.Errorf("bad second UUID should exit 2; got %d", exit)
	}
}

// TestRunDiff_MissingSessionExitCode locks AC-05.
// @spec cli-session-diff
// @ac AC-07
func TestRunDiff_MissingSessionExitCode(t *testing.T) {
	t.Run("cli-session-diff/AC-07", func(t *testing.T) {})
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.OpenSQLite(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	exit := runCLI([]string{"--db", dbPath, "diff",
		uuid.New().String(), uuid.New().String()})
	if exit != 1 {
		t.Errorf("missing sessions should exit 1; got %d", exit)
	}
}

// TestRunDiff_BadFormat.
// @spec cli-session-diff
// @ac AC-08
func TestRunDiff_BadFormat(t *testing.T) {
	t.Run("cli-session-diff/AC-08", func(t *testing.T) {})
	path, sess1, sess2 := makeDiffStore(t, "host-a")
	exit := runCLI([]string{"--db", path, "diff", sess1.String(), sess2.String(), "--format", "yaml"})
	if exit != 2 {
		t.Errorf("bad format should exit 2; got %d", exit)
	}
}

// TestRunDiff_HelpExitsZero.
// @spec cli-session-diff
// @ac AC-09
func TestRunDiff_HelpExitsZero(t *testing.T) {
	t.Run("cli-session-diff/AC-09", func(t *testing.T) {})
	for _, argv := range [][]string{
		{"diff", "--help"},
		{"diff", "-h"},
	} {
		got := runCLI(argv)
		if got != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, got)
		}
	}
}

// TestRunDiff_DedupsRetriesViaStore exercises the C-04 dedup-
// on-last-started_at contract through the full store path.
// Peer review caught that the unit test in internal/diff used
// only slice position; the contract correctness depends on
// TransactionsForSession ordering by started_at ASC. This
// test guards that store-side invariant.
//
// Setup: session1 has rule-x with three ATTEMPTS at distinct
// timestamps (errored t0, rolled_back t1, committed t2).
// Session2 has rule-x once: committed. The diff must collapse
// session1 to the LATEST attempt (committed) and report
// "unchanged" — NOT "changed from errored to committed."
// @spec cli-session-diff
// @ac AC-10
func TestRunDiff_DedupsRetriesViaStore(t *testing.T) {
	t.Run("cli-session-diff/AC-10", func(t *testing.T) {})
	path := filepath.Join(t.TempDir(), "diff.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	sess1 := uuid.New()
	sess2 := uuid.New()
	if err := s.CreateSession(context.Background(), &store.Session{
		ID: sess1, StartedAt: now.Add(-1 * time.Hour), Hostname: "host-a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(context.Background(), &store.Session{
		ID: sess2, StartedAt: now, Hostname: "host-a",
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	insertAt := func(sessID uuid.UUID, ruleID, status string, when time.Time) {
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
	// session1: three attempts at distinct timestamps.
	// LAST one (committed at t2) should win the dedup.
	t0 := now.Add(-1 * time.Hour)
	insertAt(sess1, "rule-x", "errored", t0)
	insertAt(sess1, "rule-x", "rolled_back", t0.Add(1*time.Second))
	insertAt(sess1, "rule-x", "committed", t0.Add(2*time.Second))
	// session2: rule-x committed once.
	insertAt(sess2, "rule-x", "committed", now)

	stdout, _ := captureRunCLI(
		[]string{"--db", path, "diff", sess1.String(), sess2.String(), "--show-unchanged"},
		t,
	)
	if !strings.Contains(stdout, "unchanged: 1") {
		t.Errorf("dedup-by-last-started_at should treat retry-then-success as unchanged; got:\n%s", stdout)
	}
	if strings.Contains(stdout, "errored -> committed") || strings.Contains(stdout, "rolled_back -> committed") {
		t.Errorf("the early attempts must NOT win the dedup; got:\n%s", stdout)
	}
}

// TestRunDiff_MissingSessionMessageIsClean locks the cleaned-
// up "session not found" error: must NOT leak the SQL "no rows
// in result set" or the "store: GetSession" prefix; must
// suggest `kensa list sessions` for discovery.
// @spec cli-session-diff
// @ac AC-11
func TestRunDiff_MissingSessionMessageIsClean(t *testing.T) {
	t.Run("cli-session-diff/AC-11", func(t *testing.T) {})
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.OpenSQLite(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_, stderr := captureRunCLI(
		[]string{"--db", dbPath, "diff", uuid.New().String(), uuid.New().String()},
		t,
	)
	if strings.Contains(stderr, "no rows") || strings.Contains(stderr, "GetSession") {
		t.Errorf("error should not leak SQL internals; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("error should say 'not found'; got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "kensa list sessions") {
		t.Errorf("error should suggest 'kensa list sessions'; got:\n%s", stderr)
	}
}

// TestRunDiff_MissingFirstVsSecondDistinct (R1 #4) splits the
// missing-session check so we exercise the lookup of S1 AND
// S2 independently.
// @spec cli-session-diff
// @ac AC-12
func TestRunDiff_MissingFirstVsSecondDistinct(t *testing.T) {
	t.Run("cli-session-diff/AC-12", func(t *testing.T) {})
	path, sess1, sess2 := makeDiffStore(t, "host-a")
	missing := uuid.New()

	// First missing: S1 = bogus, S2 = real.
	exit := runCLI([]string{"--db", path, "diff", missing.String(), sess2.String()})
	if exit != 1 {
		t.Errorf("S1 missing: expected exit 1; got %d", exit)
	}

	// Second missing: S1 = real, S2 = bogus.
	exit = runCLI([]string{"--db", path, "diff", sess1.String(), missing.String()})
	if exit != 1 {
		t.Errorf("S2 missing: expected exit 1; got %d", exit)
	}
}

// TestRunDiff_JSONShapeAlwaysHasUnchanged locks the new
// "always-populate, never null" JSON contract. Without
// --show-unchanged the field is still present as an empty
// array, eliminating the consumer's "is this null because
// not requested or null because empty?" ambiguity.
// @spec cli-session-diff
// @ac AC-13
func TestRunDiff_JSONShapeAlwaysHasUnchanged(t *testing.T) {
	t.Run("cli-session-diff/AC-13", func(t *testing.T) {})
	path, sess1, sess2 := makeDiffStore(t, "host-a")
	// Without --show-unchanged.
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "diff", sess1.String(), sess2.String(), "--format", "json"},
		t,
	)
	var got struct {
		Unchanged []any `json:"unchanged"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal: %v\nstdout:\n%s", err, stdout)
	}
	// The fixture's rule-unchanged should always appear in
	// the JSON — flag governs only text rendering.
	if len(got.Unchanged) != 1 {
		t.Errorf("JSON 'unchanged' should be present and populated regardless of --show-unchanged flag; got len=%d, stdout:\n%s",
			len(got.Unchanged), stdout)
	}
}
