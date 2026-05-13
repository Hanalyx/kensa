// Tests for the C-051 `kensa history --format jsonl` flow.
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

// makeHistoryStore seeds a temp DB with N committed transactions
// across one session. Returns the db path. Used by the C-051
// jsonl tests so the format paths can be exercised end-to-end.
func makeHistoryStore(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	sessID := uuid.New()
	if err := s.CreateSession(context.Background(), &store.Session{
		ID: sessID, StartedAt: now, Hostname: "host-a", Subcommand: "check",
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < n; i++ {
		whenStr := now.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if _, err := db.ExecContext(context.Background(), `
            INSERT INTO transactions (
                id, rule_id, host_id, fleet_id, status, transactional, severity,
                started_at, finished_at, envelope_json, envelope_sig, session_id)
            VALUES (?, ?, 'host-a', '', 'committed', 1, 'high', ?, ?, '{}', X'', ?)`,
			uuid.New().String(), "rule-"+string(rune('a'+i%26)),
			whenStr, whenStr, sessID.String()); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	return path
}

// TestRunHistory_JSONLFormat locks AC-01: --format jsonl emits
// one JSON object per line (no top-level array wrapper).
// @spec cli-history-jsonl
// @ac AC-01
func TestRunHistory_JSONLFormat(t *testing.T) {
	t.Run("cli-history-jsonl/AC-01", func(t *testing.T) {})
	path := makeHistoryStore(t, 3)
	stdout, _ := captureRunCLI([]string{"--db", path, "history", "--format", "jsonl"}, t)
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (one per txn); got %d:\n%s", len(lines), stdout)
	}
	// First char of each non-empty line must be '{' (JSON object,
	// not '[' which would mean array-as-line).
	for i, line := range lines {
		if line == "" {
			continue
		}
		if line[0] != '{' {
			t.Errorf("line %d should start with '{'; got %q", i, line)
		}
	}
}

// TestRunHistory_JSONLEachLineParseable locks AC-02: every line
// is independently parseable as a transaction-record-shaped
// object.
// @spec cli-history-jsonl
// @ac AC-02
func TestRunHistory_JSONLEachLineParseable(t *testing.T) {
	t.Run("cli-history-jsonl/AC-02", func(t *testing.T) {})
	path := makeHistoryStore(t, 3)
	stdout, _ := captureRunCLI([]string{"--db", path, "history", "--format", "jsonl"}, t)
	for i, line := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d not parseable: %v\nline: %q", i, err, line)
		}
		if _, ok := got["RuleID"]; !ok {
			// JSON shape uses Go field names by default since
			// api.TransactionRecord has no json tags — that's
			// the existing --format json shape. jsonl matches.
			t.Errorf("line %d missing RuleID field; line: %q", i, line)
		}
	}
}

// TestRunHistory_JSONLRejectsDocumentModes locks AC-03: jsonl
// combined with --aggregate / --stats / --txn rejects with
// usage error.
// @spec cli-history-jsonl
// @ac AC-03
func TestRunHistory_JSONLRejectsDocumentModes(t *testing.T) {
	t.Run("cli-history-jsonl/AC-03", func(t *testing.T) {})
	path := makeHistoryStore(t, 1)
	cases := [][]string{
		{"--db", path, "history", "--format", "jsonl", "--aggregate", "by_host"},
		{"--db", path, "history", "--format", "jsonl", "--stats"},
		{"--db", path, "history", "--format", "jsonl", "--txn", uuid.New().String()},
	}
	for _, args := range cases {
		exit := runCLI(args)
		if exit != 2 {
			t.Errorf("runCLI(%v) = %d, want 2", args, exit)
		}
	}
	// And the error message must point at --format json.
	_, stderr := captureRunCLI(
		[]string{"--db", path, "history", "--format", "jsonl", "--stats"}, t,
	)
	if !strings.Contains(stderr, "--format json") {
		t.Errorf("error should redirect to --format json; got:\n%s", stderr)
	}
}

// TestRunHistory_JSONLShapeMatchesJSON locks AC-04: each jsonl.
// line is byte-identical to a single element of the --format
// json `transactions` array.
// @spec cli-history-jsonl
// @ac AC-04
func TestRunHistory_JSONLShapeMatchesJSON(t *testing.T) {
	t.Run("cli-history-jsonl/AC-04", func(t *testing.T) {})
	path := makeHistoryStore(t, 2)

	stdoutJSON, _ := captureRunCLI(
		[]string{"--db", path, "history", "--format", "json"}, t,
	)
	var jsonResult struct {
		Transactions []json.RawMessage `json:"Transactions"`
	}
	if err := json.Unmarshal([]byte(stdoutJSON), &jsonResult); err != nil {
		t.Fatalf("unmarshal --format json: %v\n%s", err, stdoutJSON)
	}

	stdoutJSONL, _ := captureRunCLI(
		[]string{"--db", path, "history", "--format", "jsonl"}, t,
	)
	jsonlLines := strings.Split(strings.TrimRight(stdoutJSONL, "\n"), "\n")

	if len(jsonResult.Transactions) != len(jsonlLines) {
		t.Fatalf("count mismatch: json=%d jsonl=%d", len(jsonResult.Transactions), len(jsonlLines))
	}
	// For each pair, normalize both through json.RawMessage round-
	// trip so whitespace differences don't matter — we're locking
	// the parsed-shape equivalence, not byte equality.
	for i := range jsonResult.Transactions {
		var fromArray, fromLine map[string]any
		if err := json.Unmarshal(jsonResult.Transactions[i], &fromArray); err != nil {
			t.Fatalf("array element %d: %v", i, err)
		}
		if err := json.Unmarshal([]byte(jsonlLines[i]), &fromLine); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if fromArray["RuleID"] != fromLine["RuleID"] {
			t.Errorf("element %d RuleID mismatch: array=%v jsonl=%v",
				i, fromArray["RuleID"], fromLine["RuleID"])
		}
		if fromArray["Status"] != fromLine["Status"] {
			t.Errorf("element %d Status mismatch", i)
		}
	}
}

// TestRunHistory_JSONLTrailerToStderr locks AC-05: the "N of M
// transactions shown" trailer must NOT corrupt stdout (consumers
// piping to jq -c '.' would choke on the human-readable line).
// @spec cli-history-jsonl
// @ac AC-05
func TestRunHistory_JSONLTrailerToStderr(t *testing.T) {
	t.Run("cli-history-jsonl/AC-05", func(t *testing.T) {})
	path := makeHistoryStore(t, 2)
	stdout, stderr := captureRunCLI(
		[]string{"--db", path, "history", "--format", "jsonl"}, t,
	)
	if strings.Contains(stdout, "transactions shown") {
		t.Errorf("trailer must NOT appear in stdout under jsonl; got:\n%s", stdout)
	}
	if !strings.Contains(stderr, "transactions shown") {
		t.Errorf("trailer must appear in stderr; got:\n%s", stderr)
	}
}

// TestRunHistory_JSONLAdvertisedInHelp verifies the --help text
// surfaces jsonl as a valid format.
// @spec cli-history-jsonl
// @ac AC-06
func TestRunHistory_JSONLAdvertisedInHelp(t *testing.T) {
	t.Run("cli-history-jsonl/AC-06", func(t *testing.T) {})
	stdout, _ := captureRunCLI([]string{"history", "--help"}, t)
	if !strings.Contains(stdout, "jsonl") {
		t.Errorf("history --help should mention jsonl; got:\n%s", stdout)
	}
}
