// Tests for `kensa list sessions` (added under C-048 to give
// operators a way to discover session UUIDs needed by `kensa
// diff`).
package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/internal/store"
)

// seedSessions creates a temp DB and inserts N sessions with
// distinct hostnames + timestamps. Returns the db path.
func seedSessions(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list-sessions.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < n; i++ {
		sess := &store.Session{
			ID:         uuid.New(),
			StartedAt:  now.Add(time.Duration(-i) * time.Hour),
			Hostname:   "host-" + string(rune('a'+i%3)),
			Subcommand: "check",
		}
		if err := s.CreateSession(context.Background(), sess); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// @spec cli-list-sessions-info-jsonl
// @ac AC-01
func TestRunListSessions_EmptyStore(t *testing.T) {
	t.Run("cli-list-sessions-info-jsonl/AC-01", func(t *testing.T) {})
	path := filepath.Join(t.TempDir(), "empty.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	stdout, _ := captureRunCLI([]string{"--db", path, "list", "sessions"}, t)
	if !strings.Contains(stdout, "no sessions in the store") {
		t.Errorf("empty store should print 'no sessions'; got:\n%s", stdout)
	}
}

// @spec cli-list-sessions-info-jsonl
// @ac AC-02
func TestRunListSessions_Basic(t *testing.T) {
	t.Run("cli-list-sessions-info-jsonl/AC-02", func(t *testing.T) {})
	path := seedSessions(t, 3)
	stdout, _ := captureRunCLI([]string{"--db", path, "list", "sessions"}, t)
	if !strings.Contains(stdout, "kensa list sessions") {
		t.Errorf("missing header; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "3 session(s)") {
		t.Errorf("expected '3 session(s)'; got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "session_id") {
		t.Errorf("table should advertise session_id column; got:\n%s", stdout)
	}
}

// @spec cli-list-sessions-info-jsonl
// @ac AC-03
func TestRunListSessions_FilterByHost(t *testing.T) {
	t.Run("cli-list-sessions-info-jsonl/AC-03", func(t *testing.T) {})
	path := seedSessions(t, 6) // host-a, host-b, host-c x 2 each
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "list", "sessions", "-H", "host-a"},
		t,
	)
	if !strings.Contains(stdout, "2 session(s)") {
		t.Errorf("filter by host-a should match 2; got:\n%s", stdout)
	}
}

// @spec cli-list-sessions-info-jsonl
// @ac AC-04
func TestRunListSessions_LimitClamps(t *testing.T) {
	t.Run("cli-list-sessions-info-jsonl/AC-04", func(t *testing.T) {})
	path := seedSessions(t, 5)
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "list", "sessions", "-n", "2"},
		t,
	)
	if !strings.Contains(stdout, "2 session(s)") {
		t.Errorf("--limit 2 should produce 2 session(s); got:\n%s", stdout)
	}
}

// @spec cli-list-sessions-info-jsonl
// @ac AC-05
func TestRunListSessions_JSONShape(t *testing.T) {
	t.Run("cli-list-sessions-info-jsonl/AC-05", func(t *testing.T) {})
	path := seedSessions(t, 2)
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "list", "sessions", "--format", "json"},
		t,
	)
	var got struct {
		Sessions []struct {
			ID         string `json:"id"`
			StartedAt  string `json:"started_at"`
			Hostname   string `json:"hostname"`
			Subcommand string `json:"subcommand"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, stdout)
	}
	if len(got.Sessions) != 2 {
		t.Errorf("expected 2 sessions; got %d", len(got.Sessions))
	}
	for _, snake := range []string{`"sessions":`, `"id":`, `"started_at":`, `"txn_committed":`, `"txn_rolled_back":`} {
		if !strings.Contains(stdout, snake) {
			t.Errorf("expected %q in JSON:\n%s", snake, stdout)
		}
	}
}

func TestRunListSessions_HelpExitsZero(t *testing.T) {
	for _, argv := range [][]string{
		{"list", "sessions", "--help"},
		{"list", "sessions", "-h"},
	} {
		got := runCLI(argv)
		if got != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, got)
		}
	}
}

func TestRunListSessions_BadFormat(t *testing.T) {
	path := seedSessions(t, 1)
	exit := runCLI([]string{"--db", path, "list", "sessions", "--format", "yaml"})
	if exit != 2 {
		t.Errorf("bad format should exit 2; got %d", exit)
	}
}
