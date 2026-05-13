// Tests for the C-052 `kensa list sessions --format jsonl` flow.
package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/internal/store"
)

// emptyStorePath opens (and immediately closes) a fresh SQLite
// store at a temp path, returning the path so callers can
// exercise --format jsonl on a zero-row store.
func emptyStorePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "empty.db")
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	return path
}

// TestRunListSessions_JSONLFormat locks AC-01: --format jsonl
// emits one session row per line, no top-level envelope.
// @spec cli-list-sessions-info-jsonl
// @ac AC-01
// @ac AC-04
func TestRunListSessions_JSONLFormat(t *testing.T) {
	t.Run("cli-list-sessions-info-jsonl/AC-01", func(t *testing.T) {})
	t.Run("cli-list-sessions-info-jsonl/AC-04", func(t *testing.T) {})
	path := seedSessions(t, 3)
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "list", "sessions", "--format", "jsonl"}, t,
	)
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (one per session); got %d:\n%s", len(lines), stdout)
	}
	for i, line := range lines {
		if line == "" {
			continue
		}
		// First non-whitespace char must be '{' — never '['
		// (which would mean array-as-line).
		if line[0] != '{' {
			t.Errorf("line %d should start with '{'; got %q", i, line)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d not parseable: %v\nline: %q", i, err, line)
		}
		if _, ok := got["id"]; !ok {
			t.Errorf("line %d missing 'id' field; line: %q", i, line)
		}
	}
}

// TestRunListSessions_JSONLShapeMatchesJSON locks AC-04: per-line
// shape under jsonl matches per-element shape of the JSON
// envelope's `sessions` array.
// @spec cli-list-sessions-info-jsonl
// @ac AC-02
// @ac AC-05
func TestRunListSessions_JSONLShapeMatchesJSON(t *testing.T) {
	t.Run("cli-list-sessions-info-jsonl/AC-02", func(t *testing.T) {})
	t.Run("cli-list-sessions-info-jsonl/AC-05", func(t *testing.T) {})
	path := seedSessions(t, 2)

	stdoutJSON, _ := captureRunCLI(
		[]string{"--db", path, "list", "sessions", "--format", "json"}, t,
	)
	var env struct {
		Sessions []json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(stdoutJSON), &env); err != nil {
		t.Fatalf("unmarshal --format json: %v\n%s", err, stdoutJSON)
	}

	stdoutJSONL, _ := captureRunCLI(
		[]string{"--db", path, "list", "sessions", "--format", "jsonl"}, t,
	)
	jsonlLines := strings.Split(strings.TrimRight(stdoutJSONL, "\n"), "\n")

	if len(env.Sessions) != len(jsonlLines) {
		t.Fatalf("count mismatch: json=%d jsonl=%d", len(env.Sessions), len(jsonlLines))
	}
	for i := range env.Sessions {
		var fromArray, fromLine map[string]any
		if err := json.Unmarshal(env.Sessions[i], &fromArray); err != nil {
			t.Fatalf("array element %d: %v", i, err)
		}
		if err := json.Unmarshal([]byte(jsonlLines[i]), &fromLine); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		// The JSON-array path uses sort order from
		// ListSessions (DESC by started_at). The jsonl path
		// uses the same source. Per-element ID + hostname
		// must agree.
		if fromArray["id"] != fromLine["id"] {
			t.Errorf("element %d id mismatch: array=%v jsonl=%v",
				i, fromArray["id"], fromLine["id"])
		}
		if fromArray["hostname"] != fromLine["hostname"] {
			t.Errorf("element %d hostname mismatch", i)
		}
	}
}

// TestRunListSessions_JSONLEmptyStore: jsonl on empty store
// produces zero output lines (not "(no sessions)" — that's the
// text-format human banner).
// @spec cli-list-sessions-info-jsonl
// @ac AC-03
func TestRunListSessions_JSONLEmptyStore(t *testing.T) {
	t.Run("cli-list-sessions-info-jsonl/AC-03", func(t *testing.T) {})
	path := emptyStorePath(t)
	stdout, _ := captureRunCLI(
		[]string{"--db", path, "list", "sessions", "--format", "jsonl"}, t,
	)
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("empty store under jsonl should produce zero output; got:\n%s", stdout)
	}
}
