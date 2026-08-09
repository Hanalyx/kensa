package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// @spec transaction-log
// @ac AC-10
//
// TestOpenSQLite_PragmasSurviveANewConnection checks that the PRAGMAs backing
// the store's durability and integrity guarantees hold on EVERY connection, not
// just the one that happened to serve them at open time.
//
// PRAGMAs are per-connection state. OpenSQLite issues them once through
// database/sql, so they bind to whichever pooled connection ran them. The pool
// currently holds a single connection (SetMaxOpenConns(1)), which hides the
// problem: if that connection is ever retired — an error, an idle sweep, a
// future change to the pool settings — the replacement comes up with SQLite's
// defaults instead.
//
// What silently reverts:
//
//   - foreign_keys goes back to OFF, so referential integrity stops being
//     enforced on the ledger.
//   - synchronous goes back to NORMAL, which is exactly the guarantee
//     transaction-log spec C-02 names: pre-state persistence must complete
//     before the engine proceeds.
//   - busy_timeout goes back to 0, so a contended write fails immediately
//     rather than waiting.
//
// journal_mode is not in that list: WAL is recorded in the database file and
// survives reconnection on its own.
func TestOpenSQLite_PragmasSurviveANewConnection(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "results.db")

	s, err := OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer func() { _ = s.Close() }()

	read := func(pragma string) string {
		t.Helper()
		var v string
		if err := s.db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&v); err != nil {
			t.Fatalf("read PRAGMA %s: %v", pragma, err)
		}
		return v
	}

	want := map[string]string{
		"foreign_keys": "1",
		"synchronous":  "2", // FULL
		"busy_timeout": "5000",
		"journal_mode": "wal",
	}

	for p, w := range want {
		if got := read(p); got != w {
			t.Errorf("on the opening connection, PRAGMA %s = %q, want %q", p, got, w)
		}
	}

	// Retire the pooled connection so the next statement opens a fresh one.
	// SetMaxIdleConns(0) makes database/sql close the connection when it is
	// returned to the pool instead of keeping it.
	s.db.SetMaxIdleConns(0)
	if _, err := s.db.ExecContext(ctx, "SELECT 1"); err != nil {
		t.Fatalf("cycle connection: %v", err)
	}

	for p, w := range want {
		if got := read(p); got != w {
			t.Errorf("after the connection was replaced, PRAGMA %s = %q, want %q", p, got, w)
		}
	}
}

// @spec transaction-log
// @ac AC-11
//
// TestSQLite_BusyErrorNamesTheLedger checks the other half of KN-KN-022: when a
// write loses to another client, the error must say so and name the database.
// The reported harm was not the failure itself but that it read as a broken
// rule, so seventeen of them sent the investigation to the rule corpus.
func TestSQLite_BusyErrorNamesTheLedger(t *testing.T) {
	s := &SQLite{path: "/tmp/results.db"}

	t.Run("passes other errors through untouched", func(t *testing.T) {
		in := errors.New("store: insert transaction: no such column")
		if got := s.busy(in); got != in {
			t.Fatalf("unrelated error was rewritten: %v", got)
		}
		if s.busy(nil) != nil {
			t.Fatal("nil became non-nil")
		}
	})

	t.Run("annotates a contended write", func(t *testing.T) {
		got := s.busy(fmt.Errorf("store: insert transaction: %w",
			errors.New("database is locked (5) (SQLITE_BUSY)")))
		if !errors.Is(got, ErrLedgerBusy) {
			t.Fatalf("not classified as busy: %v", got)
		}
		msg := got.Error()
		for _, want := range []string{"/tmp/results.db", "--db", "another kensa client"} {
			if !strings.Contains(msg, want) {
				t.Errorf("message does not mention %q: %s", want, msg)
			}
		}
	})
}
