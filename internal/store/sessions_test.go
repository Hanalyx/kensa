// Tests for the Phase 4 / C-039 session schema and API.
package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func openTestStore(t *testing.T) *SQLite {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	store, err := OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestCreateSession_Roundtrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	sess := &Session{
		ID:          uuid.New(),
		StartedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Hostname:    "192.168.1.211",
		Subcommand:  "check",
		ArgsSummary: "-s critical -t pci",
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("ID: got %v want %v", got.ID, sess.ID)
	}
	if got.Hostname != sess.Hostname {
		t.Errorf("Hostname: got %q want %q", got.Hostname, sess.Hostname)
	}
	if got.Subcommand != sess.Subcommand {
		t.Errorf("Subcommand: got %q want %q", got.Subcommand, sess.Subcommand)
	}
	if got.ArgsSummary != sess.ArgsSummary {
		t.Errorf("ArgsSummary: got %q want %q", got.ArgsSummary, sess.ArgsSummary)
	}
	// FinishedAt was unset; CreateSession used StartedAt as the
	// "still in progress" sentinel.
	if !got.FinishedAt.Equal(sess.StartedAt) {
		t.Errorf("FinishedAt sentinel: got %v want %v", got.FinishedAt, sess.StartedAt)
	}
}

func TestCreateSession_RejectsZeroID(t *testing.T) {
	store := openTestStore(t)
	err := store.CreateSession(context.Background(), &Session{
		StartedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("zero ID should reject")
	}
}

func TestCreateSession_RejectsZeroStartedAt(t *testing.T) {
	store := openTestStore(t)
	err := store.CreateSession(context.Background(), &Session{
		ID: uuid.New(),
	})
	if err == nil {
		t.Fatal("zero StartedAt should reject")
	}
}

func TestFinishSession_UpdatesTimestamp(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	sess := &Session{
		ID:        uuid.New(),
		StartedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}

	finished := sess.StartedAt.Add(5 * time.Minute)
	if err := store.FinishSession(ctx, sess.ID, finished); err != nil {
		t.Fatalf("finish: %v", err)
	}

	got, err := store.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.FinishedAt.Equal(finished) {
		t.Errorf("FinishedAt: got %v want %v", got.FinishedAt, finished)
	}
}

func TestFinishSession_Idempotent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	sess := &Session{
		ID:        uuid.New(),
		StartedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}

	finished := sess.StartedAt.Add(time.Minute)
	if err := store.FinishSession(ctx, sess.ID, finished); err != nil {
		t.Fatal(err)
	}
	// Second call must succeed.
	if err := store.FinishSession(ctx, sess.ID, finished.Add(time.Second)); err != nil {
		t.Fatalf("second finish: %v", err)
	}
}

func TestListSessions_OrderByStartedAtDesc(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	older := &Session{
		ID:        uuid.New(),
		StartedAt: now.Add(-2 * time.Hour),
		Hostname:  "host-a",
	}
	newer := &Session{
		ID:        uuid.New(),
		StartedAt: now,
		Hostname:  "host-a",
	}
	if err := store.CreateSession(ctx, older); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, newer); err != nil {
		t.Fatal(err)
	}

	got, err := store.ListSessions(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(got))
	}
	if got[0].ID != newer.ID {
		t.Errorf("first should be newer; got %v", got[0].ID)
	}
}

func TestListSessions_FilterByHostname(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	a := &Session{ID: uuid.New(), StartedAt: now, Hostname: "host-a"}
	b := &Session{ID: uuid.New(), StartedAt: now.Add(time.Second), Hostname: "host-b"}
	if err := store.CreateSession(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, b); err != nil {
		t.Fatal(err)
	}
	got, err := store.ListSessions(ctx, "host-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Hostname != "host-a" {
		t.Errorf("expected only host-a; got %d sessions", len(got))
	}
}

func TestAttachTransaction_NotFound(t *testing.T) {
	store := openTestStore(t)
	err := store.AttachTransaction(context.Background(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatal("expected error for non-existent transaction")
	}
}

func TestSessionsTable_Exists(t *testing.T) {
	// Confirm migration 2 ran. Querying a session that doesn't
	// exist should return sql.ErrNoRows (wrapped), not a "no
	// such table" error.
	store := openTestStore(t)
	_, err := store.GetSession(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected ErrNoRows for missing session")
	}
	// The error message should mention session / GetSession,
	// not sqlite "no such table".
	if msg := err.Error(); contains(msg, "no such table") {
		t.Errorf("migration 2 didn't run; got %q", msg)
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
