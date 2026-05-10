// Tests for the C-041 persistScanResult helper.
package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/store"
)

// makeScanResult returns a synthetic ScanResult with N
// transactions, each pointing at a distinct rule. Mirrors what
// internal/scan.Run produces (no envelopes — the caller's job).
func makeScanResult(t *testing.T, ruleIDs []string) ([]*api.Rule, *api.ScanResult) {
	t.Helper()
	rules := make([]*api.Rule, len(ruleIDs))
	result := &api.ScanResult{}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i, id := range ruleIDs {
		rules[i] = &api.Rule{
			ID:       id,
			Severity: "high",
			References: map[string]any{
				"nist_800_53": []any{"AC-1"},
			},
		}
		result.Transactions = append(result.Transactions, api.TransactionResult{
			TransactionID: uuid.New(),
			Status:        api.StatusCommitted,
			StartedAt:     now,
			FinishedAt:    now.Add(time.Second),
			Steps: []api.StepResult{{
				StepIndex: 0, Mechanism: "check", Success: true, Detail: "ok",
			}},
		})
	}
	return rules, result
}

func TestPersistScanResult_Basic(t *testing.T) {
	dir := t.TempDir()
	s, err := store.OpenSQLite(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	rules, result := makeScanResult(t, []string{"rule-a", "rule-b", "rule-c"})

	sess := &store.Session{
		ID:          uuid.New(),
		StartedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Hostname:    "host-x",
		Subcommand:  "check",
		ArgsSummary: "-s critical",
	}

	gotID, err := persistScanResult(context.Background(), s, "host-x", rules, result, sess)
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	if gotID != sess.ID {
		t.Errorf("returned session ID mismatch: got %v want %v", gotID, sess.ID)
	}

	// Verify session was created with correct denormalized counts.
	got, err := s.GetSession(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.TxnTotal != 3 {
		t.Errorf("txn_total: got %d want 3", got.TxnTotal)
	}
	if got.TxnCommitted != 3 {
		t.Errorf("txn_committed: got %d want 3", got.TxnCommitted)
	}
	if got.Hostname != "host-x" {
		t.Errorf("hostname: got %q want host-x", got.Hostname)
	}
}

func TestPersistScanResult_EmptyResult(t *testing.T) {
	dir := t.TempDir()
	s, err := store.OpenSQLite(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sess := &store.Session{
		ID:        uuid.New(),
		StartedAt: time.Now().UTC().Truncate(time.Microsecond),
		Hostname:  "host-empty",
	}
	emptyResult := &api.ScanResult{}
	if _, err := persistScanResult(context.Background(), s, "host-empty", nil, emptyResult, sess); err != nil {
		t.Fatalf("persist on empty result should not error: %v", err)
	}

	got, err := s.GetSession(context.Background(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TxnTotal != 0 {
		t.Errorf("empty result should produce zero txn_total; got %d", got.TxnTotal)
	}
}

func TestPersistScanResult_NilSession(t *testing.T) {
	s, err := store.OpenSQLite(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = persistScanResult(context.Background(), s, "h", nil, &api.ScanResult{}, nil)
	if err == nil {
		t.Fatal("nil session should error")
	}
}

func TestSummarizeCheckArgs(t *testing.T) {
	got := summarizeCheckArgs([]string{"critical"}, []string{"pci"}, "audit", "cis_rhel9", nil)
	if got == "" {
		t.Fatal("non-empty inputs should produce non-empty summary")
	}
	// Empty inputs → empty summary.
	if summarizeCheckArgs(nil, nil, "", "", nil) != "" {
		t.Error("all-empty inputs should produce empty summary")
	}
}
