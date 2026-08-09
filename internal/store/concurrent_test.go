package store_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/store"
)

// KN-KN-022: several Kensa clients started from one working directory all write
// to `.kensa/results.db` and contend for its lock.
//
// There are two shapes of that, and only one of them is the reported bug.

// TestSQLite_ConcurrentHandlesInOneProcess covers the easy shape: several
// *store.SQLite handles in one process. It passes today and is kept as a guard,
// not as the regression test. A single handle serializes internally
// (SetMaxOpenConns(1)); several handles inside one process still share the
// driver's in-process lock state, so they queue rather than fail.
func TestSQLite_ConcurrentHandlesInOneProcess(t *testing.T) {
	const (
		writers       = 6
		txnsPerWriter = 25
	)

	path := filepath.Join(t.TempDir(), "results.db")
	ctx := context.Background()

	stores := make([]*store.SQLite, writers)
	for i := range stores {
		s, err := store.OpenSQLite(ctx, path)
		if err != nil {
			t.Fatalf("writer %d: OpenSQLite: %v", i, err)
		}
		t.Cleanup(func() { _ = s.Close() })
		stores[i] = s
	}

	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
	)
	for i, s := range stores {
		wg.Add(1)
		go func(writer int, s *store.SQLite) {
			defer wg.Done()
			for n := 0; n < txnsPerWriter; n++ {
				if err := writeOne(ctx, t, s, writer, n); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}
		}(i, s)
	}
	wg.Wait()

	reportErrs(t, errs)
	assertTotal(ctx, t, stores[0], writers*txnsPerWriter)
}

// TestSQLite_ConcurrentProcessesShareOneLedger is the real regression test.
// Separate processes take separate SQLite file locks, which is the case the bug
// was measured on: six shards of the round-trip harness against one ledger
// produced 17 errors, and giving each shard its own `--db` removed all of them.
//
// The child re-runs this binary with KENSA_LEDGER_WRITER set, so the writers are
// genuinely separate processes rather than goroutines.
func TestSQLite_ConcurrentProcessesShareOneLedger(t *testing.T) {
	if os.Getenv("KENSA_LEDGER_WRITER") != "" {
		runLedgerWriter(t)
		return
	}
	if testing.Short() {
		t.Skip("spawns subprocesses")
	}

	const (
		writers       = 6
		txnsPerWriter = 40
	)

	dir := t.TempDir()
	path := filepath.Join(dir, "results.db")
	ctx := context.Background()

	// Create the schema once up front. Concurrent first-open would otherwise
	// race on migration, which is a different bug from the one under test.
	seed, err := store.OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("seed OpenSQLite: %v", err)
	}
	_ = seed.Close()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable: %v", err)
	}

	var (
		mu     sync.Mutex
		failed []string
		wg     sync.WaitGroup
	)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			cmd := exec.Command(exe,
				"-test.run", "^TestSQLite_ConcurrentProcessesShareOneLedger$",
				"-test.count=1")
			cmd.Env = append(os.Environ(),
				"KENSA_LEDGER_WRITER="+strconv.Itoa(writer),
				"KENSA_LEDGER_PATH="+path,
				"KENSA_LEDGER_TXNS="+strconv.Itoa(txnsPerWriter))
			out, err := cmd.CombinedOutput()
			if err != nil {
				mu.Lock()
				failed = append(failed, fmt.Sprintf("writer %d: %v\n%s", writer, err, out))
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	for i, f := range failed {
		if i >= 3 {
			t.Errorf("... and %d more failed writers", len(failed)-i)
			break
		}
		t.Errorf("%s", f)
	}
	if len(failed) > 0 {
		t.Fatalf("%d of %d concurrent processes failed", len(failed), writers)
	}

	check, err := store.OpenSQLite(ctx, path)
	if err != nil {
		t.Fatalf("verify OpenSQLite: %v", err)
	}
	defer func() { _ = check.Close() }()
	assertTotal(ctx, t, check, writers*txnsPerWriter)
}

// runLedgerWriter is the child half of the cross-process test.
func runLedgerWriter(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	writer, _ := strconv.Atoi(os.Getenv("KENSA_LEDGER_WRITER"))
	total, _ := strconv.Atoi(os.Getenv("KENSA_LEDGER_TXNS"))

	s, err := store.OpenSQLite(ctx, os.Getenv("KENSA_LEDGER_PATH"))
	if err != nil {
		t.Fatalf("writer %d: OpenSQLite: %v", writer, err)
	}
	defer func() { _ = s.Close() }()

	for n := 0; n < total; n++ {
		if err := writeOne(ctx, t, s, writer, n); err != nil {
			t.Fatalf("%v", err)
		}
	}
}

// writeOne performs the pair of writes a real remediation performs: the
// pre-state bundle, then the terminal record.
func writeOne(ctx context.Context, t *testing.T, s *store.SQLite, writer, n int) error {
	t.Helper()
	res := sampleTransaction(t, api.StatusCommitted,
		fmt.Sprintf("rule-w%d-n%d", writer, n),
		fmt.Sprintf("host-%d", writer))
	if err := s.PersistPreStates(ctx, res.TransactionID, []api.PreState{{
		StepIndex:  0,
		Mechanism:  "file_permissions",
		Capturable: true,
		Data:       map[string]interface{}{"mode": "0644"},
		CapturedAt: res.StartedAt,
	}}); err != nil {
		return fmt.Errorf("writer %d txn %d pre-states: %w", writer, n, err)
	}
	if err := s.PersistResult(ctx, res); err != nil {
		return fmt.Errorf("writer %d txn %d result: %w", writer, n, err)
	}
	return nil
}

// reportErrs prints a few failures verbatim. The reported harm in KN-KN-022 was
// that the error text never named the database, so the text is the evidence.
func reportErrs(t *testing.T, errs []error) {
	t.Helper()
	if len(errs) == 0 {
		return
	}
	for i, err := range errs {
		if i >= 5 {
			t.Errorf("... and %d more", len(errs)-i)
			break
		}
		t.Errorf("%v", err)
	}
	t.Fatalf("%d writes failed under concurrency", len(errs))
}

func assertTotal(ctx context.Context, t *testing.T, s *store.SQLite, want int) {
	t.Helper()
	stats, err := s.ComputeStats(ctx, store.StatsFilter{})
	if err != nil {
		t.Fatalf("ComputeStats: %v", err)
	}
	if stats.TransactionsTotal != want {
		t.Fatalf("transactions in ledger = %d, want %d", stats.TransactionsTotal, want)
	}
}
