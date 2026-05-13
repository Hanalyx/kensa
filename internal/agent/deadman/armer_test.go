package deadman

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestArmer_NewIsEmpty: fresh Armer reports zero active.
func TestArmer_NewIsEmpty(t *testing.T) {
	a := New()
	if got := a.ActiveCount(); got != 0 {
		t.Errorf("fresh Armer.ActiveCount: got %d, want 0", got)
	}
}

// TestArmer_ArmRecordsAndCancelClears: a single arm shows up
// in ActiveCount; CancelDeadman returns wasActive=true and
// drops the entry.
func TestArmer_ArmRecordsAndCancelClears(t *testing.T) {
	a := New()
	firesAt, err := a.ArmDeadman("txn-1", 5*time.Second, nil)
	if err != nil {
		t.Fatalf("ArmDeadman: %v", err)
	}
	if firesAt < time.Now().Unix() {
		t.Errorf("firesAt should be in the future; got %d", firesAt)
	}
	if got := a.ActiveCount(); got != 1 {
		t.Errorf("after Arm: ActiveCount=%d, want 1", got)
	}

	wasActive := a.CancelDeadman("txn-1")
	if !wasActive {
		t.Errorf("CancelDeadman: wasActive=false, want true")
	}
	if got := a.ActiveCount(); got != 0 {
		t.Errorf("after Cancel: ActiveCount=%d, want 0", got)
	}
}

// TestArmer_RejectsDuplicateTxnID: a second Arm with the
// same txn_id returns ErrAlreadyArmed without disturbing
// the first arm.
func TestArmer_RejectsDuplicateTxnID(t *testing.T) {
	a := New()
	if _, err := a.ArmDeadman("txn-dup", 5*time.Second, nil); err != nil {
		t.Fatal(err)
	}
	defer a.CancelDeadman("txn-dup")

	_, err := a.ArmDeadman("txn-dup", 5*time.Second, nil)
	if !errors.Is(err, ErrAlreadyArmed) {
		t.Errorf("duplicate Arm: expected ErrAlreadyArmed; got: %v", err)
	}
	if got := a.ActiveCount(); got != 1 {
		t.Errorf("after duplicate Arm: ActiveCount=%d, want 1", got)
	}
}

// TestArmer_RejectsNonPositiveWindow.
func TestArmer_RejectsNonPositiveWindow(t *testing.T) {
	a := New()
	for _, d := range []time.Duration{0, -1 * time.Second} {
		if _, err := a.ArmDeadman("txn-w", d, nil); err == nil {
			t.Errorf("Arm(window=%v): expected error", d)
		}
	}
}

// TestArmer_CancelNonExistentTxnID: returns false; not an
// error.
func TestArmer_CancelNonExistentTxnID(t *testing.T) {
	a := New()
	if wasActive := a.CancelDeadman("never-armed"); wasActive {
		t.Error("CancelDeadman on non-armed txn: expected wasActive=false")
	}
}

// TestArmer_TimerFiresAndExecutesCommands: arm with a short
// window + a touch-a-file command. After window+slop, the
// file exists.
func TestArmer_TimerFiresAndExecutesCommands(t *testing.T) {
	tmpDir := t.TempDir()
	witness := filepath.Join(tmpDir, "fired")
	cmds := []string{
		"touch " + witness,
	}

	a := New()
	if _, err := a.ArmDeadman("txn-fire", 100*time.Millisecond, cmds); err != nil {
		t.Fatal(err)
	}

	// Poll for the witness file to appear within 1s.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(witness); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(witness); err != nil {
		t.Errorf("witness file not created — timer did not fire OR rollback commands did not run: %v", err)
	}

	// Goroutine should have exited and cleared the active map.
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if a.ActiveCount() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := a.ActiveCount(); got != 0 {
		t.Errorf("after timer fire + cleanup: ActiveCount=%d, want 0", got)
	}
}

// TestArmer_CancelBeforeTimer_NoExecution: cancel before
// window expires; the rollback commands should NOT run.
func TestArmer_CancelBeforeTimer_NoExecution(t *testing.T) {
	tmpDir := t.TempDir()
	witness := filepath.Join(tmpDir, "should-not-exist")
	cmds := []string{"touch " + witness}

	a := New()
	if _, err := a.ArmDeadman("txn-cancel", 5*time.Second, cmds); err != nil {
		t.Fatal(err)
	}
	// Cancel almost immediately.
	time.Sleep(20 * time.Millisecond)
	wasActive := a.CancelDeadman("txn-cancel")
	if !wasActive {
		t.Errorf("Cancel: wasActive=false, want true")
	}

	// Wait a tick longer than would be needed for a 5s timer
	// to fire (it shouldn't fire because we canceled).
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(witness); err == nil {
		t.Errorf("rollback commands ran despite Cancel — witness file exists at %s", witness)
	}
}

// TestArmer_HandleArmDeadmanRouting: the package-level
// HandleArmDeadman dispatches to the defaultArmer.
func TestArmer_HandleArmDeadmanRouting(t *testing.T) {
	// Reset defaultArmer state by canceling anything in
	// flight from prior tests.
	defaultArmer.mu.Lock()
	txns := make([]string, 0, len(defaultArmer.active))
	for k := range defaultArmer.active {
		txns = append(txns, k)
	}
	defaultArmer.mu.Unlock()
	for _, txn := range txns {
		defaultArmer.CancelDeadman(txn)
	}

	firesAt, err := HandleArmDeadman("txn-route", 5, nil)
	if err != nil {
		t.Fatalf("HandleArmDeadman: %v", err)
	}
	if firesAt < time.Now().Unix() {
		t.Errorf("firesAt %d should be future", firesAt)
	}
	if wasActive := HandleCancelDeadman("txn-route"); !wasActive {
		t.Errorf("HandleCancelDeadman: wasActive=false, want true")
	}
}

// TestArmer_ConcurrentArms_SameTxnID locks the P0-2 fix:
// two goroutines racing with the SAME txn_id must result in
// exactly one successful Arm and one ErrAlreadyArmed —
// never two armed jobs (which would leak the loser's fds +
// goroutine, both firing rollback on timer expiration).
// The pre-fix code released the lock between duplicate-check
// and insert, letting both callers pass the check.
func TestArmer_ConcurrentArms_SameTxnID(t *testing.T) {
	a := New()
	const goroutines = 16
	var successCount, alreadyArmedCount atomic.Int64
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, err := a.ArmDeadman("txn-race", 5*time.Second, nil)
			switch {
			case err == nil:
				successCount.Add(1)
			case errors.Is(err, ErrAlreadyArmed):
				alreadyArmedCount.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
	if successCount.Load() != 1 {
		t.Errorf("expected exactly 1 successful Arm; got %d", successCount.Load())
	}
	if alreadyArmedCount.Load() != int64(goroutines-1) {
		t.Errorf("expected %d ErrAlreadyArmed; got %d", goroutines-1, alreadyArmedCount.Load())
	}
	if got := a.ActiveCount(); got != 1 {
		t.Errorf("ActiveCount after race: got %d, want 1 (orphaned arms = leak)", got)
	}
	_ = a.CancelDeadman("txn-race")
}

// TestArmer_ConcurrentArms_DifferentTxns: 8 goroutines arm
// 8 distinct txn_ids concurrently; all succeed, all
// cancellable.
func TestArmer_ConcurrentArms_DifferentTxns(t *testing.T) {
	a := New()
	const n = 8
	var failures atomic.Int64
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			txnID := "txn-" + string(rune('A'+idx))
			if _, err := a.ArmDeadman(txnID, 5*time.Second, nil); err != nil {
				failures.Add(1)
				t.Errorf("goroutine %d: %v", idx, err)
			}
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}
	if failures.Load() > 0 {
		t.Fatalf("%d concurrent arm failures", failures.Load())
	}
	if got := a.ActiveCount(); got != n {
		t.Errorf("ActiveCount: got %d, want %d", got, n)
	}
	// Cancel them all.
	for i := 0; i < n; i++ {
		_ = a.CancelDeadman("txn-" + string(rune('A'+i)))
	}
	if got := a.ActiveCount(); got != 0 {
		t.Errorf("after cancel-all: ActiveCount=%d, want 0", got)
	}
}
