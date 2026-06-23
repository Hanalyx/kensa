package cronjob

import (
	"os"
	"path/filepath"
	"testing"
)

// existingMode preserves a pre-existing cron file's mode (so the agent rollback
// is metadata-byte-perfect) and falls back to cronFileMode when absent.
//
// @spec handler-cron-job
// @ac AC-04
func TestExistingMode_PreservesPriorMode(t *testing.T) {
	t.Run("handler-cron-job/AC-04", func(t *testing.T) {})
	dir := t.TempDir()
	f := filepath.Join(dir, "kensa-audit")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := existingMode(f); got.Perm() != 0o600 {
		t.Errorf("existingMode(0600 file) = %o, want 0600", got.Perm())
	}
	if got := existingMode(filepath.Join(dir, "nope")); got != cronFileMode {
		t.Errorf("existingMode(absent) = %o, want fallback %o", got, cronFileMode)
	}
}
