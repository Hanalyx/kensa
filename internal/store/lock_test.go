package store_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa/internal/store"
)

// @spec recovery-replay
// @ac AC-04
func TestRecoverLock_ExclusiveFencing(t *testing.T) {
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-04")
	path := filepath.Join(t.TempDir(), "results.db.recover.lock")

	l1, err := store.AcquireRecoverLock(path, true)
	if err != nil {
		t.Fatalf("first exclusive acquire: %v", err)
	}

	// A second exclusive acquire must fail fast (fencing).
	if _, err := store.AcquireRecoverLock(path, true); !errors.Is(err, store.ErrRecoverLocked) {
		t.Errorf("second exclusive acquire should be ErrRecoverLocked; got %v", err)
	}
	// A shared acquire must also be blocked while exclusive is held.
	if _, err := store.AcquireRecoverLock(path, false); !errors.Is(err, store.ErrRecoverLocked) {
		t.Errorf("shared acquire under an exclusive lock should be ErrRecoverLocked; got %v", err)
	}

	// After release, the lock is re-acquirable.
	if err := l1.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	l2, err := store.AcquireRecoverLock(path, true)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	_ = l2.Release()
}

func TestRecoverLock_SharedAllowsShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.db.recover.lock")
	a, err := store.AcquireRecoverLock(path, false)
	if err != nil {
		t.Fatalf("first shared acquire: %v", err)
	}
	defer func() { _ = a.Release() }()
	// Two live engines may hold the shared lock concurrently.
	b, err := store.AcquireRecoverLock(path, false)
	if err != nil {
		t.Fatalf("second shared acquire should succeed; got %v", err)
	}
	_ = b.Release()
}
