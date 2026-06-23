package store

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrRecoverLocked is returned when the recover lock is already held by
// another process — a live engine working the same store, or another
// recovery run. The caller MUST NOT proceed with recovery.
var ErrRecoverLocked = errors.New("store: recover lock held by another process")

// RecoverLock is a cross-process advisory lock (flock) used to fence
// `kensa recover` runs. The lock file sits beside the store db. Recover takes
// it EXCLUSIVE (non-blocking, fails fast if held).
//
// The SHARED mode (exclusive=false) is the designed live-engine side of the
// fence — a live remediate/rollback would hold it SHARED so an exclusive
// recover waits for live work to drain rather than racing it. NOTE: that side
// is NOT yet wired — the live engine path does not currently take this lock,
// so today the lock fences recover against other recover runs only. Until the
// live path takes the shared lock, an operator MUST NOT run `kensa recover`
// against a host that has a live engine acting on the same store. Tracked in
// docs/roadmap/STATUS.md.
//
// flock is advisory and per-open-file-description, released automatically if
// the holding process dies (so a crash never leaves a permanent lock).
type RecoverLock struct {
	f *os.File
}

// RecoverLockPath returns the lock-file path beside a given store db path.
func RecoverLockPath(dbPath string) string { return dbPath + ".recover.lock" }

// AcquireRecoverLock takes the lock at path without blocking. exclusive=true
// (recover) takes LOCK_EX; exclusive=false (a live engine) takes LOCK_SH.
// Returns ErrRecoverLocked if the lock cannot be taken immediately.
func AcquireRecoverLock(path string, exclusive bool) (*RecoverLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: open recover lock %s: %w", path, err)
	}
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	if err := unix.Flock(int(f.Fd()), how|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrRecoverLocked
		}
		return nil, fmt.Errorf("store: flock recover lock: %w", err)
	}
	return &RecoverLock{f: f}, nil
}

// Release unlocks and closes the lock file. Safe on a nil lock.
func (l *RecoverLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return l.f.Close()
}
