package kernelio

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/Hanalyx/kensa/internal/agent/fsatomic"
)

// WriteFile atomically writes content to fullPath whether or not it
// already exists — the create-OR-replace primitive the drop-in handlers
// need. fsatomic deliberately splits the two cases (AtomicWrite errors
// ErrAlreadyExists on an existing target; AtomicReplace errors ErrNotExist
// on a missing one), so this tries AtomicWrite (create) and falls back to
// AtomicReplace (replace) when the file already exists. The two-step form
// is also race-tolerant: if the file is created or removed by another
// writer between the attempts, the fallback still lands on the right
// primitive.
//
// This is the fix for the live-caught bug where a handler used
// AtomicReplace for a drop-in file that did not yet exist (e.g. a fresh
// /etc/sysctl.d/99-kensa.conf), which failed ErrNotExist on first apply.
func WriteFile(ctx context.Context, ft FileTransport, fullPath string, mode fs.FileMode, content []byte) error {
	dir, name := filepath.Split(fullPath)
	dir = filepath.Clean(dir)
	err := ft.AtomicWrite(ctx, dir, name, mode, content)
	if errors.Is(err, fsatomic.ErrAlreadyExists) {
		return ft.AtomicReplace(ctx, fullPath, mode, content)
	}
	return err
}

// RemoveFile atomically removes fullPath, treating an already-absent file
// as success (fsatomic.AtomicRemove errors ErrNotExist on a missing
// target). Rollback uses it so "ensure this drop-in is gone" is idempotent
// — it must not fail when the file was never created.
func RemoveFile(ctx context.Context, ft FileTransport, fullPath string) error {
	err := ft.AtomicRemove(ctx, fullPath)
	if errors.Is(err, fsatomic.ErrNotExist) {
		return nil
	}
	return err
}
