// Atomic file-system primitives for the agent. P-001
// deliverable per spec PHASE-2-BREAKDOWN P-001 (ratified
// 2026-05-11).
//
// **What this gives you.** Mid-write crashes leave either
// the OLD bytes intact or the NEW bytes complete; readers
// never observe a torn or half-written file. The agent
// uses these primitives in Apply paths for the file-touching
// capturable handlers (P-002..P-005 migrate file_content,
// file_absent, config_set, config_set_dropin).
//
// **The three operations:**
//
//   AtomicWrite(dir, name, mode, content)
//      publishes a NEW file. Errors if `name` already
//      exists in `dir`. Uses O_TMPFILE + Linkat —
//      unpublished bytes never exist as a visible-but-
//      incomplete file in the directory.
//
//   AtomicReplace(fullPath, mode, content)
//      replaces an EXISTING file. Uses Renameat2 with
//      RENAME_EXCHANGE for symmetric old↔new swap; falls
//      back to Renameat (rename-into-place) on older
//      kernels or filesystems that don't support
//      RENAME_EXCHANGE. Errors if `fullPath` doesn't
//      exist.
//
//   AtomicRemove(fullPath)
//      removes an existing file via Unlinkat. The
//      unlink is atomic at the syscall level; provided
//      here so callers don't have to import unix
//      directly.
//
// **fsync discipline.** Every primitive issues:
//   - Fsync on the file fd (or skipped for AtomicRemove)
//   - Fsync on the parent dir fd (so the directory entry
//     persists across crashes)
// Without parent-dir fsync, a crash between write+fsync
// and a hypothetical scheduled sync could leave the
// directory entry absent — the bytes are on disk but no
// way to find them.
//
// **Filesystem capability cache.** RENAME_EXCHANGE is
// kernel ≥3.15 + ext4/btrfs/xfs; older ones get ENOSYS.
// We probe once per agent startup (lazy on first
// AtomicReplace) and cache the result; fallback path uses
// Renameat (atomic rename into place, sans the symmetric
// swap).

package fsatomic

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// ErrAlreadyExists is returned by AtomicWrite when the
// target name already exists in the parent directory.
// AtomicReplace should be used instead for replace
// semantics.
var ErrAlreadyExists = errors.New("fsatomic: target already exists")

// ErrNotExist is returned by AtomicReplace and
// AtomicRemove when the target doesn't exist.
var ErrNotExist = errors.New("fsatomic: target does not exist")

// renameExchangeSupported is the cached capability probe.
// Lazily initialized on first AtomicReplace call. 0 =
// unknown, 1 = supported, 2 = unsupported.
var renameExchangeSupported atomic.Int32
var renameExchangeOnce sync.Once

// AtomicWrite publishes new file content at dir/name with
// the given mode. Errors with ErrAlreadyExists if name is
// already a regular file or symlink in dir.
//
// Implementation:
//   1. Open dir via os.Open (dir fd).
//   2. Create an unnamed temp file in dir via O_TMPFILE.
//   3. Write content + Fsync the temp file.
//   4. Linkat the temp fd to dir/name (atomically publish).
//   5. Fsync the dir fd so the directory entry persists.
//
// O_TMPFILE means the temp file is invisible until the
// Linkat — there's no "partially-named file in the dir"
// state visible to other processes.
func AtomicWrite(ctx context.Context, dir, name string, mode os.FileMode, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if name == "" || filepath.Base(name) != name {
		return fmt.Errorf("fsatomic: name must be a base filename, not a path: %q", name)
	}
	fullPath := filepath.Join(dir, name)
	// ErrAlreadyExists pre-check. Linkat would also reject,
	// but pre-checking gives a cleaner error than EEXIST.
	if _, err := os.Lstat(fullPath); err == nil {
		return fmt.Errorf("%w: %s", ErrAlreadyExists, fullPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("fsatomic: stat: %w", err)
	}

	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("fsatomic: open parent dir %s: %w", dir, err)
	}
	defer dirFile.Close()
	dirFd := int(dirFile.Fd())

	// O_TMPFILE creates an unnamed regular file in dir.
	// O_RDWR | O_TMPFILE per the Linux man page.
	tmpFd, err := unix.Openat(dirFd, ".", unix.O_RDWR|unix.O_TMPFILE, uint32(mode))
	if err != nil {
		return fmt.Errorf("fsatomic: O_TMPFILE in %s: %w", dir, err)
	}
	tmpFile := os.NewFile(uintptr(tmpFd), "<tmpfile>")
	defer tmpFile.Close()

	if _, err := tmpFile.Write(content); err != nil {
		return fmt.Errorf("fsatomic: write: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("fsatomic: fsync tmpfile: %w", err)
	}

	// Linkat the temp fd into the directory via the
	// AT_SYMLINK_FOLLOW flag with the /proc/self/fd path
	// trick. This is the canonical recipe for publishing
	// an O_TMPFILE.
	procPath := fmt.Sprintf("/proc/self/fd/%d", tmpFd)
	if err := unix.Linkat(unix.AT_FDCWD, procPath, dirFd, name, unix.AT_SYMLINK_FOLLOW); err != nil {
		return fmt.Errorf("fsatomic: linkat publish: %w", err)
	}

	// Fsync the parent dir so the new directory entry
	// persists across crashes.
	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("fsatomic: fsync parent dir: %w", err)
	}
	return nil
}

// AtomicReplace atomically swaps the bytes at fullPath
// with the given content. Errors with ErrNotExist if
// fullPath doesn't exist (use AtomicWrite for new files).
//
// Implementation:
//   1. Write content to a sibling temp file
//      (`.<name>.fsatomic.<pid>`) with the requested mode.
//   2. Fsync the temp file.
//   3. Renameat2(RENAME_EXCHANGE) to swap temp ↔ target,
//      OR fall back to Renameat (rename-into-place) on
//      filesystems that don't support RENAME_EXCHANGE.
//   4. Unlink the now-unused old-content file (the temp
//      name post-swap).
//   5. Fsync the parent dir.
//
// Symlink handling: AtomicReplace follows symlinks via
// Realpath before operating. Replacing a symlink's
// target preserves the symlink's existence; replacing
// the symlink itself would require an explicit flag
// (deferred for a future deliverable if needed).
func AtomicReplace(ctx context.Context, fullPath string, mode os.FileMode, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Follow symlinks to operate on the target file. If
	// fullPath is a symlink to /etc/foo, the replace
	// happens at /etc/foo and the symlink itself is
	// preserved. Per the founder-ratified question Q2.
	resolvedPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNotExist, fullPath)
		}
		return fmt.Errorf("fsatomic: resolve symlinks: %w", err)
	}

	dir := filepath.Dir(resolvedPath)
	name := filepath.Base(resolvedPath)
	tempName := fmt.Sprintf(".%s.fsatomic.%d", name, os.Getpid())
	tempPath := filepath.Join(dir, tempName)

	// Write content to the sibling temp file.
	tmp, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("fsatomic: create temp: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tempPath)
		return fmt.Errorf("fsatomic: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tempPath)
		return fmt.Errorf("fsatomic: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("fsatomic: close temp: %w", err)
	}
	// Explicit chmod (the umask may have masked off bits
	// during OpenFile).
	if err := os.Chmod(tempPath, mode); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("fsatomic: chmod temp: %w", err)
	}

	// Open the parent dir for the swap + fsync.
	dirFile, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("fsatomic: open parent dir: %w", err)
	}
	defer dirFile.Close()
	dirFd := int(dirFile.Fd())

	useExchange := supportsRenameExchange(dirFd, tempName, name)
	if useExchange {
		// RENAME_EXCHANGE: swap temp ↔ target, then unlink
		// the old-content file (now at tempName).
		if err := unix.Renameat2(dirFd, tempName, dirFd, name, unix.RENAME_EXCHANGE); err != nil {
			_ = os.Remove(tempPath)
			return fmt.Errorf("fsatomic: renameat2 exchange: %w", err)
		}
		if err := unix.Unlinkat(dirFd, tempName, 0); err != nil {
			// Old content is now at tempName but we
			// can't unlink it — leave it; the new content
			// is in place. Operator cleanup task.
			return fmt.Errorf("fsatomic: unlink old-content after swap (new bytes are in place): %w", err)
		}
	} else {
		// Fallback: Renameat rename-into-place. Atomic at
		// the syscall level but no swap; the old target
		// is simply replaced.
		if err := unix.Renameat(dirFd, tempName, dirFd, name); err != nil {
			_ = os.Remove(tempPath)
			return fmt.Errorf("fsatomic: renameat (fallback): %w", err)
		}
	}

	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("fsatomic: fsync parent dir post-swap: %w", err)
	}
	return nil
}

// AtomicRemove unlinks fullPath. Errors with ErrNotExist
// if the file doesn't exist.
func AtomicRemove(ctx context.Context, fullPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(fullPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNotExist, fullPath)
		}
		return fmt.Errorf("fsatomic: stat: %w", err)
	}
	dir := filepath.Dir(fullPath)
	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("fsatomic: open parent dir: %w", err)
	}
	defer dirFile.Close()
	dirFd := int(dirFile.Fd())
	if err := unix.Unlinkat(dirFd, filepath.Base(fullPath), 0); err != nil {
		return fmt.Errorf("fsatomic: unlinkat: %w", err)
	}
	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("fsatomic: fsync parent dir post-unlink: %w", err)
	}
	return nil
}

// supportsRenameExchange probes the kernel + filesystem
// for RENAME_EXCHANGE support. Cached after first probe.
// Probe attempts a no-op RENAME_EXCHANGE on a known-
// nonexistent pair; success or ENOENT means the syscall
// is supported (the filesystem accepted the call shape).
// ENOSYS or EINVAL on the flag means unsupported.
//
// Lazy-init via sync.Once so multiple goroutines don't
// race to probe.
func supportsRenameExchange(dirFd int, src, dst string) bool {
	renameExchangeOnce.Do(func() {
		// Probe: RENAME_EXCHANGE on two definitely-
		// nonexistent names should return ENOENT (call
		// reached the kernel + filesystem) rather than
		// ENOSYS or EINVAL.
		probeA := ".fsatomic.probe.a"
		probeB := ".fsatomic.probe.b"
		err := unix.Renameat2(dirFd, probeA, dirFd, probeB, unix.RENAME_EXCHANGE)
		if errors.Is(err, unix.ENOENT) {
			renameExchangeSupported.Store(1)
		} else if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			renameExchangeSupported.Store(2)
		} else {
			// Other error (permission denied, etc.) is
			// inconclusive — assume supported. The actual
			// swap call will surface the real error.
			renameExchangeSupported.Store(1)
		}
		// Suppress unused-arg warnings.
		_ = src
		_ = dst
	})
	return renameExchangeSupported.Load() == 1
}
