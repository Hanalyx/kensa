// Atomic file-system primitives for the agent. P-001
// deliverable per spec PHASE-2-BREAKDOWN P-001 (ratified
// 2026-05-11). Reworked under fix/phase-2-rework after the
// post-merge security review identified symlink-follow and
// probe-cache P0s.
//
// **What this gives you.** Mid-write crashes leave either
// the OLD bytes intact or the NEW bytes complete; readers
// never observe a torn or half-written file. The agent
// uses these primitives in Apply paths for the file-touching
// capturable handlers (file_content, file_absent, config_set,
// config_set_dropin).
//
// **Symlink policy: REFUSE.** All primitives walk the
// supplied path component-by-component using `O_NOFOLLOW` and
// refuse to operate if any component (including the base) is
// a symlink. This is the strong fix for the symlink-traversal
// vulnerability: an attacker who plants
// `/etc/sudoers.d/99-foo → /etc/passwd` cannot use fsatomic
// to rewrite `/etc/passwd`; the walk surfaces
// `ErrSymlinkInPath`.
//
// **The three operations:**
//
//	AtomicWrite(dir, name, mode, content)
//	   publishes a NEW file. Errors with ErrAlreadyExists if
//	   `name` already exists in `dir`. Uses O_TMPFILE +
//	   Linkat — unpublished bytes never exist as a visible-
//	   but-incomplete file in the directory.
//
//	AtomicReplace(fullPath, mode, content)
//	   replaces an EXISTING regular file. Uses Renameat2 with
//	   RENAME_EXCHANGE for symmetric old↔new swap; falls back
//	   to Renameat (rename-into-place) on filesystems that
//	   don't support RENAME_EXCHANGE (cached per-filesystem
//	   via st_dev). Errors with ErrNotExist if `fullPath`
//	   doesn't exist; refuses symlinks (use the target path
//	   directly, not a symlink to it).
//
//	AtomicRemove(fullPath)
//	   removes an existing regular file via Unlinkat. The
//	   unlink is atomic at the syscall level; refuses
//	   symlinks.
//
// **fsync discipline.** Every primitive issues:
//   - Fsync on the file fd (or skipped for AtomicRemove)
//   - Fsync on the parent dir fd (so the directory entry
//     persists across crashes)
//
// **Error message convention.** Every error string ends with
// a parenthesized destination-state classifier so the
// operator knows what's on disk:
//   - "(old bytes intact)" — failure before publish; target
//     is byte-identical to pre-call state.
//   - "(new bytes published, ...)" — publish succeeded; a
//     later step failed (typically temp cleanup or fsync).
//   - "(file removed, ...)" — for AtomicRemove fsync failures.
//
// **Filesystem capability cache.** RENAME_EXCHANGE is kernel
// ≥3.15 + ext4/btrfs/xfs/tmpfs; older kernels return ENOSYS,
// some filesystems return EINVAL/EOPNOTSUPP/ENOTSUP. We probe
// once per filesystem (keyed by st_dev) and cache the result.
// First-observed unsupported filesystem emits a one-time
// stderr warning.
package fsatomic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ErrAlreadyExists is returned by AtomicWrite when the target
// name already exists in the parent directory. AtomicReplace
// should be used instead for replace semantics.
var ErrAlreadyExists = errors.New("fsatomic: target already exists")

// ErrNotExist is returned by AtomicReplace and AtomicRemove
// when the target doesn't exist.
var ErrNotExist = errors.New("fsatomic: target does not exist")

// ErrSymlinkInPath is returned when any component of the
// supplied path (including the base) is a symlink. The
// package refuses to follow symlinks; callers must pass the
// resolved target path directly.
var ErrSymlinkInPath = errors.New("fsatomic: refuses to follow symlink in path")

// ErrParentDirMissing is returned when the parent directory
// of the supplied path does not exist (or is missing an
// intermediate component).
var ErrParentDirMissing = errors.New("fsatomic: parent directory does not exist")

// renameExchangeCache stores per-filesystem RENAME_EXCHANGE
// probe results. Key: syscall Stat_t.Dev (uint64). Value: int
// (1 = supported, 2 = unsupported).
var renameExchangeCache sync.Map

// warnRenameExchangeOnce surfaces a one-time stderr warning
// the first time we observe RENAME_EXCHANGE unsupported on
// any filesystem.
var warnRenameExchangeOnce sync.Once

// AtomicWrite publishes new file content at dir/name with the
// given mode. Errors with ErrAlreadyExists if name already
// exists in dir. The path is walked component-by-component
// with O_NOFOLLOW; any symlink encountered surfaces
// ErrSymlinkInPath.
//
// Implementation:
//  1. Walk dir component-by-component with O_NOFOLLOW
//     (refuses symlinks); obtain a parent dir fd.
//  2. Pre-check name doesn't exist via Fstatat (refuses
//     symlinks at the leaf too).
//  3. Create an unnamed temp file in parentFd via O_TMPFILE.
//  4. Write content + Fsync the temp file + Fchmod.
//  5. Linkat the temp fd to parentFd/name (atomically
//     publish via /proc/self/fd/<N>).
//  6. Fsync the parent dir fd so the directory entry
//     persists.
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

	parentFd, base, err := safeOpenParentDir(fullPath)
	if err != nil {
		return err
	}
	defer unix.Close(parentFd)

	// Pre-check name doesn't exist. AT_SYMLINK_NOFOLLOW so a
	// planted symlink at the target is detected here rather
	// than silently followed by Linkat.
	var st unix.Stat_t
	if err := unix.Fstatat(parentFd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return fmt.Errorf("%w: %s (old bytes intact)", ErrAlreadyExists, fullPath)
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("fsatomic: stat target: %w (old bytes intact)", err)
	}

	// O_TMPFILE inside parentFd creates an unnamed regular
	// file. The mode arg is applied with umask masking; the
	// explicit Fchmod below defends against that.
	tmpFd, err := unix.Openat(parentFd, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, uint32(mode))
	if err != nil {
		return fmt.Errorf("fsatomic: O_TMPFILE in %s: %w (old bytes intact)", dir, err)
	}
	tmpFile := os.NewFile(uintptr(tmpFd), "<tmpfile>")
	defer tmpFile.Close()

	if _, err := tmpFile.Write(content); err != nil {
		return fmt.Errorf("fsatomic: write tmpfile: %w (old bytes intact)", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("fsatomic: fsync tmpfile: %w (old bytes intact)", err)
	}
	if err := unix.Fchmod(tmpFd, uint32(mode)&0o7777); err != nil {
		return fmt.Errorf("fsatomic: fchmod tmpfile: %w (old bytes intact)", err)
	}

	// Linkat publishes the O_TMPFILE via /proc/self/fd/<N>.
	// AT_SYMLINK_FOLLOW follows the proc symlink (a symlink
	// the kernel manages, NOT user input — safe).
	procPath := fmt.Sprintf("/proc/self/fd/%d", tmpFd)
	if err := unix.Linkat(unix.AT_FDCWD, procPath, parentFd, base, unix.AT_SYMLINK_FOLLOW); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s (old bytes intact, race with another writer)", ErrAlreadyExists, fullPath)
		}
		return fmt.Errorf("fsatomic: linkat publish: %w (old bytes intact)", err)
	}

	if err := unix.Fsync(parentFd); err != nil {
		return fmt.Errorf("fsatomic: fsync parent dir: %w (new bytes published but not durable until next sync)", err)
	}
	return nil
}

// AtomicReplace atomically swaps the bytes at fullPath with
// the given content. Errors with ErrNotExist if fullPath
// doesn't exist; errors with ErrSymlinkInPath if any
// component of fullPath (including the base) is a symlink.
//
// Implementation:
//  1. Walk fullPath component-by-component with O_NOFOLLOW.
//  2. Verify base is a regular file (not symlink, not dir).
//  3. Write content to a sibling temp file
//     (`.<name>.fsatomic.<rand>`) with the requested mode
//     via Openat into parentFd with O_NOFOLLOW.
//  4. Fchmod + Fsync the temp file.
//  5. Renameat2(RENAME_EXCHANGE) to swap temp ↔ target, OR
//     fall back to Renameat (rename-into-place) on
//     filesystems that don't support RENAME_EXCHANGE.
//  6. Unlink the now-unused old-content file (the temp name
//     post-swap; absent in fallback path).
//  7. Fsync the parent dir.
func AtomicReplace(ctx context.Context, fullPath string, mode os.FileMode, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	parentFd, base, err := safeOpenParentDir(fullPath)
	if err != nil {
		return err
	}
	defer unix.Close(parentFd)

	// Verify target exists, is not a symlink, is a regular
	// file (not a directory).
	var st unix.Stat_t
	if err := unix.Fstatat(parentFd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%w: %s", ErrNotExist, fullPath)
		}
		return fmt.Errorf("fsatomic: stat target: %w (old bytes intact)", err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("%w: %s", ErrSymlinkInPath, fullPath)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("fsatomic: target is not a regular file: %s (old bytes intact)", fullPath)
	}

	// Random temp suffix avoids intra-process goroutine
	// collisions AND cross-process collisions.
	tempName := fmt.Sprintf(".%s.fsatomic.%s", base, randomSuffix())

	// O_CREAT|O_EXCL refuses if the random name somehow
	// collides; O_NOFOLLOW refuses if an attacker planted a
	// symlink at the temp name.
	tmpFd, err := unix.Openat(parentFd, tempName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		uint32(mode))
	if err != nil {
		return fmt.Errorf("fsatomic: create temp: %w (old bytes intact)", err)
	}
	tmpFile := os.NewFile(uintptr(tmpFd), "<temp>")

	cleanup := func() {
		_ = tmpFile.Close()
		_ = unix.Unlinkat(parentFd, tempName, 0)
	}

	if _, err := tmpFile.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("fsatomic: write temp: %w (old bytes intact)", err)
	}
	if err := tmpFile.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsatomic: fsync temp: %w (old bytes intact)", err)
	}
	// Explicit Fchmod (umask may have masked off bits during
	// O_CREAT).
	if err := unix.Fchmod(tmpFd, uint32(mode)&0o7777); err != nil {
		cleanup()
		return fmt.Errorf("fsatomic: fchmod temp: %w (old bytes intact)", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = unix.Unlinkat(parentFd, tempName, 0)
		return fmt.Errorf("fsatomic: close temp: %w (old bytes intact)", err)
	}

	if supportsRenameExchange(parentFd) {
		if err := unix.Renameat2(parentFd, tempName, parentFd, base, unix.RENAME_EXCHANGE); err != nil {
			_ = unix.Unlinkat(parentFd, tempName, 0)
			return fmt.Errorf("fsatomic: renameat2 exchange: %w (old bytes intact)", err)
		}
		// Old content is now at tempName. Remove it.
		if err := unix.Unlinkat(parentFd, tempName, 0); err != nil {
			return fmt.Errorf("fsatomic: unlink old-content after swap: %w (new bytes published; old bytes left at %s)", err, tempName)
		}
	} else {
		// Renameat rename-into-place. Atomic at syscall level.
		if err := unix.Renameat(parentFd, tempName, parentFd, base); err != nil {
			_ = unix.Unlinkat(parentFd, tempName, 0)
			return fmt.Errorf("fsatomic: renameat (fallback): %w (old bytes intact)", err)
		}
	}

	if err := unix.Fsync(parentFd); err != nil {
		return fmt.Errorf("fsatomic: fsync parent dir post-swap: %w (new bytes published but not durable until next sync)", err)
	}
	return nil
}

// AtomicRemove unlinks fullPath. Errors with ErrNotExist if
// the file doesn't exist; refuses to follow symlinks.
func AtomicRemove(ctx context.Context, fullPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	parentFd, base, err := safeOpenParentDir(fullPath)
	if err != nil {
		return err
	}
	defer unix.Close(parentFd)

	var st unix.Stat_t
	if err := unix.Fstatat(parentFd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%w: %s", ErrNotExist, fullPath)
		}
		return fmt.Errorf("fsatomic: stat target: %w (file intact)", err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("%w: %s", ErrSymlinkInPath, fullPath)
	}

	if err := unix.Unlinkat(parentFd, base, 0); err != nil {
		return fmt.Errorf("fsatomic: unlinkat: %w (file intact)", err)
	}
	if err := unix.Fsync(parentFd); err != nil {
		return fmt.Errorf("fsatomic: fsync parent dir post-unlink: %w (file removed but not durable until next sync)", err)
	}
	return nil
}

// safeOpenParentDir walks fullPath component-by-component
// using O_NOFOLLOW and returns (parentDirFd, base, error).
// Caller MUST close parentDirFd via unix.Close.
//
// Any symlink encountered along the way → ErrSymlinkInPath.
// Any missing intermediate component → ErrParentDirMissing.
// Any non-directory intermediate → typed "not a directory"
// error. The fullPath argument MUST be absolute and not "/".
//
// The base filename is NOT opened — callers Fstatat/Openat
// against the returned parentFd as needed. Symlink-ness of
// the base is checked by callers via AT_SYMLINK_NOFOLLOW.
func safeOpenParentDir(fullPath string) (int, string, error) {
	if !filepath.IsAbs(fullPath) {
		return -1, "", fmt.Errorf("fsatomic: path must be absolute: %q", fullPath)
	}
	cleaned := filepath.Clean(fullPath)
	if cleaned == "/" {
		return -1, "", fmt.Errorf("fsatomic: cannot operate on filesystem root")
	}
	parentPath := filepath.Dir(cleaned)
	base := filepath.Base(cleaned)
	if base == "" || base == "/" || base == "." || base == ".." {
		return -1, "", fmt.Errorf("fsatomic: invalid base filename %q", base)
	}

	dirFd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("fsatomic: open /: %w", err)
	}

	if parentPath != "/" {
		parts := strings.Split(strings.TrimPrefix(parentPath, "/"), "/")
		for _, component := range parts {
			if component == "" || component == "." || component == ".." {
				_ = unix.Close(dirFd)
				return -1, "", fmt.Errorf("fsatomic: invalid path component %q in %s", component, fullPath)
			}
			nextFd, openErr := unix.Openat(dirFd, component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr != nil {
				// Linux returns ELOOP for O_NOFOLLOW on a symlink
				// in the general case but ENOTDIR when O_DIRECTORY
				// is also set (the kernel sees the symlink dentry,
				// which is not a directory, before evaluating the
				// follow). Distinguish via a NOFOLLOW Fstatat.
				isSymlink := false
				var compSt unix.Stat_t
				if statErr := unix.Fstatat(dirFd, component, &compSt, unix.AT_SYMLINK_NOFOLLOW); statErr == nil {
					if compSt.Mode&unix.S_IFMT == unix.S_IFLNK {
						isSymlink = true
					}
				}
				_ = unix.Close(dirFd)
				if isSymlink {
					return -1, "", fmt.Errorf("%w: %s (symlink at component %q)", ErrSymlinkInPath, fullPath, component)
				}
				if errors.Is(openErr, unix.ELOOP) {
					return -1, "", fmt.Errorf("%w: %s (symlink at component %q)", ErrSymlinkInPath, fullPath, component)
				}
				if errors.Is(openErr, unix.ENOENT) {
					return -1, "", fmt.Errorf("%w: %s (component %q missing)", ErrParentDirMissing, fullPath, component)
				}
				if errors.Is(openErr, unix.ENOTDIR) {
					return -1, "", fmt.Errorf("fsatomic: path component %q is not a directory in %s", component, fullPath)
				}
				return -1, "", fmt.Errorf("fsatomic: open intermediate %q: %w", component, openErr)
			}
			_ = unix.Close(dirFd)
			dirFd = nextFd
		}
	}

	return dirFd, base, nil
}

// supportsRenameExchange probes the filesystem (keyed by
// st_dev) for RENAME_EXCHANGE support. Result is cached
// per-filesystem; first unsupported observation emits a
// one-time stderr warning.
func supportsRenameExchange(parentFd int) bool {
	var st unix.Stat_t
	if err := unix.Fstat(parentFd, &st); err != nil {
		// Can't determine fs; assume supported and let the
		// real call surface the error.
		return true
	}
	if v, ok := renameExchangeCache.Load(st.Dev); ok {
		return v.(int) == 1
	}

	probeA := ".fsatomic.probe.a." + randomSuffix()
	probeB := ".fsatomic.probe.b." + randomSuffix()
	err := unix.Renameat2(parentFd, probeA, parentFd, probeB, unix.RENAME_EXCHANGE)

	var supported int
	switch {
	case errors.Is(err, unix.ENOENT):
		// Call reached the kernel + fs accepted the call
		// shape; only failed because the probe names don't
		// exist.
		supported = 1
	case errors.Is(err, unix.ENOSYS),
		errors.Is(err, unix.EINVAL),
		errors.Is(err, unix.EOPNOTSUPP),
		errors.Is(err, unix.ENOTSUP):
		supported = 2
		warnRenameExchangeOnce.Do(func() {
			fmt.Fprintln(os.Stderr, "kensa: fsatomic: RENAME_EXCHANGE unsupported on at least one mounted filesystem; using rename-into-place fallback (atomic at the syscall level but no symmetric swap)")
		})
	default:
		// Inconclusive (EACCES, EBUSY, etc.). Conservative:
		// assume supported and let the real call surface the
		// error.
		supported = 1
	}
	renameExchangeCache.Store(st.Dev, supported)
	return supported == 1
}

// randomSuffix returns a 16-character hex string from
// crypto/rand. Used for collision-free temp filenames.
func randomSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
