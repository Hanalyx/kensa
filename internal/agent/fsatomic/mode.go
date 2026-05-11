package fsatomic

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ValidatePath is a first-line check for rule-supplied paths
// before they reach either fsatomic (agent-mode) or the shell
// pipeline (direct-SSH). Requires:
//   - Absolute path
//   - Canonical form (no ".." segments after filepath.Clean)
//
// fsatomic's safeOpenParentDir enforces the same constraints
// internally, but the shell-fallback path has no such defense
// — a rule with `path: "../../etc/shadow"` would shell-resolve
// the path relative to the agent's cwd. This helper makes the
// rejection consistent across both transport paths.
func ValidatePath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path must be absolute: %q", p)
	}
	if p != filepath.Clean(p) {
		return fmt.Errorf("path must be canonical (no '..' or redundant separators): %q", p)
	}
	return nil
}

// ParseMode parses a file-mode string accepted in rule YAML
// — "644", "0644", or "0o644" — into an os.FileMode. The
// returned mode encodes the 9 permission bits in the low 9
// positions of the value. Empty input returns
// (os.FileMode(0), false, nil); callers handle the "no mode
// specified" intent themselves (typically by preserving the
// target file's current mode).
//
// Errors only on a non-empty string that doesn't parse as
// octal. Symbolic notation like "u=rw,g=r,o=r" is rejected
// — the rule corpus uses octal.
//
// Returns (mode, specified, error). `specified` is true iff
// the input was non-empty.
func ParseMode(s string) (os.FileMode, bool, error) {
	if s == "" {
		return 0, false, nil
	}
	cleaned := strings.TrimPrefix(s, "0o")
	n, err := strconv.ParseUint(cleaned, 8, 32)
	if err != nil {
		return 0, true, fmt.Errorf("invalid octal mode %q: %w", s, err)
	}
	return os.FileMode(n), true, nil
}

// FileModeBits extracts the 12 low Unix-mode bits (9 perm
// + setuid + setgid + sticky) from a Go os.FileMode and
// returns an os.FileMode whose `uint32()` cast yields the
// right Linux mode_t value.
//
// Why this is necessary: Go encodes ModeSetuid (1<<23),
// ModeSetgid (1<<22), and ModeSticky (1<<20) in HIGH bits,
// not in the 0o7777 range. A naive `info.Mode() & 0o7777`
// silently drops the special bits. Sed -i preserves all 12
// — kensa must match.
func FileModeBits(m os.FileMode) os.FileMode {
	raw := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		raw |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		raw |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		raw |= 0o1000
	}
	return os.FileMode(raw)
}

// FileExists reports whether path is a regular file or
// symlink on disk. Returns (false, nil) on os.ErrNotExist;
// (false, err) on other stat errors. Used by handlers to
// branch between AtomicWrite (new) and AtomicReplace
// (existing) in agent-mode Apply paths.
func FileExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
