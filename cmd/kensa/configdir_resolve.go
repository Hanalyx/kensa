package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// resolveConfigDir picks the effective config directory using
// the auto-detect chain promised by the C-036 spec:
//
//  1. explicit value (operator passed --config-dir).
//  2. $KENSA_CONFIG_DIR env var.
//  3. $XDG_CONFIG_HOME/kensa.
//  4. $HOME/.config/kensa.
//  5. /etc/kensa.
//
// Returns "" when no candidate exists — operators get only the
// embedded built-in defaults. Returns the FIRST candidate that
// exists as a directory; later candidates are not consulted.
//
// The chain is per-invocation: changing $XDG_CONFIG_HOME between
// runs picks a different dir on the next run.
func resolveConfigDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, candidate := range configDirCandidates() {
		if candidate == "" {
			continue
		}
		if isDir(candidate) {
			return candidate
		}
	}
	return ""
}

// configDirCandidates returns the auto-detect chain in order,
// excluding the explicit-value tier (which is checked
// separately in resolveConfigDir).
func configDirCandidates() []string {
	out := make([]string, 0, 4)
	if v := os.Getenv("KENSA_CONFIG_DIR"); v != "" {
		out = append(out, v)
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		out = append(out, filepath.Join(v, "kensa"))
	}
	if v := os.Getenv("HOME"); v != "" {
		out = append(out, filepath.Join(v, ".config", "kensa"))
	}
	out = append(out, "/etc/kensa")
	return out
}

// isDir returns true when path exists and is a directory.
// Non-directory entries (regular files, symlinks to non-
// directories) and any stat errors return false. Used by the
// auto-detect chain to skip candidates that don't exist.
func isDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		return false // permission denied / other; skip
	}
	return info.IsDir()
}
