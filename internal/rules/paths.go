// Package rules holds runtime resolution policy for rule loading.
//
// The binary carries no embedded corpus — rules ship as the kensa-rules
// package and install to DefaultPath. Resolve picks the effective rules
// directory: explicit operator intent wins, then positional rule files
// alone (no dir-walk), then the packaged default, then a usage error.
package rules

import (
	"fmt"
	"os"
)

// DefaultPath is where the kensa-rules package installs the corpus.
// Resolve falls back to this when --rules-dir is unset and no positional
// rule paths are given.
const DefaultPath = "/usr/share/kensa/rules"

// Resolve picks the effective rules directory.
//
// Inputs:
//   - dir: the value of --rules-dir (may be "")
//   - paths: any positional rule YAML paths the operator passed
//   - stat: filesystem stat injection — typically os.Stat in production, a
//     stub in tests
//
// Returns:
//   - dir verbatim when dir != "" (explicit operator intent wins; C-01)
//   - ("", nil) when dir == "" and len(paths) > 0 (positional files alone;
//     caller loads paths without dir-walking; C-02)
//   - (DefaultPath, nil) when dir == "" and paths is empty and stat
//     succeeds for DefaultPath (kensa-rules package present; C-03)
//   - ("", err) when dir == "" and paths is empty and stat fails for
//     DefaultPath — err names both --rules-dir AND DefaultPath so the
//     operator sees the two fix paths (C-04)
func Resolve(dir string, paths []string, stat func(string) (os.FileInfo, error)) (string, error) {
	// C-01: explicit --rules-dir wins. Stat the operator's choice is
	// the existing loader's job, not ours.
	if dir != "" {
		return dir, nil
	}
	// C-02: positional files alone — let the caller load them; don't
	// drag in the default corpus on top of an explicit file set.
	if len(paths) > 0 {
		return "", nil
	}
	// C-03/C-04: no flag, no positional paths. Fall back to the
	// packaged default when present; otherwise return a usage error
	// that names BOTH fix paths.
	if _, err := stat(DefaultPath); err == nil {
		return DefaultPath, nil
	}
	return "", fmt.Errorf(
		"no rules to load: pass --rules-dir <dir>, give one or more rule YAML paths, "+
			"or install the kensa-rules package (default path: %s)",
		DefaultPath,
	)
}
