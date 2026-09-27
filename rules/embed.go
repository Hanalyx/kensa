// Package rules is the Kensa rule corpus as a file tree compiled into the
// program that imports it.
//
// A program that links the Kensa module gets, from this package, exactly the
// corpus of the module version it pins. The engine and the corpus then come
// from one version and cannot be paired wrongly at install time, which a
// corpus read from /usr/share/kensa/rules can be.
//
// Load the tree with the file-tree loaders in pkg/kensa. The standalone kensa
// binaries do not import this package: they read the corpus at run time, so it
// can be updated without a binary release.
package rules

import (
	"embed"
	"io/fs"
)

// The pattern must collect exactly what the directory loaders collect, which
// is every *.yml file under this directory. Today every rule sits one level
// down, in a topic directory. TestEmbeddedMatchesDisk fails if a rule file is
// ever added that this pattern misses.
//
//go:embed */*.yml
var corpus embed.FS

// FS returns the embedded corpus. Paths are relative to the corpus root, in
// the form "<topic>/<rule-id>.yml", the same layout the kensa-rules package
// installs under /usr/share/kensa/rules.
func FS() fs.FS {
	return corpus
}
