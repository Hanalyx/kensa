package handlers

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Hanalyx/kensa/internal/handler"
)

// TestHandlerBundleCompleteness is the drift guard for issue #94: every
// internal/handlers/<mechanism>/ package MUST be blank-imported by this
// bundle. Importing this package (the test is in it) registers every
// bundled handler; the count must equal the number of handler packages on
// disk. A new handler dir that isn't added here fails this test — which
// is exactly the regression (#94) we are preventing from recurring.
//
// @spec pkg-handler-registration
// @ac AC-03
func TestHandlerBundleCompleteness(t *testing.T) {
	t.Run("pkg-handler-registration/AC-03", func(t *testing.T) {})

	registered := len(handler.Default().Names())
	dirs := handlerPackageDirs(t)

	if registered != len(dirs) {
		t.Fatalf("pkg/kensa/handlers registers %d handler(s) but internal/handlers has %d package(s) %v — a handler is missing from the bundle; add its blank import to handlers.go (issue #94 drift guard)",
			registered, len(dirs), dirs)
	}
}

// handlerPackageDirs returns the names of the per-mechanism packages under
// internal/handlers/ (directories containing Go source).
func handlerPackageDirs(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	base := filepath.Join(root, "internal", "handlers")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read %s: %v", base, err)
	}
	// nonHandlerPkgs are directories under internal/handlers/ that are
	// NOT per-mechanism handler packages and so must not be counted by
	// the bundle-completeness guard. servicedbus holds the systemd
	// dual-path helpers shared by the three service handlers; it
	// registers no mechanism of its own.
	nonHandlerPkgs := map[string]bool{
		"servicedbus": true,
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() || nonHandlerPkgs[e.Name()] {
			continue
		}
		// Only count directories that actually hold a handler package.
		goFiles, _ := filepath.Glob(filepath.Join(base, e.Name(), "*.go"))
		if len(goFiles) > 0 {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs
}

// repoRoot walks up from this test file to the directory containing go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod ancestor")
		}
		dir = parent
	}
}
