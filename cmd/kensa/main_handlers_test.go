package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestMainHasNoHandlerBlankImports enforces the single-source-of-truth
// rule for issue #94: the CLI must NOT carry its own
// internal/handlers/* blank-import list. Handlers register transitively
// via pkg/kensa (which imports the pkg/kensa/handlers bundle), so the
// CLI handler set and the external-consumer handler set cannot diverge.
// Re-adding a direct handler list here would let the two drift apart.
//
// @spec pkg-handler-registration
// @ac AC-04
func TestMainHasNoHandlerBlankImports(t *testing.T) {
	t.Run("pkg-handler-registration/AC-04", func(t *testing.T) {})

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	mainPath := filepath.Join(filepath.Dir(file), "main.go")
	src, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if strings.Contains(string(src), "internal/handlers/") {
		t.Errorf("cmd/kensa/main.go imports internal/handlers/* directly; handlers must come via the pkg/kensa/handlers bundle (single source of truth, issue #94)")
	}
}
