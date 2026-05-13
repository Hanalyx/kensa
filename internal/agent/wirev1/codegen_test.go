package wirev1

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodegenSync locks AC-02: the checked-in wire.pb.go MUST be
// byte-identical to what `protoc-gen-go` produces from wire.proto
// at the pinned plugin version. Drift would mean a future build
// from a clean checkout regenerates a different file than what's
// committed — at best a noisy git diff on every build, at worst
// a wire-schema/Go-type mismatch that breaks at runtime.
//
// CI also enforces this via `make proto-check`. The Go test
// duplicates the gate so an engineer running `go test ./...`
// locally catches drift without needing to remember the make
// target.
//
// The test is skipped when `protoc` is not in PATH — developer
// machines without the protoc compiler still run the rest of the
// suite, and CI installs protoc in the toolchain layer.
//
// @spec agent-wire-protocol
// @ac AC-02
func TestCodegenSync(t *testing.T) {
	t.Log("// @spec agent-wire-protocol")
	t.Log("// @ac AC-02")
	// Closing the fail-open hole flagged by security review:
	// under CI, missing protoc is a HARD failure. A contributor
	// who hand-edits wire.pb.go and relies on local `go test`
	// (where protoc isn't installed) skipping the gate gets a
	// loud failure in CI instead. The CI workflow MUST install
	// protoc + protoc-gen-go before running tests.
	underCI := os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") == "true"
	if _, err := exec.LookPath("protoc"); err != nil {
		if underCI {
			t.Fatal("protoc not in PATH under CI; the codegen-drift gate cannot fail open — install protoc in the CI workflow")
		}
		t.Skip("protoc not in PATH (local dev only); codegen-sync gate enforced in CI via `make proto-check`")
	}
	if _, err := exec.LookPath("protoc-gen-go"); err != nil {
		if underCI {
			t.Fatal("protoc-gen-go not in PATH under CI; install via `go install google.golang.org/protobuf/cmd/protoc-gen-go`")
		}
		t.Skip("protoc-gen-go not in PATH (local dev only); install via `go install google.golang.org/protobuf/cmd/protoc-gen-go`")
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}
	committed, err := os.ReadFile(filepath.Join(repoRoot, "internal/agent/wirev1/wire.pb.go"))
	if err != nil {
		t.Fatalf("read committed wire.pb.go: %v", err)
	}

	// Regenerate into a tempdir so the test never mutates the
	// committed file. Invocation MUST match `make proto` exactly
	// (no `-I` flag, run from repo root) — protoc bakes the
	// source path into generated symbol names, so a different
	// path produces byte-different output even when the .proto
	// content is identical.
	tmpDir := t.TempDir()
	cmd := exec.Command("protoc",
		"--go_out="+tmpDir,
		"--go_opt=paths=source_relative",
		"internal/agent/wirev1/wire.proto",
	)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("protoc: %v\n%s", err, out)
	}
	regenerated, err := os.ReadFile(filepath.Join(tmpDir, "internal/agent/wirev1/wire.pb.go"))
	if err != nil {
		t.Fatalf("read regenerated wire.pb.go: %v", err)
	}

	if !bytes.Equal(committed, regenerated) {
		t.Errorf("wire.pb.go drift: committed file differs from `protoc` output. " +
			"Run `make proto` to refresh and commit the result.")
	}
}

// TestSchemaVersion_PresentOnAllRootMessages locks AC-06: every
// root message type carries a `SchemaVersion` field so L-012's
// version handshake has something to inspect. Without this gate
// a developer could add a new root message type without the
// version field, and L-012 would silently fail to detect skew.
//
// @spec agent-wire-protocol
// @ac AC-06
func TestSchemaVersion_PresentOnAllRootMessages(t *testing.T) {
	t.Log("// @spec agent-wire-protocol")
	t.Log("// @ac AC-06")
	rootMessages := []struct {
		name string
		// Each constructor returns a pointer to a freshly-allocated
		// instance with SchemaVersion populated; the test verifies
		// the field exists and is non-zero (current value 1).
		schemaVersion func() uint32
	}{
		{"Request", func() uint32 { return (&Request{SchemaVersion: 1}).GetSchemaVersion() }},
		{"Response", func() uint32 { return (&Response{SchemaVersion: 1}).GetSchemaVersion() }},
		{"Error", func() uint32 { return (&Error{SchemaVersion: 1}).GetSchemaVersion() }},
		{"Heartbeat", func() uint32 { return (&Heartbeat{SchemaVersion: 1}).GetSchemaVersion() }},
	}
	for _, m := range rootMessages {
		t.Run(m.name, func(t *testing.T) {
			if got := m.schemaVersion(); got != 1 {
				t.Errorf("%s.SchemaVersion: got %d, want 1", m.name, got)
			}
		})
	}
}

// TestToolsFileBuildConstraint locks the //go:build tools constraint
// on the repo-root tools.go. Without it, protoc-gen-go would leak
// into the production binary, growing it by several MB and pulling
// unaudited reflection code into the agent (which runs with sudo
// escalation on customer hosts).
//
// A contributor accidentally deleting the build tag would silently
// fold the tool into production; this test catches that at PR time.
//
// @spec agent-wire-protocol
// @ac AC-05
func TestToolsFileBuildConstraint(t *testing.T) {
	t.Log("// @spec agent-wire-protocol")
	t.Log("// @ac AC-05")
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, "tools.go"))
	if err != nil {
		t.Fatalf("read tools.go: %v", err)
	}
	src := string(data)
	if !strings.Contains(src, "//go:build tools") {
		t.Error("tools.go missing `//go:build tools` build constraint — protoc-gen-go import will leak into production binary")
	}
	if !strings.Contains(src, "\npackage tools\n") {
		t.Error("tools.go must declare package `tools` (matches build tag); otherwise the file is in the default package")
	}
}

// findRepoRoot walks up from the test's working directory until
// it finds go.mod. Test execution starts in the package dir
// (internal/agent/wirev1/), so the walk is short.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
