package client

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// TestClient_SubprocessIntegration locks AC-07: spawn the
// real bin/kensa agent --stdio subprocess, Open a Client on
// its pipes, send ApplyRequest + Heartbeat, verify Responses,
// close cleanly.
//
// @spec agent-client
// @ac AC-07
func TestClient_SubprocessIntegration(t *testing.T) {
	repoRoot := findRepoRootForTest(t)
	binPath := filepath.Join(repoRoot, "bin", "kensa")
	if !fileExists(binPath) {
		t.Skipf("bin/kensa not built (run `make build`); skipping subprocess test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "agent", "--stdio")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	client, err := Open(stdin, stdout)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Apply against the echo agent — returns a zero
	// StepResult per L-009 HandleEcho.
	sr, err := client.Apply(ctx, "file_permissions", api.Params{"path": "/etc/test"}, nil)
	if err != nil {
		t.Errorf("Apply: %v", err)
	}
	if sr == nil {
		t.Error("Apply: nil StepResult")
	}

	// Heartbeat with a non-default token.
	if err := client.Heartbeat(ctx, 0xabad1dea); err != nil {
		t.Errorf("Heartbeat: %v", err)
	}

	// Clean shutdown.
	if err := client.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("agent subprocess exited non-zero: %v", err)
	}
}

func findRepoRootForTest(t *testing.T) string {
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

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
