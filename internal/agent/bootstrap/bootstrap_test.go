package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// fakeTransport implements api.Transport for tests. Records
// every Run/Put/Get call and returns canned results.
//
// **Stage-then-install architecture (B1 fix, 2026-05-13).**
// EnsureAgent's call sequence on cache miss is:
//  1. test -x /var/cache/kensa/agent-<sha>     → cache probe
//  2. mkdir -p /var/cache/kensa                 → ensure cache dir
//  3. Put bin/kensa → /var/tmp/kensa-stage-<sha>  → user-writable stage
//  4. install -m 0755 /var/tmp/kensa-stage-<sha> /var/cache/kensa/agent-<sha> && rm -f /var/tmp/kensa-stage-<sha>
//     → sudo'd atomic install + cleanup
//  5. test -x /var/cache/kensa/agent-<sha>     → post-install verify
type fakeTransport struct {
	mu sync.Mutex

	runResults map[string]*api.CommandResult
	runErrors  map[string]error
	runHistory []string

	putErrors  map[string]error
	putHistory []putCall

	closeCalled bool
}

type putCall struct {
	localPath, remotePath string
	mode                  fs.FileMode
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		runResults: map[string]*api.CommandResult{},
		runErrors:  map[string]error{},
		putErrors:  map[string]error{},
	}
}

func (f *fakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runHistory = append(f.runHistory, cmd)
	if err, ok := f.runErrors[cmd]; ok {
		return nil, err
	}
	if r, ok := f.runResults[cmd]; ok {
		return r, nil
	}
	return &api.CommandResult{ExitCode: 0}, nil
}

func (f *fakeTransport) Put(_ context.Context, localPath, remotePath string, mode fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putHistory = append(f.putHistory, putCall{localPath, remotePath, mode})
	if err, ok := f.putErrors[remotePath]; ok {
		return err
	}
	return nil
}

func (f *fakeTransport) Get(_ context.Context, _, _ string) error { return nil }
func (f *fakeTransport) ControlChannelSensitive() bool            { return false }
func (f *fakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalled = true
	return nil
}

func writeFixture(t *testing.T, content []byte) (path, sha string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "kensa-fixture")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(content)
	return path, hex.EncodeToString(h[:])
}

// @spec agent-bootstrap
// @ac AC-01
// @ac AC-03
func TestSHA256Hex(t *testing.T) {
	t.Run("agent-bootstrap/AC-01", func(t *testing.T) {})
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-03")
	path, want := writeFixture(t, []byte("the quick brown fox"))
	got, err := sha256Hex(path)
	if err != nil {
		t.Fatalf("sha256Hex: %v", err)
	}
	if got != want {
		t.Errorf("sha mismatch: got %q, want %q", got, want)
	}
	if len(got) != 64 {
		t.Errorf("sha length: got %d, want 64", len(got))
	}
}

// TestEnsureAgent_CacheHit: probe returns exit 0 → return
// cachePath WITHOUT invoking Put or install.
//
// @spec agent-bootstrap
// @ac AC-01
// @ac AC-02
func TestEnsureAgent_CacheHit(t *testing.T) {
	t.Run("agent-bootstrap/AC-02", func(t *testing.T) {})
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-01")
	localPath, sha := writeFixture(t, []byte("kensa-binary-fixture"))

	tr := newFakeTransport()
	cachePath := systemCacheDir + "/agent-" + sha
	tr.runResults["test -x '"+cachePath+"'"] = &api.CommandResult{ExitCode: 0}

	got, err := EnsureAgent(context.Background(), tr, localPath)
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	if got != cachePath {
		t.Errorf("path: got %q, want %q", got, cachePath)
	}
	if len(tr.putHistory) != 0 {
		t.Errorf("cache hit should not Put; got %d Puts", len(tr.putHistory))
	}
	for _, cmd := range tr.runHistory {
		if strings.HasPrefix(cmd, "install -m") {
			t.Errorf("cache hit should not invoke install; got: %s", cmd)
		}
		if strings.HasPrefix(cmd, "mkdir -p") {
			t.Errorf("cache hit should not invoke mkdir; got: %s", cmd)
		}
	}
}

// TestEnsureAgent_CacheMiss_StageThenInstall locks the B1 fix
// (2026-05-13). On cache miss, EnsureAgent must
//  1. mkdir the system cache dir,
//  2. Put the binary at a USER-WRITABLE stage path
//     (/var/tmp/kensa-stage-<sha>) — NOT the cache path
//     directly (would fail under sudo because scp runs as
//     the SSH user, not root),
//  3. sudo-run install -m 0755 to move it into place,
//  4. test -x the cache path.
//
// @spec agent-bootstrap
// @ac AC-02
// @ac AC-03
func TestEnsureAgent_CacheMiss_StageThenInstall(t *testing.T) {
	t.Run("agent-bootstrap/AC-03", func(t *testing.T) {})
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-02")
	localPath, sha := writeFixture(t, []byte("kensa-binary-fixture-v2"))
	cachePath := systemCacheDir + "/agent-" + sha
	stagePath := stageDir + "/kensa-stage-" + sha

	tr := &queueFakeTransport{
		probeResults: []*api.CommandResult{{ExitCode: 1}, {ExitCode: 0}},
	}

	got, err := EnsureAgent(context.Background(), tr, localPath)
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	if got != cachePath {
		t.Errorf("returned path: got %q, want %q", got, cachePath)
	}

	if len(tr.putHistory) != 1 {
		t.Fatalf("cache miss should Put exactly once; got %d", len(tr.putHistory))
	}
	if tr.putHistory[0].remotePath != stagePath {
		t.Errorf("Put remotePath: got %q, want %q (must stage to /var/tmp, NOT the root-owned cache path)",
			tr.putHistory[0].remotePath, stagePath)
	}
	if tr.putHistory[0].localPath != localPath {
		t.Errorf("Put localPath: got %q, want %q", tr.putHistory[0].localPath, localPath)
	}
	if tr.putHistory[0].mode != 0o755 {
		t.Errorf("Put mode: got %o, want 0755", tr.putHistory[0].mode)
	}

	if !tr.mkdirCalled {
		t.Error("cache miss should mkdir the system cache dir")
	}
	if !tr.installCalled {
		t.Error("cache miss should invoke install -m 0755")
	}
	if !strings.Contains(tr.installCmd, stagePath) {
		t.Errorf("install cmd should mention stage path %q; got: %q", stagePath, tr.installCmd)
	}
	if !strings.Contains(tr.installCmd, cachePath) {
		t.Errorf("install cmd should mention cache path %q; got: %q", cachePath, tr.installCmd)
	}
	if !strings.Contains(tr.installCmd, "rm -f") {
		t.Errorf("install cmd should clean up the stage file; got: %q", tr.installCmd)
	}
}

// TestEnsureAgent_PutFailure: stage upload fails → wrapped
// error mentioning both local + stage paths.
//
// @spec agent-bootstrap
// @ac AC-04
func TestEnsureAgent_PutFailure(t *testing.T) {
	t.Run("agent-bootstrap/AC-04", func(t *testing.T) {})
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-04")
	localPath, sha := writeFixture(t, []byte("v3"))
	stagePath := stageDir + "/kensa-stage-" + sha

	tr := &queueFakeTransport{
		probeResults: []*api.CommandResult{{ExitCode: 1}},
		putErr:       errors.New("scp: disk full"),
	}

	_, err := EnsureAgent(context.Background(), tr, localPath)
	if err == nil {
		t.Fatal("expected stage upload failure error")
	}
	msg := err.Error()
	if !strings.Contains(msg, localPath) {
		t.Errorf("error should mention local path; got: %v", err)
	}
	if !strings.Contains(msg, stagePath) {
		t.Errorf("error should mention stage path; got: %v", err)
	}
	if !strings.Contains(msg, "scp: disk full") {
		t.Errorf("error should wrap underlying cause; got: %v", err)
	}
}

// TestEnsureAgent_InstallFailure: sudo-install fails →
// surface error AND best-effort stage cleanup.
//
// @spec agent-bootstrap
// @ac AC-04
func TestEnsureAgent_InstallFailure(t *testing.T) {
	t.Run("agent-bootstrap/AC-04", func(t *testing.T) {})
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-04")
	localPath, sha := writeFixture(t, []byte("v3a"))
	stagePath := stageDir + "/kensa-stage-" + sha

	tr := &queueFakeTransport{
		probeResults:  []*api.CommandResult{{ExitCode: 1}},
		installResult: &api.CommandResult{ExitCode: 1, Stderr: "install: cannot create regular file: read-only filesystem"},
	}

	_, err := EnsureAgent(context.Background(), tr, localPath)
	if err == nil {
		t.Fatal("expected install failure error")
	}
	if !strings.Contains(err.Error(), "install") {
		t.Errorf("error should mention install; got: %v", err)
	}
	cleanupFound := false
	for _, cmd := range tr.runHistory {
		if strings.HasPrefix(cmd, "rm -f ") && strings.Contains(cmd, stagePath) {
			cleanupFound = true
			break
		}
	}
	if !cleanupFound {
		t.Errorf("install failure should trigger stage cleanup; runHistory=%v", tr.runHistory)
	}
}

// TestEnsureAgent_AbsolutePath: returned path is absolute +
// under /var/cache/kensa/.
//
// @spec agent-bootstrap
// @ac AC-05
func TestEnsureAgent_AbsolutePath(t *testing.T) {
	t.Run("agent-bootstrap/AC-05", func(t *testing.T) {})
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-05")
	localPath, sha := writeFixture(t, []byte("v4"))
	cachePath := systemCacheDir + "/agent-" + sha
	tr := &queueFakeTransport{
		probeResults: []*api.CommandResult{{ExitCode: 0}},
	}

	got, err := EnsureAgent(context.Background(), tr, localPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != cachePath {
		t.Errorf("returned path: got %q, want %q", got, cachePath)
	}
	if !strings.HasPrefix(got, "/var/cache/kensa/") {
		t.Errorf("returned path should be under /var/cache/kensa/; got: %q", got)
	}
}

// TestEnsureAgent_MkdirFailure: cache-dir mkdir fails →
// wrapped error before any Put attempt.
//
// @spec agent-bootstrap
// @ac AC-04
func TestEnsureAgent_MkdirFailure(t *testing.T) {
	t.Run("agent-bootstrap/AC-04", func(t *testing.T) {})
	localPath, _ := writeFixture(t, []byte("v5"))
	tr := &queueFakeTransport{
		probeResults: []*api.CommandResult{{ExitCode: 1}},
		mkdirResult:  &api.CommandResult{ExitCode: 1, Stderr: "mkdir: permission denied"},
	}
	_, err := EnsureAgent(context.Background(), tr, localPath)
	if err == nil {
		t.Fatal("expected mkdir failure error")
	}
	if !strings.Contains(err.Error(), "mkdir") {
		t.Errorf("error should mention mkdir; got: %v", err)
	}
	if len(tr.putHistory) != 0 {
		t.Errorf("Put should not be attempted when mkdir fails; got %d Puts", len(tr.putHistory))
	}
}

// ─── queue-based fake transport ──────────────────────────

type queueFakeTransport struct {
	mu sync.Mutex

	probeResults  []*api.CommandResult
	mkdirResult   *api.CommandResult
	installResult *api.CommandResult
	putErr        error

	mkdirCalled   bool
	installCalled bool
	installCmd    string
	probeCalls    int
	putHistory    []putCall
	runHistory    []string
}

func (f *queueFakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runHistory = append(f.runHistory, cmd)
	switch {
	case strings.HasPrefix(cmd, "mkdir -p "):
		f.mkdirCalled = true
		if f.mkdirResult != nil {
			return f.mkdirResult, nil
		}
		return &api.CommandResult{ExitCode: 0}, nil
	case strings.HasPrefix(cmd, "install -m"):
		f.installCalled = true
		f.installCmd = cmd
		if f.installResult != nil {
			return f.installResult, nil
		}
		return &api.CommandResult{ExitCode: 0}, nil
	case strings.HasPrefix(cmd, "test -x "):
		if f.probeCalls >= len(f.probeResults) {
			return &api.CommandResult{ExitCode: 0}, nil
		}
		r := f.probeResults[f.probeCalls]
		f.probeCalls++
		return r, nil
	default:
		return &api.CommandResult{ExitCode: 0}, nil
	}
}

func (f *queueFakeTransport) Put(_ context.Context, localPath, remotePath string, mode fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putHistory = append(f.putHistory, putCall{localPath, remotePath, mode})
	return f.putErr
}

func (f *queueFakeTransport) Get(_ context.Context, _, _ string) error { return nil }
func (f *queueFakeTransport) ControlChannelSensitive() bool            { return false }
func (f *queueFakeTransport) Close() error                             { return nil }
