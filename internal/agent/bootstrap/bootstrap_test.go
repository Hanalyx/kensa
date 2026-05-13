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

	"github.com/Hanalyx/kensa-go/api"
)

// fakeTransport implements api.Transport for tests. Records
// every Run/Put/Get call and returns canned results.
type fakeTransport struct {
	mu sync.Mutex

	// runResults is keyed by exact command string; absent
	// keys default to {ExitCode: 0, ...}.
	runResults map[string]*api.CommandResult
	runErrors  map[string]error // returned alongside the run result
	runHistory []string

	putErrors   map[string]error // keyed by remotePath
	putHistory  []putCall

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
	// Default: success.
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

// writeFixture creates a temp file with the given content
// and returns the path + its expected sha256 hex.
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

// TestSHA256Hex locks AC-03: streaming SHA-256 produces
// the expected lower-hex 64-char digest for a known input.
//
// @spec agent-bootstrap
// @ac AC-03
func TestSHA256Hex(t *testing.T) {
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

// TestEnsureAgent_CacheHit locks AC-01: when the cache probe
// returns exit 0, EnsureAgent returns the cachePath WITHOUT
// invoking Put.
//
// @spec agent-bootstrap
// @ac AC-01
func TestEnsureAgent_CacheHit(t *testing.T) {
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-01")
	localPath, sha := writeFixture(t, []byte("kensa-binary-fixture"))

	tr := newFakeTransport()
	tr.runResults[`printf '%s' "$HOME"`] = &api.CommandResult{ExitCode: 0, Stdout: "/home/operator"}
	cachePath := "/home/operator/.cache/kensa/agent-" + sha
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
}

// TestEnsureAgent_CacheMiss_PushesBinary locks AC-02: cache
// probe returns non-zero → mkdir + Put + final-test-x; returns
// cachePath.
//
// @spec agent-bootstrap
// @ac AC-02
func TestEnsureAgent_CacheMiss_PushesBinary(t *testing.T) {
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-02")
	localPath, sha := writeFixture(t, []byte("kensa-binary-fixture-v2"))

	tr := newFakeTransport()
	tr.runResults[`printf '%s' "$HOME"`] = &api.CommandResult{ExitCode: 0, Stdout: "/home/op"}
	cachePath := "/home/op/.cache/kensa/agent-" + sha
	// First probe → cache miss.
	tr.runResults["test -x '"+cachePath+"'"] = &api.CommandResult{ExitCode: 1}
	// mkdir succeeds (default).
	// Post-push verify needs to flip to exit 0 — but the
	// fake transport's runResults map can't distinguish
	// before-vs-after-Put unless we mutate it during Put.
	// Use a stateful callback approach: install a putError
	// hook that flips the test-x result.
	tr.putErrors[cachePath] = nil // success
	// We'll instrument the post-push verify by using a
	// separate result lookup — since both probes use the
	// SAME command string, we need to swap the result
	// between calls. Easiest: track call count.
	probeCmd := "test -x '" + cachePath + "'"
	probeCount := 0
	tr.mu.Lock()
	delete(tr.runResults, probeCmd) // remove the static entry
	tr.mu.Unlock()
	// Re-attach a dynamic handler via runHistory + a custom
	// pre-Run hook is too much plumbing. Simpler: switch
	// to a slice-of-results, popping each call.

	// Reinitialize with a queue-based fake.
	tr2 := &queueFakeTransport{
		homeResult:    &api.CommandResult{ExitCode: 0, Stdout: "/home/op"},
		probeResults:  []*api.CommandResult{{ExitCode: 1}, {ExitCode: 0}}, // miss then hit
		cachePath:     cachePath,
		cacheDir:      "/home/op/.cache/kensa",
	}
	_ = probeCount

	got, err := EnsureAgent(context.Background(), tr2, localPath)
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	if got != cachePath {
		t.Errorf("path: got %q, want %q", got, cachePath)
	}
	if len(tr2.putHistory) != 1 {
		t.Fatalf("cache miss should Put exactly once; got %d", len(tr2.putHistory))
	}
	if tr2.putHistory[0].localPath != localPath {
		t.Errorf("Put localPath: got %q, want %q", tr2.putHistory[0].localPath, localPath)
	}
	if tr2.putHistory[0].remotePath != cachePath {
		t.Errorf("Put remotePath: got %q, want %q", tr2.putHistory[0].remotePath, cachePath)
	}
	if tr2.putHistory[0].mode != 0o755 {
		t.Errorf("Put mode: got %o, want 0755", tr2.putHistory[0].mode)
	}
	if !tr2.mkdirCalled {
		t.Error("cache miss should mkdir first")
	}
}

// TestEnsureAgent_PushFailure locks AC-04: Put error is
// wrapped with both paths in the error message.
//
// @spec agent-bootstrap
// @ac AC-04
func TestEnsureAgent_PushFailure(t *testing.T) {
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-04")
	localPath, sha := writeFixture(t, []byte("v3"))

	cachePath := "/home/op/.cache/kensa/agent-" + sha
	tr := &queueFakeTransport{
		homeResult:   &api.CommandResult{ExitCode: 0, Stdout: "/home/op"},
		probeResults: []*api.CommandResult{{ExitCode: 1}}, // miss; no second probe since Put fails
		cachePath:    cachePath,
		cacheDir:     "/home/op/.cache/kensa",
		putErr:       errors.New("scp: disk full"),
	}

	_, err := EnsureAgent(context.Background(), tr, localPath)
	if err == nil {
		t.Fatal("expected push failure error")
	}
	msg := err.Error()
	if !strings.Contains(msg, localPath) {
		t.Errorf("error should mention local path; got: %v", err)
	}
	if !strings.Contains(msg, cachePath) {
		t.Errorf("error should mention remote path; got: %v", err)
	}
	if !strings.Contains(msg, "scp: disk full") {
		t.Errorf("error should wrap underlying cause; got: %v", err)
	}
}

// TestEnsureAgent_AbsolutePath locks AC-05: the returned
// path always starts with `/`.
//
// @spec agent-bootstrap
// @ac AC-05
func TestEnsureAgent_AbsolutePath(t *testing.T) {
	t.Log("// @spec agent-bootstrap")
	t.Log("// @ac AC-05")
	localPath, sha := writeFixture(t, []byte("v4"))
	cachePath := "/home/abs/.cache/kensa/agent-" + sha
	tr := &queueFakeTransport{
		homeResult:   &api.CommandResult{ExitCode: 0, Stdout: "/home/abs"},
		probeResults: []*api.CommandResult{{ExitCode: 0}}, // hit
		cachePath:    cachePath,
		cacheDir:     "/home/abs/.cache/kensa",
	}

	got, err := EnsureAgent(context.Background(), tr, localPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "/") {
		t.Errorf("returned path is not absolute: %q", got)
	}
}

// TestEnsureAgent_HomeResolveFailure: $HOME resolution
// failure surfaces a wrapped error mentioning $HOME.
func TestEnsureAgent_HomeResolveFailure(t *testing.T) {
	localPath, _ := writeFixture(t, []byte("v5"))
	tr := &queueFakeTransport{
		homeResult: &api.CommandResult{ExitCode: 1, Stderr: "permission denied"},
	}
	_, err := EnsureAgent(context.Background(), tr, localPath)
	if err == nil {
		t.Fatal("expected $HOME resolution error")
	}
	if !strings.Contains(err.Error(), "HOME") {
		t.Errorf("error should mention HOME; got: %v", err)
	}
}

// TestEnsureAgent_NonAbsoluteHome rejects a $HOME value that
// isn't absolute (defense against a misconfigured target shell).
func TestEnsureAgent_NonAbsoluteHome(t *testing.T) {
	localPath, _ := writeFixture(t, []byte("v6"))
	tr := &queueFakeTransport{
		homeResult: &api.CommandResult{ExitCode: 0, Stdout: "relative/home"},
	}
	_, err := EnsureAgent(context.Background(), tr, localPath)
	if err == nil {
		t.Fatal("expected error on non-absolute $HOME")
	}
}

// ─── queue-based fake transport for sequenced tests ───────

// queueFakeTransport is the fake when test expectations
// require ORDERED Run responses (e.g., probe-miss then
// probe-hit after Put). The fields document the expected
// call sequence; each call advances the queue.
type queueFakeTransport struct {
	mu sync.Mutex

	homeResult   *api.CommandResult // returned for `printf '%s' "$HOME"`
	probeResults []*api.CommandResult // returned for each `test -x ...` call in order
	putErr       error
	cachePath    string
	cacheDir     string

	mkdirCalled bool
	probeCalls  int
	putHistory  []putCall
}

func (f *queueFakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case cmd == `printf '%s' "$HOME"`:
		if f.homeResult == nil {
			return &api.CommandResult{ExitCode: 0, Stdout: "/home/default"}, nil
		}
		return f.homeResult, nil
	case strings.HasPrefix(cmd, "mkdir -p "):
		f.mkdirCalled = true
		return &api.CommandResult{ExitCode: 0}, nil
	case strings.HasPrefix(cmd, "test -x "):
		if f.probeCalls >= len(f.probeResults) {
			return &api.CommandResult{ExitCode: 0}, nil // default success
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
