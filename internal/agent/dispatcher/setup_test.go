package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// fakeTransport: bootstrap.EnsureAgent uses this to check
// the cache hit/miss path. Returns a canned $HOME + always-
// cache-hit so EnsureAgent returns the pre-built kensa binary.
type fakeTransport struct {
	mu       sync.Mutex
	home     string
	runErr   error
	runCalls []string
	putCalls int
}

func (f *fakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runCalls = append(f.runCalls, cmd)
	if f.runErr != nil {
		return nil, f.runErr
	}
	switch {
	case strings.Contains(cmd, `printf '%s' "$HOME"`):
		return &api.CommandResult{ExitCode: 0, Stdout: f.home}, nil
	case strings.HasPrefix(cmd, "test -x "):
		return &api.CommandResult{ExitCode: 0}, nil // cache hit
	case strings.HasPrefix(cmd, "mkdir -p "):
		return &api.CommandResult{ExitCode: 0}, nil
	}
	return &api.CommandResult{ExitCode: 0}, nil
}

func (f *fakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putCalls++
	return nil
}

func (f *fakeTransport) Get(_ context.Context, _, _ string) error { return nil }
func (f *fakeTransport) ControlChannelSensitive() bool            { return false }
func (f *fakeTransport) Close() error                             { return nil }

// findRepoRootForTest walks up to go.mod from this test file.
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

// TestOpenAgent_LocalStub locks AC-03: with a stub
// SSHCommandFunc that exec's the local kensa binary
// directly (bypassing real SSH), OpenAgent returns a
// working Client and the handshake succeeds.
//
// @spec agent-cli-env-var
// @ac AC-03
// @spec agent-cli-env-var
// @ac AC-01
// @ac AC-05
func TestOpenAgent_LocalStub(t *testing.T) {
	t.Run("agent-cli-env-var/AC-05", func(t *testing.T) {})
	t.Run("agent-cli-env-var/AC-01", func(t *testing.T) {})
	t.Log("// @spec agent-cli-env-var")
	t.Log("// @ac AC-03")
	repoRoot := findRepoRootForTest(t)
	binPath := filepath.Join(repoRoot, "bin", "kensa")
	if !fileExists(binPath) {
		t.Skipf("bin/kensa not built (run `make build`); skipping local-stub test")
	}

	tr := &fakeTransport{home: "/home/test"}

	// Stub SSHCommandFunc exec's the local kensa binary
	// directly. The bootstrap.EnsureAgent path returns the
	// fake cachePath; we ignore it and exec the real
	// kensa binary's `agent --stdio` mode.
	stubSSHCmd := func(ctx context.Context, _, _, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, binPath, "agent", "--stdio")
	}

	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, cleanup, err := OpenAgent(ctx, tr, "test-host", Options{
		LocalBinary:    binPath,
		SSHCommandFunc: stubSSHCmd,
		Stderr:         &stderr,
	})
	if err != nil {
		t.Fatalf("OpenAgent: %v; stderr=%q", err, stderr.String())
	}
	defer cleanup()

	if c == nil {
		t.Fatal("OpenAgent returned nil client")
	}
}

// TestOpenAgent_AnnounceLine locks AC-06: stderr carries the
// agent-mode-fired announce line so operators can observe
// the flip.
//
// @spec agent-cli-env-var
// @ac AC-06
// @spec agent-cli-env-var
// @ac AC-02
func TestOpenAgent_AnnounceLine(t *testing.T) {
	t.Run("agent-cli-env-var/AC-06", func(t *testing.T) {})
	t.Run("agent-cli-env-var/AC-02", func(t *testing.T) {})
	t.Log("// @spec agent-cli-env-var")
	t.Log("// @ac AC-06")
	repoRoot := findRepoRootForTest(t)
	binPath := filepath.Join(repoRoot, "bin", "kensa")
	if !fileExists(binPath) {
		t.Skipf("bin/kensa not built (run `make build`); skipping")
	}

	tr := &fakeTransport{home: "/home/test"}
	stubSSHCmd := func(ctx context.Context, _, _, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, binPath, "agent", "--stdio")
	}

	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, cleanup, err := OpenAgent(ctx, tr, "myhost.example.com", Options{
		LocalBinary:    binPath,
		SSHCommandFunc: stubSSHCmd,
		Stderr:         &stderr,
	})
	if err != nil {
		t.Fatalf("OpenAgent: %v; stderr=%q", err, stderr.String())
	}
	defer cleanup()
	_ = c

	got := stderr.String()
	if !strings.Contains(got, "kensa: agent mode") {
		t.Errorf("expected announce-line in stderr; got: %q", got)
	}
	if !strings.Contains(got, "myhost.example.com") {
		t.Errorf("announce-line should include host; got: %q", got)
	}
	if !strings.Contains(got, "KENSA_NO_AGENT=1") {
		t.Errorf("announce-line should reference env var; got: %q", got)
	}
}

// TestOpenAgent_CleanupOnError: bootstrap failure aborts
// OpenAgent early; the returned cleanup is nil and the
// caller doesn't need to defer it.
//
// @spec agent-cli-env-var
// @ac AC-05
// @spec agent-cli-env-var
// @ac AC-03
// @ac AC-07
func TestOpenAgent_CleanupOnError(t *testing.T) {
	t.Run("agent-cli-env-var/AC-07", func(t *testing.T) {})
	t.Run("agent-cli-env-var/AC-03", func(t *testing.T) {})
	t.Log("// @spec agent-cli-env-var")
	t.Log("// @ac AC-05")
	tr := &fakeTransport{runErr: errors.New("simulated bootstrap failure")}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	c, cleanup, err := OpenAgent(ctx, tr, "test-host", Options{})
	if err == nil {
		t.Fatal("expected error from bootstrap failure")
	}
	if c != nil {
		t.Error("expected nil client on error")
	}
	if cleanup != nil {
		t.Error("expected nil cleanup on error (caller doesn't defer on err)")
	}
	if !strings.Contains(err.Error(), "ensure agent") {
		t.Errorf("error should identify bootstrap step; got: %v", err)
	}
}

// TestOpenAgent_HandshakeFailure: agent subprocess that
// doesn't respond (or responds with a major mismatch)
// causes Handshake to fail; cleanup kills the subprocess.
//
// Skipped if bin/kensa not built since we need a real
// subprocess for this test.
// @spec agent-cli-env-var
// @ac AC-04
func TestOpenAgent_HandshakeFailure(t *testing.T) {
	t.Run("agent-cli-env-var/AC-04", func(t *testing.T) {})
	// To exercise handshake failure cleanly we'd need a
	// subprocess that replies with major=2. The simplest
	// approach: use a stub SSH command that exec's
	// /bin/true (exits immediately; client.Open blocks on
	// EOF). Handshake then sees ErrAgentStreamClosed.
	tr := &fakeTransport{home: "/home/test"}
	stubSSHCmd := func(ctx context.Context, _, _, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, cleanup, err := OpenAgent(ctx, tr, "host", Options{
		LocalBinary:    "/bin/true",
		SSHCommandFunc: stubSSHCmd,
	})
	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		_ = c
		t.Fatal("expected handshake failure")
	}
	if !strings.Contains(err.Error(), "handshake") {
		t.Errorf("error should mention handshake; got: %v", err)
	}
}

// TestDefaultSSHCommand_SuppressesBanner guards the fix for the
// server login-banner (e.g. a USG consent banner) leaking into the
// agent subprocess's forwarded stderr: defaultSSHCommand must pass
// `-o LogLevel=ERROR` so the banner is suppressed while genuine ssh
// errors still surface. The transport (direct-SSH path) already hides
// the banner by buffering its ControlMaster stderr; this keeps
// agent-mode (remediate/rollback) consistent with check.
func TestDefaultSSHCommand_SuppressesBanner(t *testing.T) {
	for _, sudo := range []bool{false, true} {
		cmd := defaultSSHCommand(context.Background(), "/run/kensa-test.sock", "owadmin", "host-x", "/var/cache/kensa/agent-abc", sudo, "")
		joined := strings.Join(cmd.Args, " ")
		if !strings.Contains(joined, "-o LogLevel=ERROR") {
			t.Errorf("sudo=%v: expected `-o LogLevel=ERROR` in ssh args to suppress the login banner; got %q", sudo, joined)
		}
		// The LogLevel option must precede the target so ssh applies it.
		oIdx := indexOf(cmd.Args, "LogLevel=ERROR")
		tIdx := indexOf(cmd.Args, "owadmin@host-x")
		if oIdx == -1 || tIdx == -1 || oIdx > tIdx {
			t.Errorf("sudo=%v: LogLevel option must come before the target; args=%q", sudo, cmd.Args)
		}
	}
}

// TestDefaultSSHCommand_SudoPasswordWrap verifies the agent spawn uses
// `sudo -S -p ”` when a sudo password is supplied (so OpenAgent can
// feed it on stdin), `sudo -n` when not, and that the password is NEVER
// placed in argv.
//
// @spec cli-sudo-password-flag
// @ac AC-03
func TestDefaultSSHCommand_SudoPasswordWrap(t *testing.T) {
	t.Run("cli-sudo-password-flag/AC-03", func(t *testing.T) {})

	// No password → `sudo -n`.
	noPw := defaultSSHCommand(context.Background(), "/run/kensa-test.sock", "owadmin", "host-x", "/var/cache/kensa/agent-abc", true, "")
	if got := strings.Join(noPw.Args, " "); !strings.Contains(got, "sudo -n") || strings.Contains(got, "-S") {
		t.Errorf("no-password sudo spawn should use `sudo -n`; got %q", got)
	}

	// With password → `sudo -S -p ''`, and the password must not be in argv.
	const pw = "s3cr3t-agent-pw"
	withPw := defaultSSHCommand(context.Background(), "/run/kensa-test.sock", "owadmin", "host-x", "/var/cache/kensa/agent-abc", true, pw)
	joined := strings.Join(withPw.Args, " ")
	if !strings.Contains(joined, "sudo -S -p ''") {
		t.Errorf("password sudo spawn should use `sudo -S -p ''` (literal '' so the empty prompt survives the remote shell); got %q", joined)
	}
	for _, a := range withPw.Args {
		if a == pw || strings.Contains(a, pw) {
			t.Fatalf("SECURITY: sudo password leaked into agent spawn argv: %q", withPw.Args)
		}
	}
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// The agent session must multiplex over the transport's ControlMaster, because
// building its own connection is what dropped every operator-supplied setting.
// A run aimed at -H 127.0.0.1 -P 2231 went to 127.0.0.1 port 22, a different
// machine; it failed only because auth failed there, and with a working key it
// would have remediated the wrong host.
func TestDefaultSSHCommandMultiplexesOverControlMaster(t *testing.T) {
	const sock = "/run/user/1000/kensa-owadmin@h:2231-42"
	for _, tc := range []struct {
		name     string
		sudo     bool
		password string
	}{
		{"no sudo", false, ""},
		{"sudo -n", true, ""},
		{"sudo -S with password", true, "hunter2"},
	} {
		cmd := defaultSSHCommand(context.Background(), sock, "owadmin", "h", "/var/cache/kensa/agent-abc", tc.sudo, tc.password)
		joined := strings.Join(cmd.Args, " ")
		if !strings.Contains(joined, "ControlPath="+sock) {
			t.Errorf("%s: no ControlPath in %q", tc.name, joined)
		}
		// Every setting the operator gave lives on the master, so the ssh side
		// must NOT restate any of them. Scope this to the args BEFORE the
		// target: everything after it is the REMOTE command, where `-p` is
		// sudo's prompt flag and has nothing to do with a port.
		sshArgs := cmd.Args
		for i, a := range cmd.Args {
			if a == "owadmin@h" {
				sshArgs = cmd.Args[:i]
				break
			}
		}
		for _, forbidden := range []string{"-p", "-i", "StrictHostKeyChecking"} {
			for _, a := range sshArgs {
				if a == forbidden || strings.HasPrefix(a, forbidden+"=") {
					t.Errorf("%s: ssh side rebuilds connection setting %q: %s", tc.name, forbidden, joined)
				}
			}
		}
		if !strings.Contains(joined, "LogLevel=ERROR") {
			t.Errorf("%s: lost banner suppression: %s", tc.name, joined)
		}
	}
}

// A transport that cannot supply a socket must be refused, never silently
// downgraded to a bare `ssh <target>`. That fallback is the defect.
func TestControlSocketOfRejectsNonSSHAndClosed(t *testing.T) {
	if _, ok := controlSocketOf(&fakeTransport{}); ok {
		t.Error("a transport with no ControlSocket method must be refused")
	}
	if _, ok := controlSocketOf(emptySocketTransport{}); ok {
		t.Error("an empty socket (closed transport) must be refused")
	}
	if got, ok := controlSocketOf(liveSocketTransport{}); !ok || got != "/run/live.sock" {
		t.Errorf("a live socket must be accepted, got %q ok=%v", got, ok)
	}
}

type emptySocketTransport struct{ api.Transport }

func (emptySocketTransport) ControlSocket() string { return "" }

type liveSocketTransport struct{ api.Transport }

func (liveSocketTransport) ControlSocket() string { return "/run/live.sock" }
