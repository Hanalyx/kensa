// Package ssh implements [api.Transport] over the system OpenSSH
// client with persistent ControlMaster multiplexing. Choosing the
// system binary instead of golang.org/x/crypto/ssh is a deliberate
// architectural decision per docs/KENSA_GO_DAY1_PLAN.md §1.3 and §6.1:
//
//   - FIPS compliance through RHEL's certified OpenSSH binary instead
//     of an internal Go crypto stack.
//   - The operator's ~/.ssh/config, ProxyJump, ProxyCommand,
//     PKCS#11 / FIDO2 keys, ssh-agent, and Kerberos / GSSAPI all
//     work without reimplementation.
//   - The system crypto policy (update-crypto-policies on RHEL 8+)
//     governs the transport automatically.
//   - Smaller supply chain: no Go-side crypto module to audit.
//
// Construct a transport with [Connect]; close it with
// [Transport.Close] when done. Concurrent calls against the same
// transport are safe; the engine's per-host serialization (engine-
// transaction spec C-05) is the source of higher-level ordering.
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// Config configures [Connect].
type Config struct {
	// Host is the target hostname or IP.
	Host string
	// User is the SSH login user. Empty defers to the system ssh
	// client's defaults (~/.ssh/config plus current $USER).
	User string
	// Port defaults to 22 when zero.
	Port int
	// Sudo wraps every Run command in `sudo -n sh -c`.
	Sudo bool
	// KeyPath is an explicit identity file. Empty defers to ssh-agent
	// and ~/.ssh/config.
	KeyPath string
	// Password is the SSH password for password-auth hosts. Wired
	// in C-026. When non-empty, the ControlMaster connection is
	// established via `sshpass -e ssh ...` with the password
	// passed in via the SSHPASS environment variable (NOT argv,
	// to avoid /proc-visible exposure). Empty defers to key-based
	// auth (KeyPath / ssh-agent / ~/.ssh/config).
	//
	// Operators must have `sshpass` installed on the host running
	// kensa for this to work; if absent, Connect returns a clear
	// error instructing the operator how to install it.
	Password string
	// ConnectTimeout is the maximum wall time to establish the
	// ControlMaster connection. Zero means 30 seconds.
	ConnectTimeout time.Duration
	// SocketDir is the directory where the ControlMaster socket
	// lives. Empty means $TMPDIR (typically /tmp).
	SocketDir string
}

// Transport is the active SSH session backed by a ControlMaster
// process. Each transport owns one persistent connection; subsequent
// [Transport.Run] calls multiplex over it.
type Transport struct {
	cfg        Config
	socketPath string

	mu     sync.Mutex
	closed bool

	ccSensitive bool
}

// Connect establishes the ControlMaster connection to cfg.Host. Returns
// a [Transport] ready for [Transport.Run] / [Transport.Put] /
// [Transport.Get] calls.
//
// The persistent connection holds until [Transport.Close]; subsequent
// commands reuse it through the control socket with sub-millisecond
// connection overhead.
func Connect(ctx context.Context, cfg Config) (*Transport, error) {
	if cfg.Host == "" {
		return nil, errors.New("ssh: Config.Host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 30 * time.Second
	}
	if cfg.SocketDir == "" {
		cfg.SocketDir = os.TempDir()
	}

	socketPath := computeSocketPath(cfg)

	// Establish the master connection in background mode with -fN so
	// no remote command runs; the connection persists for ControlPersist
	// after the foreground client exits.
	args := masterArgs(cfg, socketPath)
	bin := "ssh"
	if cfg.Password != "" {
		// Wrap in sshpass for password-auth hosts. -e reads the
		// password from the SSHPASS environment variable; passing
		// it via -p would expose it in /proc/.../cmdline.
		if _, err := exec.LookPath("sshpass"); err != nil {
			return nil, fmt.Errorf("ssh: --password requires sshpass on PATH (install via your package manager); not found: %w", err)
		}
		bin = "sshpass"
		args = append([]string{"-e", "ssh"}, args...)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if cfg.Password != "" {
		cmd.Env = append(os.Environ(), "SSHPASS="+cfg.Password)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrText := stderr.String()
		// Defense-in-depth: scrub the password from any stderr we
		// echo back to the operator. sshpass v1.06+ doesn't echo
		// SSHPASS itself, but verbose ssh debug output or future
		// sshpass behavior could surface fragments.
		if cfg.Password != "" {
			stderrText = strings.ReplaceAll(stderrText, cfg.Password, "***")
		}
		return nil, fmt.Errorf("ssh: connect failed: %w (stderr: %s)", err, stderrText)
	}
	return &Transport{cfg: cfg, socketPath: socketPath}, nil
}

// computeSocketPath generates a deterministic socket path for the
// given config. The pid is included so concurrent transports against
// the same host from different processes do not collide.
func computeSocketPath(cfg Config) string {
	user := cfg.User
	if user == "" {
		user = os.Getenv("USER")
	}
	name := fmt.Sprintf("kensa-%s@%s:%d-%d", user, cfg.Host, cfg.Port, os.Getpid())
	return filepath.Join(cfg.SocketDir, name)
}

// masterArgs assembles the `ssh -fN` argument list for establishing
// the ControlMaster connection.
func masterArgs(cfg Config, socketPath string) []string {
	args := []string{
		"-fN",
		"-o", "ControlMaster=yes",
		"-o", "ControlPath=" + socketPath,
		"-o", "ControlPersist=600",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=" + strconv.Itoa(int(cfg.ConnectTimeout.Seconds())),
		"-p", strconv.Itoa(cfg.Port),
	}
	if cfg.KeyPath != "" {
		args = append(args, "-i", cfg.KeyPath)
		args = append(args, "-o", "IdentitiesOnly=yes")
	}
	target := cfg.Host
	if cfg.User != "" {
		target = cfg.User + "@" + cfg.Host
	}
	args = append(args, target)
	return args
}

// reuseArgs assembles the per-command argument list that reuses the
// existing ControlMaster socket.
func (t *Transport) reuseArgs() []string {
	args := []string{
		"-o", "ControlPath=" + t.socketPath,
		"-p", strconv.Itoa(t.cfg.Port),
	}
	target := t.cfg.Host
	if t.cfg.User != "" {
		target = t.cfg.User + "@" + t.cfg.Host
	}
	args = append(args, target)
	return args
}

// Run executes cmd on the target host and returns the result.
//
// When the transport is configured with sudo, the command is wrapped
// in `sudo -n sh -c '...'`. The -n flag means non-interactive: a
// password prompt fails immediately rather than blocking.
func (t *Transport) Run(ctx context.Context, command string) (*api.CommandResult, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("ssh: transport is closed")
	}
	t.mu.Unlock()

	if t.cfg.Sudo {
		command = "sudo -n sh -c " + shellQuote(command)
	}

	args := append(t.reuseArgs(), command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			// Transport-level error (cannot reach host, socket gone).
			return nil, fmt.Errorf("ssh: run %q: %w (stderr: %s)", command, err, stderr.String())
		}
	}

	return &api.CommandResult{
		ExitCode: exitCode,
		Stdout:   trimNewline(stdout.String()),
		Stderr:   trimNewline(stderr.String()),
		Duration: duration,
	}, nil
}

// Put uploads a local file to remotePath on the target host. The mode
// is applied via chmod after upload.
//
// Implementation uses scp(1) over the existing ControlMaster socket so
// the upload reuses the multiplexed connection.
func (t *Transport) Put(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("ssh: transport is closed")
	}
	t.mu.Unlock()

	target := t.cfg.Host
	if t.cfg.User != "" {
		target = t.cfg.User + "@" + t.cfg.Host
	}
	args := []string{
		"-o", "ControlPath=" + t.socketPath,
		"-P", strconv.Itoa(t.cfg.Port),
		localPath,
		target + ":" + remotePath,
	}
	cmd := exec.CommandContext(ctx, "scp", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh: scp upload %s -> %s: %w (stderr: %s)", localPath, remotePath, err, stderr.String())
	}

	// Apply mode via a chmod follow-up.
	chmodCmd := fmt.Sprintf("chmod %o %s", mode.Perm(), shellQuote(remotePath))
	if _, err := t.Run(ctx, chmodCmd); err != nil {
		return fmt.Errorf("ssh: chmod after upload: %w", err)
	}
	return nil
}

// Get downloads remotePath to localPath via scp over the existing
// ControlMaster socket.
func (t *Transport) Get(ctx context.Context, remotePath, localPath string) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("ssh: transport is closed")
	}
	t.mu.Unlock()

	target := t.cfg.Host
	if t.cfg.User != "" {
		target = t.cfg.User + "@" + t.cfg.Host
	}
	args := []string{
		"-o", "ControlPath=" + t.socketPath,
		"-P", strconv.Itoa(t.cfg.Port),
		target + ":" + remotePath,
		localPath,
	}
	cmd := exec.CommandContext(ctx, "scp", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh: scp download %s -> %s: %w (stderr: %s)", remotePath, localPath, err, stderr.String())
	}
	return nil
}

// ControlChannelSensitive reports whether the engine's deadman-timer
// subsystem has flagged the in-flight transaction as
// control-channel-affecting. Set via [Transport.SetControlChannelSensitive]
// before the relevant transaction begins.
func (t *Transport) ControlChannelSensitive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ccSensitive
}

// SetControlChannelSensitive flips the flag. The engine calls this
// when pre-flight detects a mechanism in the transaction that could
// disrupt SSH, networking, PAM, or firewall state.
func (t *Transport) SetControlChannelSensitive(v bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ccSensitive = v
}

// Close terminates the ControlMaster connection and removes the
// control socket. Safe to call multiple times.
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	target := t.cfg.Host
	if t.cfg.User != "" {
		target = t.cfg.User + "@" + t.cfg.Host
	}
	args := []string{
		"-O", "exit",
		"-o", "ControlPath=" + t.socketPath,
		target,
	}
	// Best-effort: if the ControlMaster already exited (timed out),
	// the exit command returns non-zero; we still try to clean up the
	// socket file.
	_ = exec.Command("ssh", args...).Run()
	_ = os.Remove(t.socketPath)
	return nil
}

// trimNewline strips a single trailing \n from s. Matches the
// convention from [api.CommandResult] field comments.
func trimNewline(s string) string {
	if n := len(s); n > 0 && s[n-1] == '\n' {
		return s[:n-1]
	}
	return s
}

// shellQuote wraps s in single quotes for safe inclusion in a
// `sudo -n sh -c` argument or chmod path. Embedded single quotes are
// escaped via the standard '\” idiom.
func shellQuote(s string) string {
	return "'" + replaceAll(s, "'", `'\''`) + "'"
}

// replaceAll is a tiny helper to avoid pulling strings just for
// strings.ReplaceAll in this otherwise stdlib-heavy file.
func replaceAll(s, old, new string) string {
	out := make([]byte, 0, len(s))
	for {
		i := indexOf(s, old)
		if i < 0 {
			out = append(out, s...)
			return string(out)
		}
		out = append(out, s[:i]...)
		out = append(out, new...)
		s = s[i+len(old):]
	}
}

// indexOf returns the position of substr in s, or -1.
func indexOf(s, substr string) int {
	if substr == "" {
		return 0
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Compile-time assertion: *Transport satisfies [api.Transport].
var _ api.Transport = (*Transport)(nil)
