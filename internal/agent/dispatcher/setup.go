// Agent-mode lifecycle setup. L-014b deliverable per spec
// agent-cli-env-var.
//
// **What this does.** Encapsulates the bootstrap + spawn +
// open + handshake lifecycle so cmd/kensa/main.go's
// runRemediate path doesn't have to inline every step:
//
//   1. bootstrap.EnsureAgent → cachePath on target
//   2. spawn `ssh <user>@<host> <cachePath> agent --stdio`
//      as exec.Cmd; pipe stdin/stdout to/from the AgentClient
//   3. client.Open on the pipes
//   4. client.Handshake; abort with clear stderr on
//      ErrIncompatibleProtocol
//   5. return *Client + cleanup closure that, on engine
//      completion, runs client.Close, cmd.Wait, and surfaces
//      non-zero subprocess exit codes.
//
// **Testability.** The SSH command-builder is injectable
// (`SSHCommandFunc`). Tests pass a function that exec's
// the local kensa binary directly, bypassing the SSH wire
// entirely. Live-host integration ships separately when
// CI has a real SSH-able target.

package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/bootstrap"
	"github.com/Hanalyx/kensa/internal/agent/client"
)

// Options configures OpenAgent. Zero value works for the
// default production path (ssh subprocess to <host>).
type Options struct {
	// LocalBinary is the path to the kensa binary the
	// controller side is running. EnsureAgent SHA-hashes
	// this for cache-keying and pushes if absent on target.
	// If empty, defaults to os.Args[0].
	LocalBinary string

	// SSHCommandFunc builds the exec.Cmd that runs
	// `<remotePath> agent --stdio` on the target. Default
	// builds `ssh <user>@<host> <remotePath> agent --stdio`.
	// Tests inject a function that exec's the local kensa
	// binary directly, bypassing SSH.
	SSHCommandFunc func(ctx context.Context, user, host, remotePath string) *exec.Cmd

	// Stderr is the operator-visible diagnostic sink for
	// the agent-mode announce line and any bootstrap
	// errors. Defaults to os.Stderr.
	Stderr io.Writer

	// User is the SSH user for the target connection.
	// Empty means "current user" (per ssh's default).
	User string

	// Sudo controls whether the agent invocation runs under
	// `sudo -n` on the target. Pre-B1 (2026-05-13) the
	// agent always ran as the SSH user; that worked when the
	// SSH user was root but broke for the documented
	// security model of "unprivileged SSH user + sudo for
	// privileged ops" because the agent binary lives in
	// `/var/cache/kensa/` (root-owned) and the non-root SSH
	// user can't enter the cache dir to exec the binary.
	// Setting Sudo=true prefixes the invocation with
	// `sudo -n` so sudo elevates BEFORE the binary path is
	// resolved by the remote shell. Callers pass through
	// from api.HostConfig.Sudo.
	Sudo bool

	// SudoPassword, when non-empty (and Sudo true), switches the
	// agent spawn from `sudo -n` to `sudo -S -p ''` and OpenAgent
	// writes the password as the FIRST line of the agent's stdin —
	// sudo consumes that line, then the spawned agent (now root)
	// reads the wire protocol from the remaining stdin. The
	// password never enters argv. Callers pass through from
	// api.HostConfig.SudoPassword. Empty keeps the `sudo -n` path.
	// Note: the on-host local transport needs no password — the
	// agent runs as root after the sudo spawn, so its NewAuto sees
	// euid 0 and does not re-sudo. See
	// docs/roadmap/SUDO_PASSWORD_SCAN_DECISION.md.
	SudoPassword string
}

// OpenAgent runs the L-014b lifecycle setup and returns a
// ready-to-use AgentClient + a cleanup closure.
//
// Spec C-03 / C-05 / C-06.
//
// Errors are wrapped with a "dispatcher: " prefix and
// include the step that failed for operator diagnosability.
// Returns nil cleanup on error (caller doesn't need to
// defer cleanup on err != nil).
func OpenAgent(ctx context.Context, transport api.Transport, host string, opts Options) (*client.Client, func(), error) {
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.LocalBinary == "" {
		opts.LocalBinary = os.Args[0]
	}
	if opts.SSHCommandFunc == nil {
		// Capture Sudo + SudoPassword in the closure so the
		// SSHCommandFunc signature stays stable for test injectors.
		sudo := opts.Sudo
		sudoPassword := opts.SudoPassword
		opts.SSHCommandFunc = func(ctx context.Context, user, host, remotePath string) *exec.Cmd {
			return defaultSSHCommand(ctx, user, host, remotePath, sudo, sudoPassword)
		}
	}

	cachePath, err := bootstrap.EnsureAgent(ctx, transport, opts.LocalBinary)
	if err != nil {
		return nil, nil, fmt.Errorf("dispatcher: ensure agent on target: %w", err)
	}

	cmd := opts.SSHCommandFunc(ctx, opts.User, host, cachePath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("dispatcher: StdinPipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, nil, fmt.Errorf("dispatcher: StdoutPipe: %w", err)
	}
	// Stderr from the subprocess goes to our Stderr so
	// operators see agent-side diagnostics (read-frame
	// errors, dispatch failures, etc.) inline.
	cmd.Stderr = opts.Stderr

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, nil, fmt.Errorf("dispatcher: start agent subprocess: %w", err)
	}

	// For the `sudo -S` spawn, the remote sudo reads the password from
	// the first line of stdin before exec'ing the agent. Write it now,
	// before the client takes over the pipe for the wire protocol. sudo
	// consumes exactly this line; the agent inherits the rest.
	if opts.SudoPassword != "" {
		if _, err := io.WriteString(stdin, opts.SudoPassword+"\n"); err != nil {
			_ = stdin.Close()
			return nil, nil, fmt.Errorf("dispatcher: write sudo password to agent stdin: %w", err)
		}
	}

	c, err := client.Open(stdin, stdout)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, fmt.Errorf("dispatcher: client.Open: %w", err)
	}

	if err := c.Handshake(ctx); err != nil {
		_ = c.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, nil, fmt.Errorf("dispatcher: handshake: %w", err)
	}

	// Spec C-06 announce-line. One stderr line per
	// agent-mode session so operators see the path firing.
	// P-011: agent-mode is now the default (Q1.c ratified
	// 2026-05-12); KENSA_NO_AGENT=1 opts out.
	fmt.Fprintf(opts.Stderr, "kensa: agent mode (default; unset with KENSA_NO_AGENT=1): bootstrap+spawn+handshake completed for host %s\n", host)

	cleanup := func() {
		_ = c.Close()
		// Wait for the subprocess to exit. If the agent
		// exited cleanly via stdin-close (Close above sent
		// EOF), Wait returns nil. If it exited non-zero,
		// Wait returns *exec.ExitError; surface that to
		// stderr but do not panic — engine errors take
		// precedence in the caller.
		if werr := cmd.Wait(); werr != nil {
			var exitErr *exec.ExitError
			if errors.As(werr, &exitErr) {
				fmt.Fprintf(opts.Stderr, "kensa: agent subprocess exited %d\n", exitErr.ExitCode())
			} else {
				fmt.Fprintf(opts.Stderr, "kensa: agent subprocess wait: %v\n", werr)
			}
		}
	}
	return c, cleanup, nil
}

// defaultSSHCommand builds the production ssh-subprocess
// invocation. The user argument can be empty (ssh uses the
// current user). When sudo is true the remote command is
// prefixed with `sudo -n` so the agent binary at the
// root-owned cache path (/var/cache/kensa/agent-<sha>) can
// be exec'd — the non-root SSH user can't enter that dir
// to exec the binary directly, but sudo elevates before
// path resolution by the remote shell.
//
// `-n` (non-interactive) is the sudoers-NOPASSWD friendly
// form: matches the kensa-rpm sudoers fragment template
// and fails fast if a password would be required.
func defaultSSHCommand(ctx context.Context, user, host, remotePath string, sudo bool, sudoPassword string) *exec.Cmd {
	target := host
	if user != "" {
		target = user + "@" + host
	}
	// -o LogLevel=ERROR suppresses the server's pre-auth login banner
	// (e.g. a USG/DoD consent banner) so it does not leak into the
	// agent subprocess's stderr — which we forward to the operator's
	// stderr for agent-side diagnostics. The transport (direct-SSH /
	// check path) already hides the banner by capturing its
	// ControlMaster stderr into a buffer; this keeps agent-mode
	// (remediate/rollback) consistent. ERROR (not QUIET/-q) is chosen
	// deliberately: it silences the info-level banner while preserving
	// genuine ssh error diagnostics.
	base := []string{"-o", "LogLevel=ERROR", target}
	if sudo {
		if sudoPassword != "" {
			// `sudo -S -p ''` reads the password from the FIRST line
			// of stdin (OpenAgent writes it before the wire protocol),
			// then execs the agent which inherits the remaining stdin.
			// `-p ''` suppresses the prompt so it never reaches the
			// forwarded stderr; the empty arg is written as the literal
			// two-character token `''` because ssh space-joins these
			// args into one string that the REMOTE shell re-parses — a
			// bare "" would collapse and `-p` would swallow the agent
			// path. The password is NOT in argv (it rides stdin).
			return exec.CommandContext(ctx, "ssh", append(base, "sudo", "-S", "-p", "''", remotePath, "agent", "--stdio")...)
		}
		return exec.CommandContext(ctx, "ssh", append(base, "sudo", "-n", remotePath, "agent", "--stdio")...)
	}
	return exec.CommandContext(ctx, "ssh", append(base, remotePath, "agent", "--stdio")...)
}
