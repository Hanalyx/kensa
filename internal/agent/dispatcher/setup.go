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

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent/bootstrap"
	"github.com/Hanalyx/kensa-go/internal/agent/client"
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
		opts.SSHCommandFunc = defaultSSHCommand
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
	// agent-mode session so operators see the flip
	// firing.
	fmt.Fprintf(opts.Stderr, "kensa: agent mode (KENSA_USE_AGENT=1): bootstrap+spawn+handshake completed for host %s\n", host)

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
// invocation. user can be empty (ssh uses current user).
func defaultSSHCommand(ctx context.Context, user, host, remotePath string) *exec.Cmd {
	target := host
	if user != "" {
		target = user + "@" + host
	}
	return exec.CommandContext(ctx, "ssh", target, remotePath, "agent", "--stdio")
}
