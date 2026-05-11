package api

import (
	"context"
	"io/fs"
	"time"
)

// NOTE: The AtomicTransport capability interface previously
// lived here. It has been moved to
// `internal/agent/fsatomic` as `fsatomic.Transport` —
// atomicity is an agent-side capability and OpenWatch (the
// primary external `api.Transport` implementer) is not
// expected to provide it. See the package doc at
// `internal/agent/fsatomic/transport.go` for the rationale.

// Transport is the abstraction over how the engine reaches a target host.
//
// The primary implementation (internal/transport/ssh) wraps the system
// OpenSSH client with ControlMaster multiplexing. Reasons for using the
// system binary rather than a Go SSH library are enumerated in
// docs/KENSA_GO_DAY1_PLAN.md §1.3 and §6.1: FIPS via RHEL's certified
// OpenSSH, ~/.ssh/config support, system crypto-policy compliance, and
// a smaller supply chain.
//
// A fallback implementation (internal/transport/crypto) uses
// golang.org/x/crypto/ssh for environments where the system ssh binary
// is unavailable. It is not the default and is not the supported
// configuration for federal deployment.
type Transport interface {
	// Run executes a command on the target host and returns the
	// outcome. When the transport is configured with sudo enabled,
	// the command is wrapped in `sudo -n sh -c`.
	Run(ctx context.Context, cmd string) (*CommandResult, error)

	// Put uploads a local file to remotePath on the target host with
	// the specified mode.
	Put(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error

	// Get downloads a file at remotePath on the target host to
	// localPath.
	Get(ctx context.Context, remotePath, localPath string) error

	// ControlChannelSensitive reports whether this transport considers
	// itself at risk of being disrupted by the in-flight change. The
	// deadman-timer subsystem sets this to true when a transaction
	// includes mechanisms that affect SSH, networking, PAM, or
	// firewall state.
	ControlChannelSensitive() bool

	// Close terminates the transport. For the ssh transport this
	// stops the ControlMaster and removes the control socket.
	Close() error
}

// CommandResult is the structured outcome of [Transport.Run].
type CommandResult struct {
	// ExitCode is the command's exit status. Zero means success.
	ExitCode int
	// Stdout is the captured standard output, with the trailing
	// newline removed.
	Stdout string
	// Stderr is the captured standard error, with the trailing
	// newline removed.
	Stderr string
	// Duration is the wall-clock time the command took on the host.
	Duration time.Duration
}

// OK reports whether the command exited successfully (exit code zero).
func (r *CommandResult) OK() bool { return r.ExitCode == 0 }
