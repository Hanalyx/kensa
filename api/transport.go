package api

import (
	"context"
	"io/fs"
	"time"
)

// Transport is the abstraction over "how do I reach the target host."
//
// The primary implementation (internal/transport/ssh) uses the system
// OpenSSH client with ControlMaster multiplexing, for the reasons
// enumerated in KENSA_GO_DAY1_PLAN.md §1.3 and §6.1: FIPS via the RHEL
// OpenSSH binary, ~/.ssh/config support, system crypto policy
// compliance, no Go-side crypto dependency.
//
// A fallback implementation (internal/transport/crypto) uses
// golang.org/x/crypto/ssh for environments where the system ssh binary
// is unavailable. It is not the default.
type Transport interface {
	// Run executes a command on the target host and returns the result.
	// The command is wrapped with sudo when the transport is configured
	// with sudo=true.
	Run(ctx context.Context, cmd string) (*CommandResult, error)

	// Put uploads a file to the target host with the specified mode.
	Put(ctx context.Context, localPath, remotePath string, mode fs.FileMode) error

	// Get downloads a file from the target host to a local path.
	Get(ctx context.Context, remotePath, localPath string) error

	// ControlChannelSensitive reports whether this transport considers
	// itself at risk of being disrupted by the current in-flight change.
	// Set by the deadman-timer subsystem when it detects a
	// control-channel-affecting mechanism in the transaction (sshd,
	// networking, PAM, firewall).
	ControlChannelSensitive() bool

	// Close tears down the transport. For the ssh transport this
	// terminates the ControlMaster and removes the control socket.
	Close() error
}

// CommandResult is the structured return from Transport.Run.
type CommandResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
}

// OK reports whether the command exited with code 0.
func (r *CommandResult) OK() bool { return r.ExitCode == 0 }
