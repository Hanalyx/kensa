// UsageError signals that a subcommand failed because of operator
// input — a missing required flag, a malformed argument, an unknown
// flag — rather than a runtime failure (network, store, engine).
//
// runCLI in main.go discriminates the two using errors.As: anything
// that wraps a UsageError exits 2 (per GNU/POSIX convention for "the
// invocation was wrong"), and any other error exits 1 (per the
// convention for "something went wrong while doing what you asked").
//
// pflag's --help path returns pflag.ErrHelp, which is checked
// separately and exits 0. Subcommands that wrap a flag-parse error
// or detect a missing required flag should return a UsageError so
// the dispatcher routes it correctly.
//
// Adding a new usage-error case: wrap the message with NewUsageError
// or construct &UsageError{...} directly. Don't mix usage and runtime
// signals in a single error — if a single subcommand path can fail
// either way, return the right type for the actual cause.
//
// Deliverable C-008 in docs/roadmap/DELIVERABLES.md.
package main

import "errors"

// UsageError represents a usage error: bad flag, missing required
// argument, malformed value. Process exit code 2 per GNU/POSIX
// convention.
//
// Carries an optional Cause for error wrapping (so errors.Is/As
// chains across pflag.ErrHelp and similar sentinels continue to
// work).
type UsageError struct {
	// Msg is the operator-facing message printed to stderr.
	Msg string
	// Cause is the underlying error this UsageError wraps, if any.
	// Useful for preserving pflag's structured parse errors.
	Cause error
}

// Error returns Msg, optionally followed by ": " + Cause.Error().
func (e *UsageError) Error() string {
	if e.Cause == nil {
		return e.Msg
	}
	if e.Msg == "" {
		return e.Cause.Error()
	}
	return e.Msg + ": " + e.Cause.Error()
}

// Unwrap returns the wrapped cause for errors.Is / errors.As.
func (e *UsageError) Unwrap() error {
	return e.Cause
}

// NewUsageError returns a UsageError with the given message and no
// cause. Convenience for the common "missing required flag" path.
func NewUsageError(msg string) error {
	return &UsageError{Msg: msg}
}

// WrapUsageError returns a UsageError wrapping cause with a context
// message. If cause is already a UsageError, the existing one is
// returned unchanged (idempotent — useful when subcommand parsers
// chain through helpers).
func WrapUsageError(msg string, cause error) error {
	var ue *UsageError
	if errors.As(cause, &ue) {
		return ue
	}
	return &UsageError{Msg: msg, Cause: cause}
}

// IsUsageError reports whether err is or wraps a UsageError.
// Equivalent to: var ue *UsageError; errors.As(err, &ue) — provided
// as a convenience for the dispatcher and tests.
func IsUsageError(err error) bool {
	var ue *UsageError
	return errors.As(err, &ue)
}

// Compile-time check that UsageError satisfies the error interface
// and the unwrap-via-Unwrap convention.
var _ error = (*UsageError)(nil)
var _ interface{ Unwrap() error } = (*UsageError)(nil)
