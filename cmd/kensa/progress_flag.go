package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/Hanalyx/kensa/internal/progress"
)

// Progress-mode vocabulary for the --progress flag (PR4,
// spec cli-progress-stream). The mode is one knob; whether the live
// progress stream actually renders is the AND of this mode with the
// stderr-is-TTY heuristic and the --quiet flag, computed by
// progressEnabled.
const (
	// progressAuto turns the stream on only when stderr is a TTY and
	// --quiet is not set. The default — clean logs when redirected,
	// live feedback at an interactive terminal.
	progressAuto = "auto"
	// progressAlways forces the stream on regardless of the TTY
	// heuristic (so an operator can capture it in a redirected stderr).
	progressAlways = "always"
	// progressNever forces the stream off regardless of TTY/quiet.
	progressNever = "never"
)

// registerProgressFlag wires `--progress=auto|always|never` (long-only,
// default auto) onto fs. Shared by `kensa check` and `kensa detect`; both
// are the read-only single-host commands wired to the renderer in PR4.
func registerProgressFlag(fs *pflag.FlagSet, dst *string) {
	fs.StringVarP(dst, "progress", ShortProgress, progressAuto,
		"live progress stream on stderr: auto (TTY only), always, or never")
}

// validateProgressMode rejects any --progress value outside the
// {auto, always, never} vocabulary as a usage error. Called before the
// SSH transport is opened so a typo surfaces as exit 2 immediately, not
// after a connection attempt (spec cli-progress-stream C-04 / AC-04).
func validateProgressMode(mode string) error {
	switch mode {
	case progressAuto, progressAlways, progressNever:
		return nil
	default:
		return NewUsageError(fmt.Sprintf(
			"--progress %q: unknown mode (choices: auto, always, never)", mode))
	}
}

// progressEnabled is the pure decision function for whether the live
// progress stream renders. It is a function ONLY of the three injected
// inputs so both branches are deterministically unit-testable — it never
// probes a real terminal itself (the caller injects stderrIsTTY via
// stderrIsTerminal). Resolution (spec cli-progress-stream C-02/C-03):
//
//	auto   -> stderrIsTTY AND NOT quiet   (--quiet wins over the heuristic)
//	always -> on  (regardless of TTY/quiet)
//	never  -> off (regardless of TTY/quiet)
//
// An unrecognized mode resolves to off; validateProgressMode rejects such
// values earlier, so this is only a defensive default.
func progressEnabled(mode string, stderrIsTTY, quiet bool) bool {
	switch mode {
	case progressAlways:
		return true
	case progressNever:
		return false
	case progressAuto:
		return stderrIsTTY && !quiet
	default:
		return false
	}
}

// stderrIsTerminal reports whether os.Stderr is attached to a terminal.
// This is the single runtime TTY probe for progress; it is kept out of
// progressEnabled so the decision logic stays pure and testable. Progress
// bytes always go to stderr (never stdout), so the TTY heuristic probes
// stderr — not stdout, which carries the canonical result and may be piped
// to a file independently of whether the operator is at a terminal.
func stderrIsTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// stdoutIsTerminal reports whether os.Stdout is attached to a terminal. Used
// by the default text path, whose live result rows go to stdout (the result
// stream), so color is gated on whether stdout — not stderr — is a TTY.
func stdoutIsTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// newProgressSink returns the text StreamConsumer the CLI wires into the
// scan runner / DetectWithProgress when progress is enabled, pointed at
// w (the caller passes os.Stderr). It returns a typed *progress.StreamConsumer
// rather than a progress.Sink so a nil result is unambiguous: callers that
// do NOT want progress simply never call this and pass a nil sink.
//
// The writer is REQUIRED to be a non-stdout stream (the CLI passes
// os.Stderr); the renderer writes only to w, so the canonical result on
// stdout is never touched (spec cli-progress-stream C-05).
func newProgressSink(w io.Writer, isTTY bool) *progress.StreamConsumer {
	return progress.NewTextConsumer(w, isTTY)
}
