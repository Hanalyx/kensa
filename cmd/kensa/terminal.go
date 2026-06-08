package main

import (
	"os"

	"golang.org/x/term"
)

// stdoutIsTerminal reports whether os.Stdout is attached to a terminal. Used
// by the default text path, whose live result rows go to stdout (the result
// stream), so color is gated on whether stdout is a TTY.
func stdoutIsTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}
