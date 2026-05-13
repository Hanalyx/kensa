package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// passwordPromptSentinel is the value pflag stores in the password
// variable when --password / -p was passed without an argument
// (NoOptDefVal mechanism). The runtime detects this sentinel and
// prompts on the controlling TTY instead of treating it as a
// literal password.
//
// The literal "<prompt>" is a documented reserved value: passing
// `--password='<prompt>'` will trigger the prompt rather than use
// those eight characters as the password. The pflag library also
// renders this string in the auto-generated help text, where it
// reads as a natural placeholder. Operators whose actual password
// is the string "<prompt>" must set SSHPASS env or change their
// password.
const passwordPromptSentinel = "<prompt>"

// resolvePassword returns the actual password to use for SSH auth.
//
// Behavior:
//   - empty string → empty (no password auth; KeyPath / ssh-agent path)
//   - sentinel value → prompt on controlling TTY; return entered bytes
//   - any other value → return as-is (operator passed a literal)
//
// When the sentinel is present but stdin is not a TTY, returns a
// usage error so a CI script that accidentally piped --password
// doesn't hang waiting for input that won't come.
func resolvePassword(raw string, stdin io.Reader, stderr io.Writer) (string, error) {
	if raw == "" {
		return "", nil
	}
	if raw != passwordPromptSentinel {
		return raw, nil
	}
	// Prompt mode. Require a TTY on stdin to avoid blocking forever.
	stdinFile, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(stdinFile.Fd())) {
		return "", errors.New("--password without an argument requires a TTY for the prompt; pass the value inline or via SSHPASS env when scripted")
	}
	if _, err := fmt.Fprint(stderr, "SSH password: "); err != nil {
		return "", err
	}
	pw, err := term.ReadPassword(int(stdinFile.Fd()))
	// Always emit the trailing newline so the operator's terminal
	// returns to a clean line, even if ReadPassword errored.
	_, _ = fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(pw) == 0 {
		return "", errors.New("--password prompt: empty password rejected")
	}
	return string(pw), nil
}

// registerPasswordFlag wires --password / -p onto fs. Used by
// detect, check, remediate, and plan — all subcommands that open
// SSH transports. Centralized to keep the help text, short flag,
// and NoOptDefVal sentinel in one place.
func registerPasswordFlag(fs *pflag.FlagSet, dst *string) {
	fs.StringVarP(dst, "password", ShortPassword, "",
		"SSH password (omit value for TTY prompt; reserved literal: <prompt>)")
	fs.Lookup("password").NoOptDefVal = passwordPromptSentinel
}
