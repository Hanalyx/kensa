package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// sudoPasswordEnv is the environment variable consulted for the sudo
// password when --sudo-password is not passed inline. It lets scripted
// and --inventory runs supply a shared sudo password without putting it
// on the command line (mirrors SSHPASS for --password).
const sudoPasswordEnv = "KENSA_SUDO_PASSWORD"

// sudoPasswordPromptSentinel is the value pflag stores when
// --sudo-password was passed without an argument (NoOptDefVal). The
// runtime detects it and prompts on the controlling TTY. Mirrors
// passwordPromptSentinel; passing `--sudo-password='<prompt>'` triggers
// the prompt rather than using those characters literally.
const sudoPasswordPromptSentinel = "<prompt>"

// resolveSudoPassword returns the sudo password to use for `sudo -S`.
//
// Resolution order:
//   - inline value (anything but the sentinel) → used as-is
//   - sentinel (flag given without an argument) → prompt on the TTY
//   - empty flag → fall back to the KENSA_SUDO_PASSWORD env var
//     (empty if unset; the host must then allow passwordless sudo)
//
// As with resolvePassword, the sentinel-without-a-TTY case is a usage
// error so a scripted run doesn't hang waiting for input.
func resolveSudoPassword(raw string, stdin io.Reader, stderr io.Writer) (string, error) {
	if raw == "" {
		return os.Getenv(sudoPasswordEnv), nil
	}
	if raw != sudoPasswordPromptSentinel {
		return raw, nil
	}
	stdinFile, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(stdinFile.Fd())) {
		return "", errors.New("--sudo-password without an argument requires a TTY for the prompt; pass the value inline or via " + sudoPasswordEnv + " env when scripted")
	}
	if _, err := fmt.Fprint(stderr, "sudo password: "); err != nil {
		return "", err
	}
	pw, err := term.ReadPassword(int(stdinFile.Fd()))
	_, _ = fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read sudo password: %w", err)
	}
	if len(pw) == 0 {
		return "", errors.New("--sudo-password prompt: empty password rejected")
	}
	return string(pw), nil
}

// resolveSudoPasswordFor resolves the sudo password for a single-host
// subcommand and enforces the --sudo dependency. When sudo is off an
// explicitly-passed --sudo-password is a usage error, while an ambient
// KENSA_SUDO_PASSWORD env value is silently ignored (it only applies to
// sudo runs, so a globally-exported env var doesn't break non-sudo
// commands). Returns the password to place on HostConfig.SudoPassword.
func resolveSudoPasswordFor(fs *pflag.FlagSet, raw string, sudo bool, stdin io.Reader, stderr io.Writer) (string, error) {
	pw, err := resolveSudoPassword(raw, stdin, stderr)
	if err != nil {
		return "", &UsageError{Cause: err}
	}
	if !sudo {
		if fs.Changed("sudo-password") {
			return "", NewUsageError("--sudo-password requires --sudo")
		}
		return "", nil
	}
	return pw, nil
}

// inventorySudoPassword returns the KENSA_SUDO_PASSWORD env value when
// sudo is enabled, else "". Inventory runs reject --sudo-password inline
// (one secret across a heterogeneous fleet is a footgun), so the env var
// is the supported channel for a shared fleet sudo password; the fan-out
// applies it to each host.
func inventorySudoPassword(sudo bool) string {
	if !sudo {
		return ""
	}
	return os.Getenv(sudoPasswordEnv)
}

// registerSudoPasswordFlag wires --sudo-password onto fs. No short
// letter (the -s space is taken by --sudo). Used by detect, check,
// remediate, and plan — the subcommands that open SSH transports under
// --sudo.
func registerSudoPasswordFlag(fs *pflag.FlagSet, dst *string) {
	fs.StringVar(dst, "sudo-password", "",
		"sudo password for non-NOPASSWD hosts (omit value for TTY prompt; or set "+sudoPasswordEnv+"; requires --sudo)")
	fs.Lookup("sudo-password").NoOptDefVal = sudoPasswordPromptSentinel
}
