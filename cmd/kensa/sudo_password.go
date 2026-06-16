package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/transport/ssh"
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

// sudoRequiresPassword reports whether the target host's sudo needs a
// password, by opening a non-sudo transport and running `sudo -n true`.
// A clean exit means passwordless sudo (NOPASSWD); a non-zero exit (or
// any connect/run failure, conservatively) means a password is required.
//
// Used by the remediate agent path to decide whether to feed the sudo
// password over the agent's stdin: on a NOPASSWD host `sudo -S` would
// not consume the line and it would corrupt the wire protocol, so the
// password must be dropped there.
func sudoRequiresPassword(ctx context.Context, hostCfg api.HostConfig) bool {
	probeCfg := hostCfg
	probeCfg.Sudo = false      // run our own `sudo -n`, unwrapped
	probeCfg.SudoPassword = "" // no password on the probe connection
	t, err := ssh.Factory{}.Connect(ctx, probeCfg)
	if err != nil {
		return true // can't tell; assume a password is needed (safe for real password hosts)
	}
	defer func() { _ = t.Close() }()
	res, err := t.Run(ctx, "sudo -n true")
	if err != nil {
		return true
	}
	return res.ExitCode != 0
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
