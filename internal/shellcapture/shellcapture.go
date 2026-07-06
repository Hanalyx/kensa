// Package shellcapture provides a byte-exact file-content capture over a shell
// transport. Transports trim the trailing newline from command stdout, so a
// handler that captured raw `cat` output silently lost a file's final newline
// and restored it one byte short on rollback — a non-byte-perfect rollback
// (the #247 class: every capturable handler that reads whole-file content over
// the shell transport and restores/rewrites it — file_content, file_absent,
// config_set_dropin, config_append, cron_job, pam_module_configure,
// pam_module_arg, sysctl_set, kernel_module_disable, dconf_set, audit_rule_set
// (its shell capture + rollback paths), plus internal/bootguard's Capture of
// /etc/default/grub and each BLS entry). Encoding the content as base64 round-trips the EXACT bytes:
// the trailing newline is inside the encoding, so trimming the transport's
// trailing newline (and any base64 line-wrapping) is harmless.
//
// The agent kernel-IO capture path (kernelio.ReadFileIfExists) already reads
// exact bytes and is unaffected; this is the shell-fallback fix only.
package shellcapture

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ContentReadCmd returns a shell fragment that emits the base64 encoding of the
// file at pathEscaped (which the caller has already shell-escaped). Plain
// `base64` (not `-w0`) is used for portability across coreutils/busybox/BSD; any
// wrapping newlines it emits are stripped at decode time. Compose this into a
// capture command and decode its output with DecodeContent.
func ContentReadCmd(pathEscaped string) string {
	return "base64 " + pathEscaped
}

// ExistenceReadCmd returns a shell fragment that emits base64(path) when path
// exists (per testFlag, e.g. "-e" or "-f") and the literal sentinel otherwise —
// using an `if…then…else…fi` form, NOT `test X && base64 X || printf S`.
//
// The `&&…||` short-circuit is a trap here: if the file exists but `base64`
// FAILS (missing on the target, EACCES), the `||` branch fires and prints the
// absent sentinel with exit 0, so the caller's res.OK() cannot see the failure
// and records an EXISTING file as ABSENT — a rollback would then DELETE it
// (destructive). With the if-form, base64 is the last command in the taken
// branch, so its non-zero exit becomes the command's exit and res.OK() aborts
// before any mutation.
//
// The sentinel is emitted as printf's ARGUMENT (`printf '%s' '<sentinel>'`), NOT
// its format string — the same format-operand hardening applied to every restore
// path (a sentinel containing `%` or `\` would otherwise be interpreted by
// printf). pathEscaped must be pre-escaped by the caller; sentinel must be a
// simple token (no single quote).
func ExistenceReadCmd(testFlag, pathEscaped, sentinel string) string {
	return fmt.Sprintf("if [ %s %s ]; then base64 %s; else printf '%%s' '%s'; fi",
		testFlag, pathEscaped, pathEscaped, sentinel)
}

// DecodeContent decodes a base64 content blob captured over a shell transport
// into the file's exact bytes. It tolerates the wrapping newlines base64 may emit
// and the transport's trailing-newline trim by stripping all ASCII whitespace
// before decoding. An empty input decodes to an empty string (an empty file).
func DecodeContent(b64 string) (string, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', ' ', '\t':
			return -1
		}
		return r
	}, b64)
	if clean == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
