// Internal tests for the sudo wrapping logic (lower-case, package-
// private) added for sudo-with-password support (`sudo -S`). The
// central invariant — the sudo password is NEVER interpolated into the
// command string (it rides stdin only) — is locked by TestSudoWrap.
package ssh

import (
	"context"
	"strings"
	"testing"
)

// @spec cli-sudo-password-flag
// @ac AC-01
// @ac AC-02
// @ac AC-03
func TestSudoWrap(t *testing.T) {
	const cmd = "cat /etc/shadow"
	const pw = "s3cr3t-sudo-pw"

	t.Run("cli-sudo-password-flag/AC-01", func(t *testing.T) {
		// sudo off → passthrough, no stdin.
		wrapped, stdin := sudoWrap(cmd, false, "")
		if wrapped != cmd {
			t.Errorf("sudo off should pass command through; got %q", wrapped)
		}
		if stdin != "" {
			t.Errorf("sudo off should have no stdin payload; got %q", stdin)
		}
		// A password with sudo off must still not appear (Connect
		// rejects that combination, but sudoWrap must be safe too).
		wrapped, stdin = sudoWrap(cmd, false, pw)
		if strings.Contains(wrapped, pw) || stdin != "" {
			t.Errorf("sudo off must ignore the password entirely; wrapped=%q stdin=%q", wrapped, stdin)
		}
	})

	t.Run("cli-sudo-password-flag/AC-02", func(t *testing.T) {
		// sudo on, no password → unchanged `sudo -n` path.
		wrapped, stdin := sudoWrap(cmd, true, "")
		if wrapped != "sudo -n sh -c "+shellQuote(cmd) {
			t.Errorf("NOPASSWD path drifted; got %q", wrapped)
		}
		if stdin != "" {
			t.Errorf("NOPASSWD path must not feed stdin; got %q", stdin)
		}
	})

	t.Run("cli-sudo-password-flag/AC-03", func(t *testing.T) {
		// sudo on, with password → `sudo -S -p ''`, password on stdin.
		wrapped, stdin := sudoWrap(cmd, true, pw)
		if wrapped != "sudo -S -p '' sh -c "+shellQuote(cmd) {
			t.Errorf("password path wrap drifted; got %q", wrapped)
		}
		// THE INVARIANT: the password must never appear in the command
		// string (argv / /proc / recorded evidence) — only on stdin.
		if strings.Contains(wrapped, pw) {
			t.Fatalf("SECURITY: sudo password leaked into the command string %q", wrapped)
		}
		if stdin != pw+"\n" {
			t.Errorf("stdin payload should be the password + newline; got %q", stdin)
		}
	})
}

// @spec cli-sudo-password-flag
// @ac AC-06
func TestSudoPasswordRejected(t *testing.T) {
	t.Run("cli-sudo-password-flag/AC-06", func(t *testing.T) {})
	yes := []string{
		"sudo: 1 incorrect password attempt",
		"Sorry, try again.",
		"sudo: 3 incorrect password attempts",
		"sudo: no password was provided",
	}
	for _, s := range yes {
		if !sudoPasswordRejected(s) {
			t.Errorf("expected sudoPasswordRejected(true) for %q", s)
		}
	}
	no := []string{
		"",
		"true",
		"sudo: user owadmin is not allowed to execute '/bin/true' as root",
		"bash: command not found",
	}
	for _, s := range no {
		if sudoPasswordRejected(s) {
			t.Errorf("expected sudoPasswordRejected(false) for %q", s)
		}
	}
}

// @spec cli-sudo-password-flag
// @ac AC-05
func TestConnect_SudoPasswordRequiresSudo(t *testing.T) {
	t.Run("cli-sudo-password-flag/AC-05", func(t *testing.T) {})
	// The guard fires before any connection attempt, so this is a
	// pure unit check with no network.
	_, err := Connect(context.Background(), Config{
		Host:         "unreachable.invalid",
		SudoPassword: "pw",
		Sudo:         false,
	})
	if err == nil {
		t.Fatal("expected error when SudoPassword is set without Sudo")
	}
	if !strings.Contains(err.Error(), "SudoPassword set without Sudo") {
		t.Errorf("error should explain the Sudo dependency; got %v", err)
	}
}
