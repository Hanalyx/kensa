// Tests for the --sudo-password resolver and its --sudo dependency
// guard. Mirrors password_prompt_test.go for the sudo-with-password
// (`sudo -S`) deliverable.
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// @spec cli-sudo-password-flag
// @ac AC-07
func TestResolveSudoPassword_Empty_NoEnv(t *testing.T) {
	t.Run("cli-sudo-password-flag/AC-07", func(t *testing.T) {})
	t.Setenv(sudoPasswordEnv, "")
	got, err := resolveSudoPassword("", &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if got != "" {
		t.Errorf("empty input with no env should produce empty output; got %q", got)
	}
}

// @spec cli-sudo-password-flag
// @ac AC-07
func TestResolveSudoPassword_EnvFallback(t *testing.T) {
	t.Setenv(sudoPasswordEnv, "fromenv")
	got, err := resolveSudoPassword("", &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("env fallback: %v", err)
	}
	if got != "fromenv" {
		t.Errorf("empty flag should fall back to %s env; got %q", sudoPasswordEnv, got)
	}
}

// @spec cli-sudo-password-flag
// @ac AC-07
func TestResolveSudoPassword_Literal(t *testing.T) {
	// A literal must win over the env (explicit beats ambient).
	t.Setenv(sudoPasswordEnv, "fromenv")
	got, err := resolveSudoPassword("inline", &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("literal: %v", err)
	}
	if got != "inline" {
		t.Errorf("literal should pass through and beat env; got %q", got)
	}
}

// @spec cli-sudo-password-flag
// @ac AC-07
func TestResolveSudoPassword_SentinelOnNonTTY(t *testing.T) {
	stdin := bytes.NewBufferString("anything")
	_, err := resolveSudoPassword(sudoPasswordPromptSentinel, stdin, &bytes.Buffer{})
	if err == nil {
		t.Fatal("non-TTY sentinel should error, not block")
	}
	if !strings.Contains(err.Error(), "TTY") {
		t.Errorf("error should mention TTY: %v", err)
	}
}

// @spec cli-sudo-password-flag
// @ac AC-08
func TestResolveSudoPasswordFor_RequiresSudo(t *testing.T) {
	t.Run("cli-sudo-password-flag/AC-08", func(t *testing.T) {})
	newFS := func() *pflag.FlagSet {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		var dst string
		registerSudoPasswordFlag(fs, &dst)
		return fs
	}

	// Flag explicitly passed without --sudo → usage error.
	fs := newFS()
	if err := fs.Parse([]string{"--sudo-password=pw"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err := resolveSudoPasswordFor(fs, "pw", false, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "requires --sudo") {
		t.Errorf("explicit --sudo-password without --sudo should error with 'requires --sudo'; got %v", err)
	}

	// Ambient env value (flag not changed) without --sudo → silently
	// ignored, returns empty (a globally-exported env var must not
	// break non-sudo commands).
	fs = newFS()
	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := resolveSudoPasswordFor(fs, "fromenv", false, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("ambient env without sudo should not error; got %v", err)
	}
	if got != "" {
		t.Errorf("ambient env without sudo should be ignored; got %q", got)
	}

	// With --sudo, the resolved value flows through.
	fs = newFS()
	if err := fs.Parse([]string{"--sudo-password=pw"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err = resolveSudoPasswordFor(fs, "pw", true, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("with sudo: %v", err)
	}
	if got != "pw" {
		t.Errorf("with --sudo the password should flow through; got %q", got)
	}
}

// @spec cli-sudo-password-flag
// @ac AC-08
func TestBuildRollbackHostCfg_SudoPassword(t *testing.T) {
	t.Run("cli-sudo-password-flag/AC-08", func(t *testing.T) {})
	newFS := func() *pflag.FlagSet {
		fs := pflag.NewFlagSet("rollback", pflag.ContinueOnError)
		registerStrictHostKeysFlag(fs)
		return fs
	}

	// --sudo-password without --sudo → usage error.
	if _, err := buildRollbackHostCfg(newFS(), "h", "u", 22, "", false, "pw"); err == nil ||
		!strings.Contains(err.Error(), "requires --sudo") {
		t.Errorf("rollback --sudo-password without --sudo should error; got %v", err)
	}

	// With --sudo, the password is wired onto the HostConfig.
	cfg, err := buildRollbackHostCfg(newFS(), "h", "u", 22, "", true, "pw")
	if err != nil {
		t.Fatalf("with sudo: %v", err)
	}
	if cfg.SudoPassword != "pw" || !cfg.Sudo { // pragma: allowlist secret  (fake test value)
		t.Errorf("expected SudoPassword wired with Sudo true; got Sudo=%v SudoPassword=%q", cfg.Sudo, cfg.SudoPassword)
	}
}

// @spec cli-sudo-password-flag
// @ac AC-08
func TestInventorySudoPassword(t *testing.T) {
	t.Setenv(sudoPasswordEnv, "fleetpw")
	if got := inventorySudoPassword(false); got != "" {
		t.Errorf("inventory sudo password must be empty when sudo is off; got %q", got)
	}
	if got := inventorySudoPassword(true); got != "fleetpw" {
		t.Errorf("inventory sudo password should come from env when sudo is on; got %q", got)
	}
}
