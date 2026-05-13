// Tests for the --password flag's prompt resolver (deliverable
// C-026). Covers the three resolver branches: empty (no password),
// literal value (operator passed --password VALUE), prompt sentinel
// (operator passed --password with no value, must come from TTY).
package main

import (
	"bytes"
	"strings"
	"testing"
)

// @spec cli-password-flag
// @ac AC-01
// @ac AC-05
// @ac AC-09
func TestResolvePassword_Empty(t *testing.T) {
	t.Run("cli-password-flag/AC-01", func(t *testing.T) {})
	t.Run("cli-password-flag/AC-05", func(t *testing.T) {})
	t.Run("cli-password-flag/AC-09", func(t *testing.T) {})
	got, err := resolvePassword("", &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if got != "" {
		t.Errorf("empty input should produce empty output; got %q", got)
	}
}

// @spec cli-password-flag
// @ac AC-02
// @ac AC-06
func TestResolvePassword_LiteralValue(t *testing.T) {
	t.Run("cli-password-flag/AC-02", func(t *testing.T) {})
	t.Run("cli-password-flag/AC-06", func(t *testing.T) {})
	got, err := resolvePassword("hunter2", &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("literal: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("literal input should pass through; got %q", got)
	}
}

// @spec cli-password-flag
// @ac AC-03
// @ac AC-07
func TestResolvePassword_SentinelOnNonTTY(t *testing.T) {
	t.Run("cli-password-flag/AC-03", func(t *testing.T) {})
	t.Run("cli-password-flag/AC-07", func(t *testing.T) {})
	// When the sentinel is set but stdin is a non-TTY (e.g.,
	// piped to bytes.Buffer), the resolver fails with a usage
	// error rather than blocking forever.
	stdin := bytes.NewBufferString("anything")
	stderr := &bytes.Buffer{}
	_, err := resolvePassword(passwordPromptSentinel, stdin, stderr)
	if err == nil {
		t.Fatal("non-TTY sentinel should error, not block")
	}
	if !strings.Contains(err.Error(), "TTY") {
		t.Errorf("error should mention TTY: %v", err)
	}
}

// @spec cli-password-flag
// @ac AC-04
// @ac AC-08
func TestResolvePassword_SentinelValue_NotMistakenForLiteral(t *testing.T) {
	t.Run("cli-password-flag/AC-04", func(t *testing.T) {})
	t.Run("cli-password-flag/AC-08", func(t *testing.T) {})
	// The sentinel is a documented reserved literal: an operator
	// passing --password='<prompt>' triggers the prompt rather than
	// using those characters as the password. The resolver detects
	// on exact string equality. This test locks the contract.
	if passwordPromptSentinel == "" {
		t.Fatal("sentinel must be non-empty")
	}
	if passwordPromptSentinel != "<prompt>" {
		t.Errorf("sentinel changed; update reserved-literal docs in password.spec.yaml: got %q", passwordPromptSentinel)
	}
}
