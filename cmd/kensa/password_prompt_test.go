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

func TestResolvePassword_Empty(t *testing.T) {
	got, err := resolvePassword("", &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if got != "" {
		t.Errorf("empty input should produce empty output; got %q", got)
	}
}

func TestResolvePassword_LiteralValue(t *testing.T) {
	got, err := resolvePassword("hunter2", &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("literal: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("literal input should pass through; got %q", got)
	}
}

func TestResolvePassword_SentinelOnNonTTY(t *testing.T) {
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

func TestResolvePassword_SentinelValue_NotMistakenForLiteral(t *testing.T) {
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
