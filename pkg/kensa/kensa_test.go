package kensa

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestKensaDefault_LoadsSigningKey locks C-060 AC-06: when
// KENSA_SIGNING_KEY env var points at a PEM-encoded .priv file,
// Default() loads it as the engine's signing key (instead of
// generating a fresh ephemeral one). The test fixture is a key
// produced by kensa-keygen's PEM format; we re-derive it inline
// here to avoid coupling pkg/kensa to the kensa-keygen binary.
//
// @spec cli-verify-subcommand
// @ac AC-06
func TestKensaDefault_LoadsSigningKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.priv")
	// PEM-encoded PKCS#8 Ed25519 private key. Generated once with
	// kensa-keygen and inlined here as a fixture so the test has
	// no external dependency on the keygen binary.
	const privPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIN2WeGFNzdYfuYhZQ/MGmxv2yvMoXyU3kVOwEJEK1JC
-----END PRIVATE KEY-----
`
	if err := os.WriteFile(keyPath, []byte(privPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KENSA_SIGNING_KEY", keyPath)

	storePath := filepath.Join(dir, "results.db")
	svc, err := Default(context.Background(), storePath)
	if err != nil {
		t.Fatalf("Default(KENSA_SIGNING_KEY=%s): %v", keyPath, err)
	}
	defer svc.Close()
}

// TestKensaDefault_RejectsLooseModeKey locks the security
// guard added in C-060 review fix: a .priv file with group/
// other-readable permissions MUST be rejected, OpenSSH
// StrictModes-style. Loading a leaked key silently would let
// any co-tenant who already read the file forge envelopes.
func TestKensaDefault_RejectsLooseModeKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "loose.priv")
	const privPEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIN2WeGFNzdYfuYhZQ/MGmxv2yvMoXyU3kVOwEJEK1JC
-----END PRIVATE KEY-----
`
	if err := os.WriteFile(keyPath, []byte(privPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("KENSA_SIGNING_KEY", keyPath)

	storePath := filepath.Join(dir, "results.db")
	svc, err := Default(context.Background(), storePath)
	if err == nil {
		_ = svc.Close()
		t.Fatal("Default() should have rejected mode 0644 .priv but returned nil err")
	}
}
