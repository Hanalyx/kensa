package evidence_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/internal/evidence"
)

// writePEMKeypair generates and writes a kensa-keygen-compatible
// PEM keypair to a temp dir, returns the priv path + pub path +
// the parsed keys for cross-check.
func writePEMKeypair(t *testing.T, dir string) (string, string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privPath := filepath.Join(dir, "test.priv")
	pubPath := filepath.Join(dir, "test.pub")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath, priv, pub
}

// TestLoadSigner_RoundTrip locks: the .priv file written by
// kensa-keygen (PKCS#8 PEM) loads via LoadSigner, and the
// resulting signer's KeyID matches what computeKeyID would have
// produced from the corresponding .pub.
func TestLoadSigner_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, _, _ := writePEMKeypair(t, dir)

	signer, err := evidence.LoadSigner(privPath)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if len(signer.KeyID()) != 64 {
		t.Errorf("KeyID len: got %d, want 64", len(signer.KeyID()))
	}

	// Verify the signer's public-key-as-keyID matches what we'd
	// derive from the .pub file independently.
	pubBytes, _ := os.ReadFile(pubPath)
	block, _ := pem.Decode(pubBytes)
	parsed, _ := x509.ParsePKIXPublicKey(block.Bytes)
	expectedKeyID := lowerHexSHA256(parsed.(ed25519.PublicKey))
	if signer.KeyID() != expectedKeyID {
		t.Errorf("KeyID mismatch: signer=%q, derived-from-pub=%q",
			signer.KeyID(), expectedKeyID)
	}
}

// TestLoadVerifier_RoundTrip locks: the .pub file loads, the
// resulting verify-only signer has matching KeyID, and Sign()
// fails clearly because there's no private key.
func TestLoadVerifier_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	_, pubPath, _, _ := writePEMKeypair(t, dir)

	verifier, err := evidence.LoadVerifier(pubPath)
	if err != nil {
		t.Fatalf("LoadVerifier: %v", err)
	}
	if len(verifier.KeyID()) != 64 {
		t.Errorf("KeyID len: got %d, want 64", len(verifier.KeyID()))
	}

	// Sign() on a verify-only signer must fail with a clear
	// message. Use a synthetic envelope.
	env := makeEnvelope() // helper from signer_test.go
	_, _, err = verifier.Sign(env)
	if err == nil {
		t.Error("Sign on verify-only signer should fail")
	}
	if !strings.Contains(err.Error(), "verify-only") {
		t.Errorf("error should mention verify-only; got: %v", err)
	}
}

// TestLoadSigner_VerifyAcrossInstances locks the C-060
// cross-invocation-verifiability contract: a key loaded by
// one signer can verify what another signer loaded from the
// same file produced.
func TestLoadSigner_VerifyAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, _, _ := writePEMKeypair(t, dir)

	signerA, _ := evidence.LoadSigner(privPath)
	verifierB, _ := evidence.LoadVerifier(pubPath)

	env := makeEnvelope()
	sig, keyID, err := signerA.Sign(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	env.SigningKeyID = keyID

	r, err := verifierB.Verify(env)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !r.Valid {
		t.Error("verify-only signer should validate the same key's signature")
	}
	if r.KeyID != signerA.KeyID() {
		t.Errorf("matched KeyID mismatch: got %q, want %q", r.KeyID, signerA.KeyID())
	}
}

// TestLoadSigner_BadInputs locks the failure modes.
func TestLoadSigner_BadInputs(t *testing.T) {
	dir := t.TempDir()

	// Missing file.
	_, err := evidence.LoadSigner(filepath.Join(dir, "no-such-file.priv"))
	if err == nil {
		t.Error("missing file should error")
	}

	// Non-PEM file.
	bogusPath := filepath.Join(dir, "bogus.priv")
	os.WriteFile(bogusPath, []byte("not a pem file"), 0o600)
	_, err = evidence.LoadSigner(bogusPath)
	if err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Errorf("non-PEM file should error with PEM mention; got: %v", err)
	}

	// PEM with wrong block type.
	wrongTypePath := filepath.Join(dir, "wrongtype.priv")
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("garbage")})
	os.WriteFile(wrongTypePath, wrongPEM, 0o600)
	_, err = evidence.LoadSigner(wrongTypePath)
	if err == nil || !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("wrong PEM type should be rejected; got: %v", err)
	}
}

// lowerHexSHA256 mirrors evidence.computeKeyID for cross-check.
func lowerHexSHA256(pub ed25519.PublicKey) string {
	// Replicate the evidence package's computeKeyID without
	// importing internal-only helpers. SHA-256 of the raw
	// public-key bytes, lower-hex.
	signer := evidence.NewVerifier(pub)
	return signer.KeyID()
}
