// Tests for the M-012 kensa-keygen binary.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_HelpExitsZero locks the --help / -h path.
func TestRun_HelpExitsZero(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}} {
		var stdout, stderr bytes.Buffer
		exit := run(args, &stdout, &stderr)
		if exit != 0 {
			t.Errorf("run(%v) = %d, want 0; stderr=%s", args, exit, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Usage: kensa-keygen") {
			t.Errorf("--help should print usage; got: %s", stdout.String())
		}
	}
}

// TestRun_HappyPath_DefaultKeyID locks the canonical flow:
// generate a keypair, write both files, print the key_id (which
// must equal SHA-256 hex of the public key bytes).
func TestRun_HappyPath_DefaultKeyID(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--out", dir}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("run = %d, want 0; stderr=%s", exit, stderr.String())
	}

	keyID := strings.TrimSpace(stdout.String())
	if len(keyID) != 64 {
		t.Errorf("default key_id should be 64 hex chars (SHA-256); got %d: %q", len(keyID), keyID)
	}

	privPath := filepath.Join(dir, keyID+".priv")
	pubPath := filepath.Join(dir, keyID+".pub")

	// Files exist with right modes.
	stPriv, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("priv file: %v", err)
	}
	if stPriv.Mode().Perm() != 0o600 {
		t.Errorf(".priv mode: got %o, want 0600", stPriv.Mode().Perm())
	}
	stPub, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("pub file: %v", err)
	}
	if stPub.Mode().Perm() != 0o644 {
		t.Errorf(".pub mode: got %o, want 0644", stPub.Mode().Perm())
	}

	// Files parse as PEM-wrapped Ed25519 keys.
	privPEMBytes, _ := os.ReadFile(privPath)
	pubPEMBytes, _ := os.ReadFile(pubPath)
	priv := parsePrivKey(t, privPEMBytes)
	pub := parsePubKey(t, pubPEMBytes)

	// Public key in the .pub file must equal Public() of the
	// .priv file's key. If they don't match, the operator's
	// key pair is broken — verification will fail every time.
	derivedPub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("priv.Public() not ed25519.PublicKey")
	}
	if !bytes.Equal(derivedPub, pub) {
		t.Error("priv file's public half != .pub file contents")
	}

	// key_id printed to stdout must match SHA-256 hex of the
	// public key bytes — defends the convention crossover with
	// internal/evidence.computeKeyID.
	hash := sha256.Sum256(pub)
	wantID := hex.EncodeToString(hash[:])
	if keyID != wantID {
		t.Errorf("printed key_id %q doesn't match SHA-256 of pub key %q", keyID, wantID)
	}
}

// TestRun_ExplicitKeyID locks --key-id NAME so an operator can
// pick a human-readable name like "production". When --key-id
// differs from the content-addressed SHA-256 hash, kensa-keygen
// also writes a `<sha256>.pub` alias so `kensa verify` (which
// looks up keys by signing_key_id per spec C-02) can find the
// public key without a --trust-dir gymnastic.
func TestRun_ExplicitKeyID(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--out", dir, "--key-id", "production"}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("run = %d, want 0; stderr=%s", exit, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "production" {
		t.Errorf("stdout: got %q, want 'production'", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "production.priv")); err != nil {
		t.Errorf("production.priv missing: %v", err)
	}
	humanPubPath := filepath.Join(dir, "production.pub")
	if _, err := os.Stat(humanPubPath); err != nil {
		t.Errorf("production.pub missing: %v", err)
	}

	// Hash-named alias must exist with identical PEM bytes so
	// `kensa verify` (signing_key_id-based lookup) works.
	humanPEM, err := os.ReadFile(humanPubPath)
	if err != nil {
		t.Fatalf("read production.pub: %v", err)
	}
	block, _ := pem.Decode(humanPEM)
	if block == nil {
		t.Fatal("production.pub is not PEM-encoded")
	}
	pkix, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := pkix.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("not an Ed25519 public key: %T", pkix)
	}
	hash := sha256.Sum256(pub)
	hashID := hex.EncodeToString(hash[:])
	aliasPath := filepath.Join(dir, hashID+".pub")
	aliasPEM, err := os.ReadFile(aliasPath)
	if err != nil {
		t.Errorf("hash-named alias %s missing: %v", aliasPath, err)
	}
	if !bytes.Equal(humanPEM, aliasPEM) {
		t.Errorf("alias .pub PEM differs from human .pub PEM (alias must be byte-identical for verify lookups)")
	}
}

// TestRun_DefaultKeyID_NoAlias locks the negative case: when no
// --key-id is passed, the file is already named by SHA-256 hash,
// so a separate alias would be a duplicate. Verify only ONE .pub
// gets written.
func TestRun_DefaultKeyID_NoAlias(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--out", dir}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("run = %d, want 0; stderr=%s", exit, stderr.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	pubCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pub") {
			pubCount++
		}
	}
	if pubCount != 1 {
		t.Errorf("default --key-id: want exactly 1 .pub file (no alias needed); got %d", pubCount)
	}
}

// TestRun_RejectsExistingFiles locks the safety contract: by
// default kensa-keygen refuses to overwrite. Operator who really
// means it passes --force.
func TestRun_RejectsExistingFiles(t *testing.T) {
	dir := t.TempDir()
	// Pre-create the .priv file the next run would write.
	preExisting := filepath.Join(dir, "production.priv")
	if err := os.WriteFile(preExisting, []byte("not a real key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--out", dir, "--key-id", "production"}, &stdout, &stderr)
	if exit != 2 {
		t.Errorf("collision should exit 2 (usage); got %d", exit)
	}
	if !strings.Contains(stderr.String(), "refusing to overwrite") {
		t.Errorf("stderr should explain collision; got: %s", stderr.String())
	}
	// Pre-existing file MUST NOT have been clobbered.
	contents, _ := os.ReadFile(preExisting)
	if string(contents) != "not a real key" {
		t.Errorf("pre-existing file was modified — refusal didn't hold")
	}
}

// TestRun_ForceOverwrites locks the --force escape hatch.
func TestRun_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	preExisting := filepath.Join(dir, "production.priv")
	if err := os.WriteFile(preExisting, []byte("old key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--out", dir, "--key-id", "production", "--force"}, &stdout, &stderr)
	if exit != 0 {
		t.Errorf("--force should exit 0; got %d, stderr=%s", exit, stderr.String())
	}
	contents, _ := os.ReadFile(preExisting)
	if string(contents) == "old key" {
		t.Errorf("--force should have overwritten the file")
	}
	// New contents must be PEM-formatted.
	if !bytes.Contains(contents, []byte("BEGIN PRIVATE KEY")) {
		t.Errorf("overwritten file should be PEM-formatted; got prefix: %q", contents[:min(40, len(contents))])
	}
}

// TestRun_ForceArchivesPriorPub locks the peer-review-driven
// safeguard: when --force overwrites an existing keypair, the
// OLD .pub file is renamed to <keyid>.pub.archived.<unix-ts>
// so auditors verifying past envelopes still have access to
// the public key. Without this, --force silently destroys the
// only thing that can verify pre-rotation envelopes.
func TestRun_ForceArchivesPriorPub(t *testing.T) {
	dir := t.TempDir()
	priorPub := filepath.Join(dir, "production.pub")
	priorContent := []byte("-----BEGIN PUBLIC KEY-----\nFAKEOLDKEY\n-----END PUBLIC KEY-----\n")
	if err := os.WriteFile(priorPub, priorContent, 0o644); err != nil {
		t.Fatal(err)
	}
	// Also a .priv so the collision check fires both ways.
	priorPriv := filepath.Join(dir, "production.priv")
	if err := os.WriteFile(priorPriv, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	exit := run([]string{"--out", dir, "--key-id", "production", "--force"}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("--force exit: %d; stderr=%s", exit, stderr.String())
	}

	// Find the archived .pub. Filename pattern: production.pub.archived.<digits>
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var archived string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "production.pub.archived.") {
			archived = filepath.Join(dir, e.Name())
		}
	}
	if archived == "" {
		t.Fatalf("expected an archived .pub file in %s; got entries: %v", dir, entries)
	}
	got, _ := os.ReadFile(archived)
	if !bytes.Equal(got, priorContent) {
		t.Errorf("archived .pub contents differ from original prior pub")
	}

	// stderr should mention the archive so the operator notices.
	if !strings.Contains(stderr.String(), "archived prior public key to") {
		t.Errorf("stderr should mention archive; got:\n%s", stderr.String())
	}
}

// TestRun_OutputIncludesFingerprint locks the SHA-256 fingerprint
// in the success-stderr output. The ssh-keygen-style
// "SHA256:<base64>" form gives operators a recognizable
// verification marker.
func TestRun_OutputIncludesFingerprint(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"--out", dir}, &stdout, &stderr); exit != 0 {
		t.Fatalf("run failed: %d %s", exit, stderr.String())
	}
	if !strings.Contains(stderr.String(), "pub fingerprint: SHA256:") {
		t.Errorf("stderr should include 'pub fingerprint: SHA256:'; got:\n%s", stderr.String())
	}
}

// TestRun_HelpMentionsRotation locks the help-text rotation
// paragraph so a future contributor doesn't accidentally drop it.
func TestRun_HelpMentionsRotation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"--help"}, &stdout, &stderr); exit != 0 {
		t.Fatalf("--help: %d %s", exit, stderr.String())
	}
	for _, want := range []string{"KEY ROTATION", "key_history", "DO NOT delete"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("--help should mention %q; got:\n%s", want, stdout.String())
		}
	}
}

// TestRun_DefaultDir uses the env-var precedence chain — set
// KENSA_CONFIG_DIR to a temp dir and verify the keys land under
// it without an explicit --out.
func TestRun_DefaultDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KENSA_CONFIG_DIR", dir)
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--key-id", "test-default"}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("run = %d, want 0; stderr=%s", exit, stderr.String())
	}
	expected := filepath.Join(dir, "keys", "test-default.priv")
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("expected key at %s: %v", expected, err)
	}
}

// TestRun_BadFlag locks the usage-error exit code (2).
func TestRun_BadFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--bogus"}, &stdout, &stderr)
	if exit != 2 {
		t.Errorf("bad flag should exit 2; got %d", exit)
	}
}

// TestRun_DirectoryAutoCreate verifies kensa-keygen mkdir's the
// output directory if it doesn't exist (with mode 0700).
func TestRun_DirectoryAutoCreate(t *testing.T) {
	root := t.TempDir()
	deepDir := filepath.Join(root, "kensa", "keys", "production")
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--out", deepDir}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("auto-create should succeed; got %d, stderr=%s", exit, stderr.String())
	}
	st, err := os.Stat(deepDir)
	if err != nil {
		t.Fatalf("dir not created: %v", err)
	}
	if !st.IsDir() {
		t.Errorf("expected directory at %s", deepDir)
	}
	// Mode 0700 — only owner can list. Mode bits include the
	// sticky-bit and setuid-bit positions, mask down to perm.
	if st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode: got %o, want 0700", st.Mode().Perm())
	}
}

// TestRun_PrivKeyParsesAsEd25519 catches a regression where the
// PKCS#8 wrapping changes algorithm OID. Crypto auditors care
// that the file says "this is an Ed25519 key" not "this is some
// generic private key bytes." Parse strictly.
func TestRun_PrivKeyParsesAsEd25519(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"--out", dir}, &stdout, &stderr); exit != 0 {
		t.Fatalf("run failed: %d %s", exit, stderr.String())
	}
	keyID := strings.TrimSpace(stdout.String())
	privPEM, _ := os.ReadFile(filepath.Join(dir, keyID+".priv"))
	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatal("priv file is not PEM-decodable")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("PEM type: got %q, want 'PRIVATE KEY'", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("PKCS#8 parse: %v", err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Errorf("PKCS#8 inner key type: got %T, want ed25519.PrivateKey", parsed)
	}
}

// parsePrivKey is a test helper.
func parsePrivKey(t *testing.T, p []byte) ed25519.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(p)
	if block == nil {
		t.Fatal("priv PEM decode failed")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("PKCS#8 parse: %v", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("not an ed25519 private key")
	}
	return priv
}

// parsePubKey is a test helper.
func parsePubKey(t *testing.T, p []byte) ed25519.PublicKey {
	t.Helper()
	block, _ := pem.Decode(p)
	if block == nil {
		t.Fatal("pub PEM decode failed")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("PKIX parse: %v", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatal("not an ed25519 public key")
	}
	return pub
}
