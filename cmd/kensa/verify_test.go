// Tests for the C-060 `kensa verify` subcommand.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
)

// makeVerifyFixture creates a temp trust dir with a real keypair
// (PKCS#8 PEM .priv + PKIX PEM .pub) and writes a signed evidence
// envelope file. Returns trustDir, evidencePath, keyID.
//
// Mirrors what kensa-keygen + a real `kensa check --store` run
// would produce on disk, so the tests exercise the full disk-load
// → verify pipeline.
func makeVerifyFixture(t *testing.T) (trustDir, evidencePath, keyID string) {
	t.Helper()
	trustDir = t.TempDir()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := evidence.New(priv)
	keyID = signer.KeyID()

	// Write the .pub at <keyID>.pub in the trust dir.
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(filepath.Join(trustDir, keyID+".pub"), pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	// Build + sign a representative envelope.
	env := &api.EvidenceEnvelope{
		SchemaVersion: "v1",
		TransactionID: uuid.MustParse("11111111-2222-3333-4444-555555555555"),
		RuleID:        "test-rule",
		HostID:        "test-host",
		StartedAt:     time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 5, 10, 12, 0, 5, 0, time.UTC),
		Decision:      api.StatusCommitted,
		Severity:      "high",
	}
	sig, sigKeyID, err := signer.Sign(env)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	env.SigningKeyID = sigKeyID

	evidencePath = filepath.Join(t.TempDir(), "evidence.json")
	data, _ := json.Marshal(env)
	if err := os.WriteFile(evidencePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return trustDir, evidencePath, keyID
}

// TestRunVerify_Valid locks AC-01: signed envelope + matching
// .pub in trust dir → exit 0.
// @spec cli-verify-subcommand
// @ac AC-01
func TestRunVerify_Valid(t *testing.T) {
	t.Run("cli-verify-subcommand/AC-01", func(t *testing.T) {})
	trustDir, evidencePath, _ := makeVerifyFixture(t)
	exit := runCLI([]string{"verify", "--trust-dir", trustDir, evidencePath})
	if exit != 0 {
		t.Errorf("valid envelope should exit 0; got %d", exit)
	}
	stdout, _ := captureRunCLI([]string{"verify", "--trust-dir", trustDir, evidencePath}, t)
	if !strings.Contains(stdout, "VALID") {
		t.Errorf("text output should say VALID; got:\n%s", stdout)
	}
}

// TestRunVerify_Tampered locks AC-02: modify envelope post-sign
// → exit 1.
// @spec cli-verify-subcommand
// @ac AC-02
func TestRunVerify_Tampered(t *testing.T) {
	t.Run("cli-verify-subcommand/AC-02", func(t *testing.T) {})
	trustDir, evidencePath, _ := makeVerifyFixture(t)

	// Read, mutate severity, write back.
	data, _ := os.ReadFile(evidencePath)
	var env api.EvidenceEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Severity = "low" // attacker mutation
	tamperedJSON, _ := json.Marshal(&env)
	if err := os.WriteFile(evidencePath, tamperedJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	exit := runCLI([]string{"verify", "--trust-dir", trustDir, evidencePath})
	if exit != 1 {
		t.Errorf("tampered envelope should exit 1; got %d", exit)
	}
	_, stderr := captureRunCLI([]string{"verify", "--trust-dir", trustDir, evidencePath}, t)
	if !strings.Contains(stderr, "verify") || strings.Contains(stderr, "VALID\n") {
		t.Errorf("stderr should signal failure; got:\n%s", stderr)
	}
}

// TestRunVerify_MissingKey locks AC-03: trust dir doesn't have a
// matching .pub for the envelope's signing_key_id → exit 1.
// @spec cli-verify-subcommand
// @ac AC-03
func TestRunVerify_MissingKey(t *testing.T) {
	t.Run("cli-verify-subcommand/AC-03", func(t *testing.T) {})
	_, evidencePath, _ := makeVerifyFixture(t)
	emptyTrustDir := t.TempDir() // no .pub files

	exit := runCLI([]string{"verify", "--trust-dir", emptyTrustDir, evidencePath})
	if exit != 1 {
		t.Errorf("missing key should exit 1; got %d", exit)
	}
}

// TestRunVerify_UsageErrors locks AC-04.
// @spec cli-verify-subcommand
// @ac AC-04
func TestRunVerify_UsageErrors(t *testing.T) {
	t.Run("cli-verify-subcommand/AC-04", func(t *testing.T) {})
	cases := [][]string{
		{"verify"},                           // no positional arg
		{"verify", "/nonexistent/file.json"}, // file doesn't exist
		{"verify", "--bogus", "f.json"},      // bad flag
		{"verify", "f.json", "extra-arg"},    // too many positional
	}
	for _, args := range cases {
		exit := runCLI(args)
		if exit != 2 {
			t.Errorf("runCLI(%v) = %d, want 2", args, exit)
		}
	}
}

// TestRunVerify_MalformedJSON locks the file-exists-but-not-JSON
// path: usage error (operator gave a wrong file path that
// happened to exist).
// @spec cli-verify-subcommand
// @ac AC-05
func TestRunVerify_MalformedJSON(t *testing.T) {
	t.Run("cli-verify-subcommand/AC-05", func(t *testing.T) {})
	bogusPath := filepath.Join(t.TempDir(), "not-json.json")
	if err := os.WriteFile(bogusPath, []byte("this is not JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	exit := runCLI([]string{"verify", bogusPath})
	if exit != 2 {
		t.Errorf("malformed JSON should exit 2; got %d", exit)
	}
}

// TestRunVerify_HelpExitsZero.
// @spec cli-verify-subcommand
// @ac AC-06
func TestRunVerify_HelpExitsZero(t *testing.T) {
	t.Run("cli-verify-subcommand/AC-06", func(t *testing.T) {})
	for _, argv := range [][]string{
		{"verify", "--help"},
		{"verify", "-h"},
	} {
		got := runCLI(argv)
		if got != 0 {
			t.Errorf("runCLI(%v) = %d, want 0", argv, got)
		}
	}
}

// TestRunVerify_JSONFormat locks the --format json shape.
// @spec cli-verify-subcommand
// @ac AC-07
func TestRunVerify_JSONFormat(t *testing.T) {
	t.Run("cli-verify-subcommand/AC-07", func(t *testing.T) {})
	trustDir, evidencePath, _ := makeVerifyFixture(t)
	stdout, _ := captureRunCLI(
		[]string{"verify", "--trust-dir", trustDir, evidencePath, "--format", "json"}, t)
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json parse: %v\nstdout:\n%s", err, stdout)
	}
	if got["valid"] != true {
		t.Errorf("valid: got %v, want true", got["valid"])
	}
}

// TestRunVerify_BadFormat locks --format validation.
// @spec cli-verify-subcommand
// @ac AC-08
func TestRunVerify_BadFormat(t *testing.T) {
	t.Run("cli-verify-subcommand/AC-08", func(t *testing.T) {})
	trustDir, evidencePath, _ := makeVerifyFixture(t)
	exit := runCLI([]string{"verify", "--trust-dir", trustDir, evidencePath, "--format", "yaml"})
	if exit != 2 {
		t.Errorf("bad format should exit 2; got %d", exit)
	}
}

// TestPrintUsage_ListsVerify locks the top-level help advertises
// the new subcommand.
func TestPrintUsage_ListsVerify(t *testing.T) {
	stdout, _ := captureRunCLI([]string{"--help"}, t)
	if !strings.Contains(stdout, "verify") {
		t.Errorf("top-level --help should list 'verify'; got:\n%s", stdout)
	}
}

// TestRunVerify_RejectsPathTraversal locks the C-060 security
// review P0 finding: an envelope whose signing_key_id contains
// path-traversal characters MUST be rejected before being joined
// into the trust-dir filesystem path. Otherwise an attacker who
// can plant a .pub anywhere readable + craft a matching signed
// envelope (their own keypair) makes verify return 0.
//
// Concretely: signing_key_id = "../../tmp/evil" combined with
// trust-dir /etc/kensa/keys would resolve to /tmp/evil.pub.
func TestRunVerify_RejectsPathTraversal(t *testing.T) {
	trustDir, evidencePath, _ := makeVerifyFixture(t)

	// Mutate the envelope's signing_key_id to a traversal string.
	data, _ := os.ReadFile(evidencePath)
	var env api.EvidenceEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{
		"../../etc/passwd",
		"..\\windows\\system32",
		"keyid/with/slash",
		"keyid with space",
		"UPPERCASE_NOT_ALLOWED",
		"only-63-chars-long-abcdefabcdefabcdefabcdefabcdefabcdefabcdefab",
	} {
		env.SigningKeyID = payload
		mutated, _ := json.Marshal(&env)
		if err := os.WriteFile(evidencePath, mutated, 0o644); err != nil {
			t.Fatal(err)
		}

		exit := runCLI([]string{"verify", "--trust-dir", trustDir, evidencePath})
		if exit == 0 {
			t.Errorf("malformed signing_key_id %q should fail verify (got exit 0)", payload)
		}
	}
}

// TestRunVerify_RejectsEmptySigningKeyID locks the empty-id guard.
// An envelope with `signing_key_id: ""` would otherwise resolve
// to `<trustDir>/.pub` (an exotic filename). Reject explicitly.
func TestRunVerify_RejectsEmptySigningKeyID(t *testing.T) {
	trustDir, evidencePath, _ := makeVerifyFixture(t)

	data, _ := os.ReadFile(evidencePath)
	var env api.EvidenceEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.SigningKeyID = ""
	mutated, _ := json.Marshal(&env)
	if err := os.WriteFile(evidencePath, mutated, 0o644); err != nil {
		t.Fatal(err)
	}

	exit := runCLI([]string{"verify", "--trust-dir", trustDir, evidencePath})
	if exit != 1 {
		t.Errorf("empty signing_key_id should exit 1; got %d", exit)
	}
}

// TestRunVerify_RejectsSymlinkInTrustDir locks the symlink-
// rejection guard: even if signing_key_id is a valid 64-char hex,
// if the matching .pub in the trust dir is a symlink, refuse.
// Otherwise an attacker who can write into the trust dir can
// plant a symlink at <hash>.pub pointing at a public key they
// control elsewhere on disk.
func TestRunVerify_RejectsSymlinkInTrustDir(t *testing.T) {
	trustDir, evidencePath, keyID := makeVerifyFixture(t)

	// Replace the .pub with a symlink to itself in /tmp.
	pubPath := filepath.Join(trustDir, keyID+".pub")
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	otherDir := t.TempDir()
	otherPub := filepath.Join(otherDir, "real.pub")
	if err := os.WriteFile(otherPub, pubData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pubPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(otherPub, pubPath); err != nil {
		t.Fatal(err)
	}

	exit := runCLI([]string{"verify", "--trust-dir", trustDir, evidencePath})
	if exit != 1 {
		t.Errorf("symlinked .pub in trust dir should exit 1; got %d", exit)
	}
}
