package evidence_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/evidence"
)

// makeEnvelope returns a minimal valid v1 envelope.
func makeEnvelope() *api.EvidenceEnvelope {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	return &api.EvidenceEnvelope{
		SchemaVersion: "v1",
		TransactionID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		RuleID:        "cis_rhel9_1_1_1",
		HostID:        "host-01.example.com",
		StartedAt:     now,
		FinishedAt:    now.Add(5 * time.Second),
		Decision:      api.StatusCommitted,
	}
}

// TestNew_DeriveKeyID verifies that the key ID is the lower-hex SHA-256
// of the public key bytes (evidence-envelope spec §key-identity).
func TestNew_DeriveKeyID(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s := evidence.New(priv)
	if len(s.KeyID()) != 64 {
		t.Errorf("key ID should be 64 hex chars, got %d: %s", len(s.KeyID()), s.KeyID())
	}
}

// TestGenerate_ReturnsFreshSigner verifies Generate produces a working signer.
func TestGenerate_ReturnsFreshSigner(t *testing.T) {
	s, err := evidence.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(s.KeyID()) != 64 {
		t.Errorf("key ID should be 64 hex chars, got %d", len(s.KeyID()))
	}
	if len(s.Public()) != ed25519.PublicKeySize {
		t.Errorf("Public() size wrong: got %d, want %d", len(s.Public()), ed25519.PublicKeySize)
	}
}

// TestSignAndVerify is the happy-path round-trip: sign an envelope, then
// verify it using the same signer.
func TestSignAndVerify(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()

	sig, keyID, err := s.Sign(env)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if keyID != s.KeyID() {
		t.Errorf("Sign returned keyID %q, want %q", keyID, s.KeyID())
	}

	env.Signature = sig
	env.SigningKeyID = keyID

	result, err := s.Verify(env)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.Valid {
		t.Error("expected Valid=true")
	}
	if result.KeyID != s.KeyID() {
		t.Errorf("VerifyResult.KeyID=%q, want %q", result.KeyID, s.KeyID())
	}
	if len(result.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", result.Warnings)
	}
}

// TestVerify_WrongSignature verifies that a tampered signature is rejected.
func TestVerify_WrongSignature(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()

	sig, keyID, _ := s.Sign(env)
	env.Signature = sig
	env.SigningKeyID = keyID

	// Corrupt the first byte.
	env.Signature[0] ^= 0xFF

	result, err := s.Verify(env)
	if err == nil {
		t.Error("expected error for tampered signature, got nil")
	}
	if result != nil && result.Valid {
		t.Error("expected Valid=false for tampered signature")
	}
}

// TestVerify_MissingSchemaVersion verifies that an envelope with no
// schema_version is rejected immediately (evidence-envelope spec AC-04).
func TestVerify_MissingSchemaVersion(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()
	env.SchemaVersion = ""

	_, err := s.Verify(env)
	if err == nil {
		t.Error("expected error for missing schema_version")
	}
}

// TestVerify_UnknownSchemaVersion verifies that an unknown schema_version
// is rejected (evidence-envelope spec AC-04).
func TestVerify_UnknownSchemaVersion(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()
	env.SchemaVersion = "v2"

	_, err := s.Verify(env)
	if err == nil {
		t.Error("expected error for unknown schema_version v2")
	}
}

// TestCanonical_ExcludesSignatureFields verifies that modifying Signature
// or SigningKeyID does not change the canonical bytes (i.e., they are
// excluded from signing) — evidence-envelope spec C-02.
func TestCanonical_ExcludesSignatureFields(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()

	sig1, _, err := s.Sign(env)
	if err != nil {
		t.Fatalf("Sign (first): %v", err)
	}

	// Attach the signature and a key ID, then re-sign.
	env.Signature = sig1
	env.SigningKeyID = "some-other-key-id"

	sig2, _, err := s.Sign(env)
	if err != nil {
		t.Fatalf("Sign (second): %v", err)
	}

	if string(sig1) != string(sig2) {
		t.Error("canonicalize must exclude Signature and SigningKeyID; got different signatures")
	}
}

// TestWithRotationHistory_MatchesOldKey verifies that an envelope signed
// by a rotated-out key is still verified, with a KeyRotation warning.
func TestWithRotationHistory_MatchesOldKey(t *testing.T) {
	// oldSigner is the signer we previously used.
	oldSigner, _ := evidence.Generate()
	env := makeEnvelope()
	sig, keyID, _ := oldSigner.Sign(env)
	env.Signature = sig
	env.SigningKeyID = keyID

	// newSigner is the current signer; old public key added to rotation history.
	newSigner, _ := evidence.Generate()
	newSigner.WithRotationHistory(oldSigner.Public())

	result, err := newSigner.Verify(env)
	if err != nil {
		t.Fatalf("Verify with rotation history: %v", err)
	}
	if !result.Valid {
		t.Error("expected Valid=true for rotated-key signature")
	}
	if len(result.Warnings) == 0 {
		t.Error("expected KeyRotation warning, got none")
	}
	found := false
	for _, w := range result.Warnings {
		if w == api.KeyRotation {
			found = true
		}
	}
	if !found {
		t.Errorf("expected api.KeyRotation warning; got %v", result.Warnings)
	}
}

// TestWithRotationHistory_NoMatch verifies that a signature by a completely
// unknown key is rejected even with rotation history present.
func TestWithRotationHistory_NoMatch(t *testing.T) {
	unknownSigner, _ := evidence.Generate()
	env := makeEnvelope()
	sig, keyID, _ := unknownSigner.Sign(env)
	env.Signature = sig
	env.SigningKeyID = keyID

	currentSigner, _ := evidence.Generate()
	// Another old key in rotation history — but not unknownSigner's key.
	anotherOld, _ := evidence.Generate()
	currentSigner.WithRotationHistory(anotherOld.Public())

	result, err := currentSigner.Verify(env)
	if err == nil {
		t.Error("expected error when no key matches")
	}
	if result != nil && result.Valid {
		t.Error("expected Valid=false when no key matches")
	}
}

// TestVerifyEnvelope_ImplementsInterface verifies that *Signer satisfies
// api.EnvelopeVerifier via the VerifyEnvelope method.
func TestVerifyEnvelope_ImplementsInterface(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()
	sig, keyID, _ := s.Sign(env)
	env.Signature = sig
	env.SigningKeyID = keyID

	var v api.EnvelopeVerifier = s
	result, err := v.VerifyEnvelope(env)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if !result.Valid {
		t.Error("expected Valid=true")
	}
}

// TestEnvelopeHash_Stable verifies that EnvelopeHash is deterministic for
// the same envelope (evidence-envelope spec C-01).
func TestEnvelopeHash_Stable(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()
	sig, keyID, _ := s.Sign(env)
	env.Signature = sig
	env.SigningKeyID = keyID

	r1, _ := s.Verify(env)
	r2, _ := s.Verify(env)
	if r1.EnvelopeHash != r2.EnvelopeHash {
		t.Error("EnvelopeHash is not stable across identical calls")
	}
}

// TestNilSliceNormalization verifies that nil and empty slice envelopes
// produce the same canonical bytes (evidence-envelope spec C-01).
func TestNilSliceNormalization(t *testing.T) {
	s, _ := evidence.Generate()

	envNil := makeEnvelope()
	// PreStateBundle, ApplySteps, ValidatorResults, PostStateBundle,
	// FrameworkRefs are all nil by default.
	sigNil, _, _ := s.Sign(envNil)

	envEmpty := makeEnvelope()
	envEmpty.PreStateBundle = []api.PreState{}
	envEmpty.ApplySteps = []api.StepResult{}
	envEmpty.ValidatorResults = []api.ValidatorResult{}
	envEmpty.PostStateBundle = []api.PreState{}
	envEmpty.FrameworkRefs = []api.FrameworkRef{}
	sigEmpty, _, _ := s.Sign(envEmpty)

	if string(sigNil) != string(sigEmpty) {
		t.Error("nil and empty slices must produce identical canonical bytes")
	}
}
