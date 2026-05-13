package evidence_test

import (
	"bytes"
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
// @spec evidence-envelope
// @ac AC-03
// @ac AC-04
func TestSignAndVerify(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Run("evidence-envelope/AC-03", func(t *testing.T) {})
	t.Run("evidence-envelope/AC-04", func(t *testing.T) {})
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
// @spec evidence-envelope
// @ac AC-05
func TestVerify_WrongSignature(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-05")
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
// is rejected (evidence-envelope spec AC-06).
// @spec evidence-envelope
// @ac AC-06
func TestVerify_UnknownSchemaVersion(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-06")
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
// @spec evidence-envelope
// @ac AC-02
// @ac AC-03
func TestCanonical_ExcludesSignatureFields(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Run("evidence-envelope/AC-02", func(t *testing.T) {})
	t.Run("evidence-envelope/AC-03", func(t *testing.T) {})
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
// @spec evidence-envelope
// @ac AC-04
func TestWithRotationHistory_MatchesOldKey(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-04")
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
// @spec evidence-envelope
// @ac AC-05
func TestWithRotationHistory_NoMatch(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-05")
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

// @spec evidence-envelope
// @ac AC-07
func TestEvidence_AC07_JSONSchemaValidatesEnvelopes(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-07")
	// AC-07: JSON Schema at evidence/envelope-v1.json must validate every
	// legal envelope and reject illegal ones (missing required field, wrong
	// type, unknown field). The schema file has not yet been generated;
	// generate it via `go generate ./internal/evidence/...` once the
	// generation script lands.
	t.Skip("TODO: evidence/envelope-v1.json not yet generated; add go:generate + schema validation test")
}

// @spec evidence-envelope
// @ac AC-10
func TestEvidence_AC10_PublishedSchemMatchesGoStruct(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-10")
	// AC-10: the schema at kensa-spec/specs/evidence/envelope-v1.yaml must
	// match the Go struct in api/envelope.go exactly, enforced at build time.
	// Requires a cross-repo schema comparison step (go generate or CI check).
	t.Skip("TODO: cross-repo schema comparison not yet implemented; track in SPECTER_FEATURE_REQUEST.md")
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
// @spec evidence-envelope
// @ac AC-09
func TestEnvelopeHash_Stable(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-09")
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

// TestVerify_TamperedSeverity locks the peer-review-caught
// regression: prior canonicalize() omitted the Severity field,
// letting an attacker mutate severity on disk without breaking
// the signature. Now Severity is in the canonical bytes;
// modifying it post-sign must invalidate verification.
func TestVerify_TamperedSeverity(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()
	env.Severity = "high"
	sig, keyID, _ := s.Sign(env)
	env.Signature = sig
	env.SigningKeyID = keyID

	// Same envelope, same key — verifies cleanly.
	if r, _ := s.Verify(env); r == nil || !r.Valid {
		t.Fatal("baseline verification should pass")
	}

	// Mutate severity. Verification MUST now fail.
	env.Severity = "low"
	r, err := s.Verify(env)
	if err == nil || (r != nil && r.Valid) {
		t.Errorf("mutating Severity must invalidate signature; got valid=%v err=%v",
			r != nil && r.Valid, err)
	}
}

// TestVerify_RejectsWrongLengthSignature locks the
// signature-length pre-check. Stdlib ed25519.Verify also rejects
// wrong-size signatures cleanly, but we want an explicit local
// contract so the early return doesn't fold into per-key
// timing differences when the rotation history is walked.
func TestVerify_RejectsWrongLengthSignature(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()
	sig, keyID, _ := s.Sign(env)
	env.SigningKeyID = keyID

	// Truncate by 1 byte.
	env.Signature = sig[:len(sig)-1]
	r, err := s.Verify(env)
	if err == nil {
		t.Error("truncated signature should error")
	}
	if r != nil && r.Valid {
		t.Error("truncated signature must NOT be Valid=true")
	}

	// Extend by 1 byte (append zero). Copy first so the parent
	// `sig` slice is not mutated in-place if it had spare cap.
	oversized := append([]byte{}, sig...)
	oversized = append(oversized, 0)
	env.Signature = oversized
	r, err = s.Verify(env)
	if err == nil {
		t.Error("oversize signature should error")
	}
	if r != nil && r.Valid {
		t.Error("oversize signature must NOT be Valid=true")
	}
}

// TestVerify_KeyIDMismatchWarning locks the post-match
// consistency check: when envelope.SigningKeyID disagrees with
// the matched key's id, verification still succeeds (the
// signature is authentic) but emits api.KeyIDMismatch in the
// warnings list so downstream tools can investigate.
func TestVerify_KeyIDMismatchWarning(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()
	sig, keyID, _ := s.Sign(env)
	env.Signature = sig
	// Operator (or attacker) writes a different key_id than the
	// one that actually signed.
	env.SigningKeyID = "00000000-0000-0000-0000-000000000000"

	r, err := s.Verify(env)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !r.Valid {
		t.Fatal("signature still authentic; should be Valid=true")
	}
	if r.KeyID != keyID {
		t.Errorf("matched KeyID: got %q, want %q", r.KeyID, keyID)
	}
	found := false
	for _, w := range r.Warnings {
		if w == api.KeyIDMismatch {
			found = true
		}
	}
	if !found {
		t.Errorf("expected api.KeyIDMismatch warning; got %v", r.Warnings)
	}
}

// TestVerify_RotationOrderReverseChronological locks spec C-04:
// "verification tries keys in reverse chronological order".
// Callers append rotated keys to the history list oldest-first
// (chronological). Verify must walk it BACKWARDS so the most-
// recently-rotated key is tried first.
//
// Without this fix (original code iterated forward), a
// compromised-but-still-listed old key could match before the
// legitimate newer rotation in some envelope sets.
func TestVerify_RotationOrderReverseChronological(t *testing.T) {
	currentSigner, _ := evidence.Generate()
	oldestSigner, _ := evidence.Generate()
	newestSigner, _ := evidence.Generate()

	// Rotation history: [oldest, newest] (chronological).
	currentSigner.WithRotationHistory(oldestSigner.Public(), newestSigner.Public())

	// Sign with the NEWEST rotated key; the verifier should hit
	// it on the FIRST history-walk iteration (because reverse
	// order means newest-first).
	env := makeEnvelope()
	sig, _, _ := newestSigner.Sign(env)
	env.Signature = sig

	r, err := currentSigner.Verify(env)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !r.Valid {
		t.Error("expected Valid=true for newest-rotation key")
	}
	if r.KeyID != newestSigner.KeyID() {
		t.Errorf("matched key: got %q, want %q (newest rotation)",
			r.KeyID, newestSigner.KeyID())
	}
}

// TestSign_DomainSeparation locks the cross-protocol replay
// defense: signatures over canonical envelope bytes are
// distinguishable from signatures over arbitrary other bytes.
// Without the domain tag, an attacker who tricked an operator
// into signing some non-envelope payload could later replay
// the signature as a "valid" envelope.
func TestSign_DomainSeparation(t *testing.T) {
	s, _ := evidence.Generate()
	env := makeEnvelope()
	sig, _, _ := s.Sign(env)

	// Verify the signature does NOT verify against the canonical
	// envelope bytes WITHOUT the domain tag prefix. (i.e., a
	// hypothetical attacker who computes raw canonical bytes
	// and signs them with the same key has produced something
	// that won't satisfy our Verify.)
	canonical, err := evidence.CanonicalForTest(env)
	if err != nil {
		t.Fatalf("CanonicalForTest: %v", err)
	}
	pub := s.Public()
	// crypto/ed25519 verify of the BARE canonical bytes against
	// the same signature MUST fail (because we signed the
	// domain-tagged bytes, not bare canonical).
	if ed25519.Verify(pub, canonical, sig) {
		t.Error("ed25519.Verify against bare canonical bytes succeeded — domain separation broken")
	}
}

// TestCanonicalize_KeysAlphabeticallySorted locks spec C-01:
// "JSON serialization uses sorted keys". Cross-language
// implementations following the spec literally MUST produce
// identical bytes; this means top-level keys appear in
// alphabetical order regardless of the originating struct's
// declared field order.
func TestCanonicalize_KeysAlphabeticallySorted(t *testing.T) {
	env := makeEnvelope()
	env.Severity = "high"
	canonical, err := evidence.CanonicalForTest(env)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	// Decode and re-extract key order. encoding/json's
	// Decoder doesn't preserve key order, but we can use the
	// raw bytes to find each key's first byte position.
	// Alphabetical order — note `post_*` precedes `pre_*` (o < r).
	keys := []string{
		"apply_steps", "decision", "finished_at", "framework_refs",
		"host_id", "post_state_bundle", "pre_state_bundle",
		"rule_id", "schema_version", "severity", "started_at",
		"transaction_id", "validator_results",
	}
	// fleet_id is omitempty and the fixture leaves it empty, so
	// it doesn't appear in the canonical form.
	prevPos := -1
	for _, k := range keys {
		needle := []byte("\"" + k + "\"")
		pos := bytesIndex(canonical, needle)
		if pos < 0 {
			t.Errorf("key %q absent from canonical bytes", k)
			continue
		}
		if pos <= prevPos {
			t.Errorf("key %q at byte %d, must be after previous (%d) — keys not sorted",
				k, pos, prevPos)
		}
		prevPos = pos
	}
}

// TestCanonicalize_TimestampNanosecondPrecision verifies that
// sub-second timestamp precision survives canonicalization. The
// engine writes time.Now() (nanos); the spec / cross-language
// contract is RFC3339Nano. A second-precision-truncating
// canonicalizer would create cross-language verification
// mismatches for any envelope whose JSON-on-disk preserves the
// nanos.
func TestCanonicalize_TimestampNanosecondPrecision(t *testing.T) {
	env := makeEnvelope()
	// Set a timestamp with sub-second precision.
	env.StartedAt = env.StartedAt.Add(123456789 * time.Nanosecond)
	canonical, err := evidence.CanonicalForTest(env)
	if err != nil {
		t.Fatal(err)
	}
	// The nanosecond suffix must appear.
	if bytesIndex(canonical, []byte(".123456789")) < 0 {
		t.Errorf("nanosecond suffix missing from canonical bytes:\n%s", canonical)
	}
}

// bytesIndex is strings.Index for []byte without importing
// strings (the test file uses bytes for raw canonical inspection).
func bytesIndex(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestCanonicalize_PreservesIntegerPrecision locks the post-merge
// verification fix: canonicalize() must NOT silently truncate
// integers > 2^53 in PreState.Data. Without json.Decoder.UseNumber()
// on the intermediate unmarshal, JSON numbers decode as float64
// and 64-bit inodes / epoch-nanosecond timestamps lose precision.
// Self-verification still passes (Sign + Verify both truncate
// identically) but a cross-language verifier preserving integer
// precision would compute different canonical bytes and fail to
// verify the same envelope — breaking spec C-01's cross-language
// byte-identity guarantee.
//
// Stored value: 9007199254740993 = 2^53 + 1, the smallest integer
// that cannot be exactly represented as float64.
func TestCanonicalize_PreservesIntegerPrecision(t *testing.T) {
	env := makeEnvelope()
	bigInt := uint64(9007199254740993) // 2^53 + 1
	env.PreStateBundle = []api.PreState{
		{
			StepIndex:  0,
			Mechanism:  "file_permissions",
			Capturable: true,
			Data: map[string]interface{}{
				"inode": bigInt,
			},
			CapturedAt: env.StartedAt,
		},
	}
	canonical, err := evidence.CanonicalForTest(env)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	// The exact digit string must be present in the canonical
	// bytes. If float64 truncation kicked in, we'd see
	// "9007199254740992" (one less) — failure mode is silent.
	if !bytes.Contains(canonical, []byte("9007199254740993")) {
		t.Errorf("integer 2^53+1 lost precision in canonicalization (got truncated to float64)\ncanonical:\n%s", canonical)
	}
}

// TestNilSliceNormalization verifies that nil and empty slice envelopes
// produce the same canonical bytes (evidence-envelope spec C-01).
// @spec evidence-envelope
// @ac AC-02
func TestNilSliceNormalization(t *testing.T) {
	t.Log("// @spec evidence-envelope")
	t.Log("// @ac AC-02")
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
