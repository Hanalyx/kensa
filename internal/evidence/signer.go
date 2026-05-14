// Package evidence implements the Ed25519 signing and verification
// contract for Kensa evidence envelopes as specified in
// specs/evidence/envelope.spec.yaml.
//
// # Canonicalization
//
// The canonical bytes are produced by:
//
//  1. Building a struct of every signable field (every field of
//     api.EvidenceEnvelope EXCEPT Signature and SigningKeyID per
//     spec C-02 — INCLUDING the Severity field, peer-review-
//     caught regression).
//  2. Marshaling that struct to JSON.
//  3. Round-tripping through map[string]any to force alphabetical
//     key order (spec C-01: "JSON serialization uses sorted keys").
//     The struct's declaration order is operator-readable but is
//     NOT the canonical order; the round-trip is what makes the
//     bytes spec-conforming and reproducible across languages.
//
// Timestamps serialize as RFC3339 with nanosecond precision in UTC.
// Sub-second precision matters because the engine writes
// time.Now() (nanos) into envelope timestamps; truncating to
// seconds in the canonicalizer would break verify after a
// SQLite round-trip that preserves nanos.
//
// Nil slices are normalized to empty slices so `null` never
// appears in the canonical form.
//
// # Domain separation
//
// The signed bytes are NOT raw canonical JSON — they're prefixed
// with a fixed domain tag (sigDomainTag) so an attacker who
// tricks an operator into signing some non-envelope payload with
// the same key cannot replay that signature as a "valid" envelope.
// Standard cryptographic practice; absence flagged in peer review.
//
// # Key identity
//
// A key ID is the lower-hex SHA-256 of the raw Ed25519 public key bytes.
// The 32-byte raw encoding (as returned by ed25519.PublicKey) is used as
// input, not the DER/PEM wrapper.
//
// # Rotation
//
// [Signer] holds a list of rotated public keys, ordered chronologically
// (oldest first by convention; callers append new rotations to the end).
// Verification tries the current key first, then each rotated key in
// REVERSE chronological order (newest rotation first) per spec C-04. A
// match on a rotated key returns [api.KeyRotation] in the warning list.
//
// A match where envelope.SigningKeyID disagrees with the matched key's
// id returns an additional warning so downstream tools surface the
// inconsistency.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// sigDomainTag is the fixed prefix prepended to canonical envelope
// bytes before Ed25519 signing. Cross-protocol replay defense per
// peer review: without this, an attacker who tricks an operator
// into signing some non-envelope payload with the same key could
// later replay that signature as a "valid" evidence envelope.
//
// The trailing NUL byte makes the tag self-delimiting against any
// canonical content that happens to start with the same prefix —
// canonical JSON starts with `{`, never `\x00`, so the boundary
// is unambiguous.
//
// MUST be cross-language stable. Python / OpenWatch implementations
// of the verifier MUST use the same exact bytes.
var sigDomainTag = []byte("kensa-evidence-envelope-v1\x00")

// Signer implements engine.Signer with a live Ed25519 private key
// (sign + verify) OR a public-only verifier (verify only, returned
// by [LoadVerifier]). Construct with [New] / [Generate] / [LoadSigner]
// for the full sign+verify form, or [LoadVerifier] for verify-only.
//
// The privateKey field is nil iff the Signer is verify-only.
// The publicKey field is always populated — derived from
// privateKey at construction time (full form) or supplied
// directly (verify-only form) — so Verify() never needs to ask
// the private key for its public half.
type Signer struct {
	privateKey ed25519.PrivateKey // nil when verify-only
	publicKey  ed25519.PublicKey  // ALWAYS populated
	keyID      string
	// rotationHistory holds public keys from previous key pairs, tried
	// in reverse-chronological order during verification after the
	// current key fails (per spec C-04).
	rotationHistory []ed25519.PublicKey
}

// New returns a Signer for the given Ed25519 private key.
// The key ID is derived as the lower-hex SHA-256 of the public key bytes.
func New(privateKey ed25519.PrivateKey) *Signer {
	pub := privateKey.Public().(ed25519.PublicKey)
	return &Signer{
		privateKey: privateKey,
		publicKey:  pub,
		keyID:      computeKeyID(pub),
	}
}

// NewVerifier returns a verify-only Signer wrapping pub. Sign()
// on the returned signer fails with a clear error; Verify()
// works against this public key as the active key. Used by
// [LoadVerifier] for the auditor workflow where only the .pub
// file is available.
func NewVerifier(pub ed25519.PublicKey) *Signer {
	return &Signer{
		privateKey: nil,
		publicKey:  pub,
		keyID:      computeKeyID(pub),
	}
}

// Generate creates a random Ed25519 key pair and returns a Signer backed
// by it. Suitable for development and single-node deployments; production
// deployments should manage key material via kensa-keygen and load the
// key with [New].
func Generate() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("evidence: generate key: %w", err)
	}
	return New(priv), nil
}

// WithRotationHistory appends oldPubs to the signer's rotation history.
// During verification, if the current key does not match, each oldPub is
// tried in order; a match returns [api.KeyRotation] in the warnings list.
func (s *Signer) WithRotationHistory(oldPubs ...ed25519.PublicKey) *Signer {
	s.rotationHistory = append(s.rotationHistory, oldPubs...)
	return s
}

// signedBytes returns the bytes that ed25519.Sign / ed25519.Verify
// operate on for a given envelope. Combines the domain-separation
// tag with the canonical JSON so signatures cannot replay across
// protocols. Cross-language verifiers MUST construct these bytes
// identically (sigDomainTag, then canonical JSON).
func signedBytes(envelope *api.EvidenceEnvelope) ([]byte, error) {
	canonical, err := canonicalize(envelope)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(sigDomainTag)+len(canonical))
	out = append(out, sigDomainTag...)
	out = append(out, canonical...)
	return out, nil
}

// Sign canonicalizes envelope (excluding Signature and SigningKeyID),
// prepends the domain-separation tag, signs the resulting bytes
// with the Ed25519 private key, and returns the 64-byte signature
// and the key ID.
//
// Failure modes:
//   - verify-only signer (no private key) → typed error
//   - canonicalize error (JSON marshaling failure) → wrapped error
func (s *Signer) Sign(envelope *api.EvidenceEnvelope) ([]byte, string, error) {
	// @spec evidence-envelope
	// @ac AC-03
	if s.privateKey == nil {
		return nil, "", errors.New("evidence: Sign: verify-only signer has no private key (load via LoadSigner, not LoadVerifier)")
	}
	bytes, err := signedBytes(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("evidence: canonicalize: %w", err)
	}
	sig := ed25519.Sign(s.privateKey, bytes)
	return sig, s.keyID, nil
}

// Verify canonicalizes envelope, tries the current public key, then the
// rotation history (newest rotation first). Returns:
//   - Valid=true when any key matches.
//   - [api.KeyRotation] warning when a rotated key matched.
//   - Valid=false with a typed error when no key matched.
//
// Verify is side-effect free (evidence-envelope spec C-05).
//
// Pre-checks (fail-closed before touching keys):
//   - SchemaVersion: empty or unknown → error.
//   - Signature length: must be exactly ed25519.SignatureSize.
//
// Post-match consistency:
//   - If envelope.SigningKeyID is non-empty AND disagrees with the
//     matched key's id, add KeyIDMismatch to the warnings list.
//     Doesn't fail the verification — the matched key signed the
//     bytes, which is the security-load-bearing fact — but
//     downstream consumers should surface the inconsistency.
//
// Failure modes:
//   - canonicalize error → error returned, result nil.
//   - no matching key → non-nil result with Valid=false, non-nil error.
func (s *Signer) Verify(envelope *api.EvidenceEnvelope) (*api.VerifyResult, error) {
	// @spec evidence-envelope
	// @ac AC-04 AC-05 AC-09
	if envelope.SchemaVersion == "" {
		return nil, errors.New("evidence: envelope missing schema_version")
	}
	if envelope.SchemaVersion != "v1" {
		return nil, fmt.Errorf("evidence: unknown schema_version %q; verifier only understands v1", envelope.SchemaVersion)
	}
	// Defensive length pre-check. Stdlib ed25519.Verify also rejects
	// wrong-size signatures cleanly, but pre-checking here makes the
	// contract explicit and avoids per-key timing differences when
	// walking the rotation history.
	if len(envelope.Signature) != ed25519.SignatureSize {
		return &api.VerifyResult{
				Valid:    false,
				KeyID:    envelope.SigningKeyID,
				SignedAt: envelope.FinishedAt,
			},
			fmt.Errorf("evidence: signature wrong length (got %d, want %d)",
				len(envelope.Signature), ed25519.SignatureSize)
	}

	bytes, err := signedBytes(envelope)
	if err != nil {
		return nil, fmt.Errorf("evidence: canonicalize: %w", err)
	}

	canonical, _ := canonicalize(envelope)
	hash := sha256.Sum256(canonical)
	pub := s.publicKey

	// Helper builds the success result + an optional KeyIDMismatch
	// warning when envelope.SigningKeyID disagrees with the actual
	// matched key.
	buildResult := func(matchedKeyID string, rotated bool) *api.VerifyResult {
		var warnings []api.VerifyWarning
		if rotated {
			warnings = append(warnings, api.KeyRotation)
		}
		if envelope.SigningKeyID != "" && envelope.SigningKeyID != matchedKeyID {
			warnings = append(warnings, api.KeyIDMismatch)
		}
		return &api.VerifyResult{
			Valid:        true,
			KeyID:        matchedKeyID,
			SignedAt:     envelope.FinishedAt,
			Warnings:     warnings,
			EnvelopeHash: hash,
		}
	}

	// Try current key first.
	if ed25519.Verify(pub, bytes, envelope.Signature) {
		return buildResult(s.keyID, false), nil
	}

	// Try rotation history in REVERSE chronological order
	// (newest rotation first per spec C-04). Callers append new
	// rotations to the end via WithRotationHistory; iterating
	// backward means the most-recently-rotated key is tried
	// before older entries.
	for i := len(s.rotationHistory) - 1; i >= 0; i-- {
		oldPub := s.rotationHistory[i]
		if ed25519.Verify(oldPub, bytes, envelope.Signature) {
			return buildResult(computeKeyID(oldPub), true), nil
		}
	}

	// @ac AC-05
	return &api.VerifyResult{
		Valid:        false,
		EnvelopeHash: hash,
	}, errors.New("evidence: signature does not match any known key")
}

// VerifyEnvelope implements [api.EnvelopeVerifier]. It delegates to
// [Signer.Verify] so the same signer satisfies both engine.Signer and
// api.EnvelopeVerifier without duplicating logic.
func (s *Signer) VerifyEnvelope(envelope *api.EvidenceEnvelope) (*api.VerifyResult, error) {
	return s.Verify(envelope)
}

// Public returns the Ed25519 public key for this signer. Works on
// both full sign+verify signers (cached from privateKey at New)
// and verify-only signers (set explicitly by NewVerifier).
func (s *Signer) Public() ed25519.PublicKey {
	return s.publicKey
}

// KeyID returns the signer's key identifier (lower-hex SHA-256 of the
// public key bytes).
func (s *Signer) KeyID() string { return s.keyID }

// envelopeCanonical is the shape that is serialized for signing.
// Contains every field of api.EvidenceEnvelope EXCEPT Signature
// and SigningKeyID per spec C-02. Severity is INCLUDED — peer
// review caught its prior omission as a silent forgery vector
// (an attacker mutating severity on disk would still pass
// verification).
//
// Field declaration order is operator-readable; the canonical
// bytes are produced by canonicalize() via a map[string]any
// round-trip that sorts keys alphabetically per spec C-01. The
// struct order here is irrelevant to the canonical form.
type envelopeCanonical struct {
	SchemaVersion    string                `json:"schema_version"`
	TransactionID    uuid.UUID             `json:"transaction_id"`
	RuleID           string                `json:"rule_id"`
	HostID           string                `json:"host_id"`
	FleetID          string                `json:"fleet_id,omitempty"`
	Severity         string                `json:"severity,omitempty"`
	StartedAt        string                `json:"started_at"`
	FinishedAt       string                `json:"finished_at"`
	PreStateBundle   []api.PreState        `json:"pre_state_bundle"`
	ApplySteps       []api.StepResult      `json:"apply_steps"`
	ValidatorResults []api.ValidatorResult `json:"validator_results"`
	Decision         api.TransactionStatus `json:"decision"`
	PostStateBundle  []api.PreState        `json:"post_state_bundle"`
	FrameworkRefs    []api.FrameworkRef    `json:"framework_refs"`
}

// canonicalize returns the canonical JSON bytes of envelope per
// spec C-01: alphabetically-sorted keys, nanosecond-precision UTC
// RFC3339 timestamps, no `null` values for nil slices, and
// Signature + SigningKeyID excluded.
//
// The sort step is a marshal → unmarshal-as-map → re-marshal
// round-trip. Go's encoding/json sorts map keys when encoding;
// re-marshaling forces alphabetical order regardless of the
// originating struct's declared order. Cross-language
// implementations following the spec literally produce identical
// bytes — confirmed by Python's json.dumps(d, sort_keys=True).
//
// Cost: roughly 2x the raw marshal time. Negligible vs the SSH
// RTT that dominates per-transaction overhead.
func canonicalize(envelope *api.EvidenceEnvelope) ([]byte, error) {
	c := envelopeCanonical{
		SchemaVersion: envelope.SchemaVersion,
		TransactionID: envelope.TransactionID,
		RuleID:        envelope.RuleID,
		HostID:        envelope.HostID,
		FleetID:       envelope.FleetID,
		Severity:      envelope.Severity,
		// Nanosecond precision so SQLite / engine writes (which
		// use time.Now()) round-trip cleanly. Truncating to
		// seconds here would create cross-language verify
		// mismatches when on-disk JSON carries .123456789.
		StartedAt:  envelope.StartedAt.UTC().Format(time.RFC3339Nano),
		FinishedAt: envelope.FinishedAt.UTC().Format(time.RFC3339Nano),
		// Normalize nil → empty to ensure `null` never appears.
		PreStateBundle:   coalescePreStates(envelope.PreStateBundle),
		ApplySteps:       coalesceStepResults(envelope.ApplySteps),
		ValidatorResults: coalesceValidatorResults(envelope.ValidatorResults),
		Decision:         envelope.Decision,
		PostStateBundle:  coalescePreStates(envelope.PostStateBundle),
		FrameworkRefs:    coalesceFrameworkRefs(envelope.FrameworkRefs),
	}
	first, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("first marshal: %w", err)
	}
	// CRITICAL: use json.Decoder.UseNumber() on the intermediate
	// unmarshal. Without it, encoding/json decodes every JSON
	// number as float64, silently truncating any integer > 2^53
	// (epoch-nanosecond timestamps, 64-bit inodes, etc.). A
	// cross-language verifier (Python kensa, OpenWatch) that
	// preserves integer precision would compute different
	// canonical bytes and fail to verify an otherwise-authentic
	// envelope. UseNumber() decodes numbers into json.Number
	// (a string-backed wrapper) so the re-marshal emits them
	// back as the same digits — no precision loss. Caught by
	// post-merge security verification audit.
	dec := json.NewDecoder(bytes.NewReader(first))
	dec.UseNumber()
	var asMap map[string]any
	if err := dec.Decode(&asMap); err != nil {
		return nil, fmt.Errorf("intermediate unmarshal: %w", err)
	}
	canonical, err := json.Marshal(asMap)
	if err != nil {
		return nil, fmt.Errorf("re-marshal: %w", err)
	}
	return canonical, nil
}

func coalescePreStates(s []api.PreState) []api.PreState {
	if s == nil {
		return []api.PreState{}
	}
	return s
}

func coalesceStepResults(s []api.StepResult) []api.StepResult {
	if s == nil {
		return []api.StepResult{}
	}
	return s
}

func coalesceValidatorResults(s []api.ValidatorResult) []api.ValidatorResult {
	if s == nil {
		return []api.ValidatorResult{}
	}
	return s
}

func coalesceFrameworkRefs(s []api.FrameworkRef) []api.FrameworkRef {
	if s == nil {
		return []api.FrameworkRef{}
	}
	return s
}

// computeKeyID returns the lower-hex SHA-256 of the raw public key bytes.
func computeKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// Compile-time assertions: *Signer satisfies the engine.Signer interface
// (Sign/Verify) and api.EnvelopeVerifier interface.
var _ interface {
	Sign(*api.EvidenceEnvelope) ([]byte, string, error)
	Verify(*api.EvidenceEnvelope) (*api.VerifyResult, error)
} = (*Signer)(nil)

var _ api.EnvelopeVerifier = (*Signer)(nil)
