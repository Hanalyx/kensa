// Package evidence implements the Ed25519 signing and verification
// contract for Kensa evidence envelopes as specified in
// specs/evidence/envelope.spec.yaml.
//
// # Canonicalization
//
// The canonical bytes are produced by serializing the envelope to JSON
// with all fields except [api.EvidenceEnvelope.Signature] and
// [api.EvidenceEnvelope.SigningKeyID]. Field order follows the
// envelopeCanonical struct declaration, which is stable across builds.
// Timestamps are serialized as RFC3339 UTC strings. Nil slices are
// normalized to empty slices so `null` never appears in the canonical form.
//
// # Key identity
//
// A key ID is the lower-hex SHA-256 of the raw Ed25519 public key bytes.
// The 32-byte raw encoding (as returned by ed25519.PublicKey) is used as
// input, not the DER/PEM wrapper.
//
// # Rotation
//
// [Signer] holds a list of rotated public keys. Verification tries the
// current key first, then each rotated key in order. A match on a
// rotated key returns [api.KeyRotation] in the warning list.
package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// Signer implements engine.Signer with a live Ed25519 private key.
// Construct with [New] (from a raw key) or [Generate] (random key pair).
type Signer struct {
	privateKey ed25519.PrivateKey
	keyID      string
	// rotationHistory holds public keys from previous key pairs, tried
	// in order during verification after the current key fails.
	rotationHistory []ed25519.PublicKey
}

// New returns a Signer for the given Ed25519 private key.
// The key ID is derived as the lower-hex SHA-256 of the public key bytes.
func New(privateKey ed25519.PrivateKey) *Signer {
	pub := privateKey.Public().(ed25519.PublicKey)
	return &Signer{
		privateKey: privateKey,
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

// Sign canonicalizes envelope (excluding Signature and SigningKeyID),
// signs the bytes with the Ed25519 private key, and returns the
// 64-byte signature and the key ID.
//
// Failure modes:
//   - canonicalize error (JSON marshaling failure) → wrapped error.
func (s *Signer) Sign(envelope *api.EvidenceEnvelope) ([]byte, string, error) {
	// @spec evidence-envelope
	// @ac AC-03
	canonical, err := canonicalize(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("evidence: canonicalize: %w", err)
	}
	sig := ed25519.Sign(s.privateKey, canonical)
	return sig, s.keyID, nil
}

// Verify canonicalizes envelope, tries the current public key, then the
// rotation history. Returns:
//   - Valid=true when any key matches.
//   - [api.KeyRotation] warning when a rotated key matched.
//   - Valid=false with a typed error when no key matched.
//
// Verify is side-effect free (evidence-envelope spec C-05).
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

	canonical, err := canonicalize(envelope)
	if err != nil {
		return nil, fmt.Errorf("evidence: canonicalize: %w", err)
	}

	hash := sha256.Sum256(canonical)
	pub := s.privateKey.Public().(ed25519.PublicKey)

	// Try current key first.
	if ed25519.Verify(pub, canonical, envelope.Signature) {
		return &api.VerifyResult{
			Valid:        true,
			KeyID:        s.keyID,
			SignedAt:     envelope.FinishedAt,
			EnvelopeHash: hash,
		}, nil
	}

	// Try rotation history.
	for _, oldPub := range s.rotationHistory {
		if ed25519.Verify(oldPub, canonical, envelope.Signature) {
			return &api.VerifyResult{
				Valid:        true,
				KeyID:        computeKeyID(oldPub),
				SignedAt:     envelope.FinishedAt,
				Warnings:     []api.VerifyWarning{api.KeyRotation},
				EnvelopeHash: hash,
			}, nil
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

// Public returns the Ed25519 public key that corresponds to this signer's
// private key. Use this to configure a verifier-only peer.
func (s *Signer) Public() ed25519.PublicKey {
	return s.privateKey.Public().(ed25519.PublicKey)
}

// KeyID returns the signer's key identifier (lower-hex SHA-256 of the
// public key bytes).
func (s *Signer) KeyID() string { return s.keyID }

// envelopeCanonical is the shape that is serialized for signing. It
// contains every field EXCEPT Signature and SigningKeyID per
// evidence-envelope spec C-02.
type envelopeCanonical struct {
	SchemaVersion    string                `json:"schema_version"`
	TransactionID    uuid.UUID             `json:"transaction_id"`
	RuleID           string                `json:"rule_id"`
	HostID           string                `json:"host_id"`
	FleetID          string                `json:"fleet_id,omitempty"`
	StartedAt        string                `json:"started_at"`
	FinishedAt       string                `json:"finished_at"`
	PreStateBundle   []api.PreState        `json:"pre_state_bundle"`
	ApplySteps       []api.StepResult      `json:"apply_steps"`
	ValidatorResults []api.ValidatorResult `json:"validator_results"`
	Decision         api.TransactionStatus `json:"decision"`
	PostStateBundle  []api.PreState        `json:"post_state_bundle"`
	FrameworkRefs    []api.FrameworkRef    `json:"framework_refs"`
}

// canonicalize returns the canonical JSON bytes of envelope, excluding the
// Signature and SigningKeyID fields. Nil slices are normalized to empty
// slices so `null` never appears in the canonical form (evidence-envelope
// spec C-01).
func canonicalize(envelope *api.EvidenceEnvelope) ([]byte, error) {
	c := envelopeCanonical{
		SchemaVersion: envelope.SchemaVersion,
		TransactionID: envelope.TransactionID,
		RuleID:        envelope.RuleID,
		HostID:        envelope.HostID,
		FleetID:       envelope.FleetID,
		StartedAt:     envelope.StartedAt.UTC().Format(time.RFC3339),
		FinishedAt:    envelope.FinishedAt.UTC().Format(time.RFC3339),
		// Normalize nil → empty to ensure `null` never appears.
		PreStateBundle:   coalescePreStates(envelope.PreStateBundle),
		ApplySteps:       coalesceStepResults(envelope.ApplySteps),
		ValidatorResults: coalesceValidatorResults(envelope.ValidatorResults),
		Decision:         envelope.Decision,
		PostStateBundle:  coalescePreStates(envelope.PostStateBundle),
		FrameworkRefs:    coalesceFrameworkRefs(envelope.FrameworkRefs),
	}
	return json.Marshal(c)
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
