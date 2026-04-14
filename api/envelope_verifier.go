package api

import "time"

// EnvelopeVerifier verifies the authenticity of an evidence envelope.
// Called by OpenWatch's audit UI, by the kensa CLI, and by third-party
// auditor tools that import api/. Re-implementing verification on the
// OpenWatch side would duplicate trust logic and risk divergence — so
// Kensa owns this interface.
//
// Implemented by internal/evidence. Satisfies the evidence-envelope
// spec (specs/evidence/envelope.spec.yaml) AC-04 through AC-06.
type EnvelopeVerifier interface {
	// VerifyEnvelope checks the signature against the deployment's
	// registered keys and their rotation history. Side-effect free
	// (evidence-envelope spec C-05): no log writes, no event emission,
	// no state mutation.
	//
	// Returns VerifyResult{Valid: true} on signature match with the
	// current key. Returns Valid: true with a KeyRotation warning on
	// match against a rotated key from the history. Returns
	// Valid: false with a specific error for unknown signers or
	// unknown schema versions (fail-closed).
	VerifyEnvelope(envelope *EvidenceEnvelope) (*VerifyResult, error)
}

// VerifyResult is the structured response from VerifyEnvelope.
type VerifyResult struct {
	Valid        bool
	KeyID        string    // Which public key matched
	SignedAt     time.Time // Per the envelope's FinishedAt
	Warnings     []VerifyWarning
	EnvelopeHash [32]byte // For audit trail cross-reference
}

// VerifyWarning names a non-fatal condition observed during verification.
type VerifyWarning string

const (
	// KeyRotation: the signature matched a key in the rotation history,
	// not the currently active key. The envelope is authentic but was
	// signed by an older key.
	KeyRotation VerifyWarning = "signed_by_rotated_key"

	// ClockSkew: the envelope's SignedAt timestamp is significantly
	// later than the verification time. May indicate a forward-dated
	// envelope or a clock-sync issue.
	ClockSkew VerifyWarning = "clock_skew_detected"
)
