package api

import "time"

// EnvelopeVerifier verifies the authenticity of an [EvidenceEnvelope].
// OpenWatch's audit UI, the kensa CLI, and third-party auditor tools
// call this rather than reimplementing trust logic — Kensa owns the
// verification path so consumers cannot drift from the canonical
// signature contract.
//
// Spec: evidence-envelope (specs/evidence/envelope.spec.yaml) AC-04
// through AC-06.
type EnvelopeVerifier interface {
	// VerifyEnvelope checks the Ed25519 signature on envelope against
	// the deployment's registered keys and rotation history. The
	// returned [VerifyResult] reports whether the signature is valid,
	// which key matched, and any non-fatal warnings such as
	// [KeyRotation].
	//
	// VerifyEnvelope is side-effect free: no log writes, no event
	// emission, no state mutation. Callers may invoke it freely.
	VerifyEnvelope(envelope *EvidenceEnvelope) (*VerifyResult, error)
}

// VerifyResult is the structured response from
// [EnvelopeVerifier.VerifyEnvelope].
type VerifyResult struct {
	// Valid is true when the signature matched a known key.
	Valid bool
	// KeyID identifies which public key the signature matched.
	KeyID string
	// SignedAt mirrors [EvidenceEnvelope.FinishedAt] for convenience.
	SignedAt time.Time
	// Warnings names any non-fatal conditions observed during
	// verification, such as [KeyRotation].
	Warnings []VerifyWarning
	// EnvelopeHash is the SHA-256 of the canonicalized envelope, for
	// audit-trail cross-reference.
	EnvelopeHash [32]byte
}

// VerifyWarning names a non-fatal condition from
// [EnvelopeVerifier.VerifyEnvelope].
type VerifyWarning string

// Defined [VerifyWarning] values.
const (
	// KeyRotation indicates the signature matched a key in the
	// rotation history rather than the currently active key. The
	// envelope is authentic but signed by an older key.
	KeyRotation VerifyWarning = "signed_by_rotated_key"

	// ClockSkew indicates [VerifyResult.SignedAt] is significantly
	// later than the verification time. May indicate a forward-dated
	// envelope or a clock-sync issue.
	ClockSkew VerifyWarning = "clock_skew_detected"

	// KeyIDMismatch indicates the envelope's claimed
	// [EvidenceEnvelope.SigningKeyID] disagrees with the actual key
	// that produced a valid signature. The signature itself is
	// authentic — the matched key signed the bytes — but the
	// envelope's metadata is inconsistent. Downstream tools should
	// surface this so an operator can investigate why the labels
	// drifted (post-hoc edit, intentional re-tagging, etc.).
	KeyIDMismatch VerifyWarning = "signing_key_id_mismatch"
)
