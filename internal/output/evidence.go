package output

import (
	"encoding/json"
	"io"

	"github.com/Hanalyx/kensa-go/api"
)

// evidenceRemediationWriter renders a RemediationResult as a stream
// of EvidenceEnvelope JSON documents — one per transaction with a
// non-nil Envelope. Transactions without an envelope (the engine
// could not produce one — e.g., a non-capturable rule that errored
// before the commit phase) are skipped.
//
// Each envelope is emitted as a complete JSON object on its own.
// Output is the concatenation of N documents with no separator,
// parseable as a JSON stream via json.Decoder.More.
//
// Why per-envelope concatenated rather than one wrapper object:
// each EvidenceEnvelope is a signed unit (post-M7 task #12 it
// carries an Ed25519 signature over its canonical-form payload).
// Wrapping N envelopes inside an outer `{envelopes: [...]}` object
// would create an unsigned outer layer; consumers verifying the
// chain would have to unwrap before checking any signature. Keeping
// each envelope at the JSON document root preserves the property
// that every byte range delimited by document boundaries is itself
// a signed evidence unit.
//
// IMPORTANT: M7 task #12 (M-012) shipped 2026-05-10 with real
// Ed25519 signatures. C-060 wired the signer through every
// engine call site that writes EvidenceEnvelope.Signature.
// Signatures are now 64-byte ed25519 over canonical bytes
// per spec C-02. Operators verify via `kensa verify
// <evidence-file>`.
//
// Wire-form vs signing-canonical-form: the indented JSON output is
// optimized for human readability. It is NOT the canonical form
// over which the Ed25519 signer computes signatures. Verifiers
// post-M7 must re-canonicalize per the documented algorithm in
// internal/evidence/signer.go before checking any signature; the
// canonicalization step strips formatting (whitespace, indent,
// key ordering) so the indented wire form and the compact signing
// form converge to the same bytes for verification.
//
// Evidence applies only to RemediationResult, not ScanResult: scan
// is read-only and produces no envelopes today. If a future kensa
// adds signed-scan-record envelopes, registering this writer for
// ScanResult is straightforward — the loop body is shape-identical.
type evidenceRemediationWriter struct{}

func (evidenceRemediationWriter) Format() string { return "evidence" }

// WriteRemediationResult emits one indented JSON document per non-
// nil envelope.
//
// hostID and rules are interface-mandated but INTENTIONALLY UNUSED.
// The threat is stronger than the OSCAL writer's: there, sourcing
// identity from outer params produces a derived view that disagrees
// with the signed source-of-truth (recoverable by re-deriving). For
// evidence the document IS the signed payload — overwriting
// envelope fields from outer params would produce bytes no longer
// verifiable as the signed audit-truth-of-record (signature-
// invalidation, not just substitution). envelope.HostID /
// envelope.RuleID / envelope.FrameworkRefs are the only correct
// identity sources.
func (evidenceRemediationWriter) WriteRemediationResult(w io.Writer, _ string, _ []*api.Rule, result *api.RemediationResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	for _, txr := range result.Transactions {
		if txr.Envelope == nil {
			continue
		}
		if err := enc.Encode(txr.Envelope); err != nil {
			return err
		}
	}
	return nil
}

// Compile-time interface assertion.
var _ RemediationResultWriter = evidenceRemediationWriter{}
