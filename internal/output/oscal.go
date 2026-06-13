package output

import (
	"io"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
)

// oscalScanWriter renders a read-only ScanResult as a single OSCAL
// 1.0.6 Assessment Results document. Unlike the remediation path, the
// scan path produces no signed EvidenceEnvelope — its OSCAL is the
// unsigned compliance-verdict-plus-observation-evidence document built
// directly from ScanResult.Outcomes (one finding + observation per
// rule, with the rule's CheckEvidence embedded as relevant-evidence and
// raw stdout as base64 back-matter). This is the v0.4.0 OSCAL
// enrichment: scan results are now first-class OSCAL artifacts, not
// just remediation transactions.
//
// hostID is the observation subject (it derives the host inventory-item
// UUID inside evidence.ExportOSCALScan); rules is interface-mandated but
// unused — every verdict and its framework refs already live on
// ScanResult.Outcomes.
type oscalScanWriter struct{}

func (oscalScanWriter) Format() string { return "oscal" }

func (oscalScanWriter) WriteScanResult(w io.Writer, hostID string, _ []*api.Rule, result *api.ScanResult) error {
	return evidence.WriteOSCALScan(w, result, hostID)
}

// Compile-time interface assertion.
var _ ScanResultWriter = oscalScanWriter{}

// oscalRemediationWriter renders a RemediationResult as a stream of
// OSCAL Assessment Results documents — one per transaction with a
// non-nil EvidenceEnvelope. Transactions without an envelope (the
// engine could not produce one — e.g., a non-capturable rule that
// errored before the commit phase) are skipped.
//
// This is the remediation counterpart to oscalScanWriter: the
// remediation document is anchored on the signed EvidenceEnvelope (the
// audit-truth-of-record), whereas the scan document is the unsigned
// read-only verdict set. Both emit OSCAL 1.0.6 AR.
//
// The output is the concatenation of N JSON documents (one per
// envelope) as produced by evidence.WriteOSCAL. Strict OSCAL
// consumers expect a single root object per document; the
// concatenated stream is parseable as a JSON-NDJSON-style sequence
// (one document per line is not guaranteed since evidence.WriteOSCAL
// does not append a trailing newline). For a single-document file,
// emit a single-transaction RemediationResult.
//
// This writer is the C-016 wiring: it does not change the byte
// production logic, which still lives in internal/evidence/oscal.go.
// The wiring registers the existing logic at the standard output
// dispatch point so a future `-o oscal:foo.json` invocation goes
// through the same code path as the legacy `--oscal /foo.json`
// flag (cmd/kensa/main.go's writeOSCALFile delegates here in the
// same PR).
type oscalRemediationWriter struct{}

func (oscalRemediationWriter) Format() string { return "oscal" }

// WriteRemediationResult emits one OSCAL document per non-nil
// envelope in result.Transactions.
//
// The hostID and rules parameters are interface-mandated but
// INTENTIONALLY UNUSED: the EvidenceEnvelope is the signed
// audit-truth-of-record (post-M7 task #12 it carries an Ed25519
// signature over its payload). Sourcing host or rule identity
// from outer parameters at write time would create a replay
// vector — a malicious caller could pass a different hostID
// than what was captured at apply time, and the resulting OSCAL
// document would lie. Reading from envelope.HostID /
// envelope.RuleID / envelope.FrameworkRefs (inside
// evidence.WriteOSCAL)
// is the only correct identity source.
func (oscalRemediationWriter) WriteRemediationResult(w io.Writer, _ string, _ []*api.Rule, result *api.RemediationResult) error {
	for _, txr := range result.Transactions {
		if txr.Envelope == nil {
			continue
		}
		if err := evidence.WriteOSCAL(w, txr.Envelope); err != nil {
			return err
		}
	}
	return nil
}

// Compile-time interface assertion.
var _ RemediationResultWriter = oscalRemediationWriter{}
