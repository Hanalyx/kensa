package kensa

import (
	"io"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/evidence"
)

// ExportOSCALScan renders a read-only [api.ScanResult] as an OSCAL 1.0.6
// Assessment Results document. It is the public entry point to Kensa's
// scan-path OSCAL exporter — the byte-production logic lives in internal/ and
// cannot be imported across the module boundary, so this is how an embedder
// (e.g. OpenWatch) turns a scan into a standards-conformant compliance
// artifact. It completes the public consumer chain:
//
//	rules, _ := kensa.LoadRules(dir, nil, vars)
//	k, _    := api.New(api.Config{Scanner: kensa.NewScanner(), TransportFactory: tf})
//	res, _  := k.Scan(ctx, host, rules)
//	doc, _  := kensa.ExportOSCALScan(res, host.ID) // OSCAL 1.0.6 AR JSON
//
// Each [api.RuleOutcome] becomes one finding + observation; the rule's
// [api.CheckEvidence] is embedded as relevant-evidence (method/exit-code/
// expected as Kensa-namespaced props, the verbatim command in remarks, raw
// stdout as base64 back-matter), and framework refs render as deduplicated,
// token-valid control-ids. The output validates against the vendored NIST
// OSCAL 1.0.6 schema (a hard test gate enforces this).
//
// The scan document is UNSIGNED by design: it is derived solely from the
// read-only ScanResult, with no signer or evidence-envelope involved. The
// cryptographic signature guarantee is exclusive to the remediation path —
// see [ExportOSCAL], which is anchored on a signed [api.EvidenceEnvelope].
//
// A nil result returns an error.
func ExportOSCALScan(result *api.ScanResult, hostname string) ([]byte, error) {
	return evidence.ExportOSCALScan(result, hostname)
}

// WriteOSCALScan is [ExportOSCALScan] streamed to w instead of returning the
// bytes — for writing an OSCAL document straight to a file or HTTP response.
func WriteOSCALScan(w io.Writer, result *api.ScanResult, hostname string) error {
	return evidence.WriteOSCALScan(w, result, hostname)
}

// ExportOSCALOutcome renders a SINGLE rule outcome as its own OSCAL 1.0.6
// Assessment Results document — the per-rule counterpart of [ExportOSCALScan],
// for a UI that exports OSCAL from one expanded rule rather than the whole scan.
//
// OSCAL AR is a whole-document artifact, but the exporter is granularity-
// agnostic: a one-outcome document is a valid one-finding/one-observation AR.
// This helper exists so a caller does not hand-roll the single-outcome
// [api.ScanResult] and accidentally drop the host context — it copies HostID,
// Capabilities, and Platform from scan so the per-rule document is as
// self-describing as the whole-scan one. A nil scan is allowed (only the
// outcome and hostname are then used). The outcome is emitted even when it
// carries no FrameworkRefs: reviewed-controls falls back to OSCAL include-all,
// so an unmapped rule still produces a schema-valid document.
//
// For the whole scan, call [ExportOSCALScan] with the full result instead.
func ExportOSCALOutcome(scan *api.ScanResult, outcome api.RuleOutcome, hostname string) ([]byte, error) {
	return evidence.ExportOSCALScan(singleOutcomeResult(scan, outcome), hostname)
}

// WriteOSCALOutcome is [ExportOSCALOutcome] streamed to w.
func WriteOSCALOutcome(w io.Writer, scan *api.ScanResult, outcome api.RuleOutcome, hostname string) error {
	return evidence.WriteOSCALScan(w, singleOutcomeResult(scan, outcome), hostname)
}

// singleOutcomeResult wraps one outcome in a ScanResult that preserves the
// parent scan's host context (HostID/Capabilities/Platform) when available.
func singleOutcomeResult(scan *api.ScanResult, outcome api.RuleOutcome) *api.ScanResult {
	one := &api.ScanResult{Outcomes: []api.RuleOutcome{outcome}}
	if scan != nil {
		one.HostID = scan.HostID
		one.Capabilities = scan.Capabilities
		one.Platform = scan.Platform
	}
	return one
}

// ExportOSCAL renders a signed [api.EvidenceEnvelope] (the audit-truth-of-record
// a remediation transaction produces) as an OSCAL 1.0.6 Assessment Results
// document. This is the remediation counterpart to [ExportOSCALScan]: where the
// scan document reports a read-only verdict, this one reports a transaction
// outcome anchored on the envelope's Ed25519 signature (the signing-key-id and
// transaction-id are carried as namespaced props).
//
// A nil envelope returns an error.
func ExportOSCAL(envelope *api.EvidenceEnvelope) ([]byte, error) {
	return evidence.ExportOSCAL(envelope)
}

// WriteOSCAL is [ExportOSCAL] streamed to w instead of returning the bytes.
func WriteOSCAL(w io.Writer, envelope *api.EvidenceEnvelope) error {
	return evidence.WriteOSCAL(w, envelope)
}
