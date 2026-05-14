package output

import (
	"errors"
	"io"

	"github.com/Hanalyx/kensa/api"
)

// Writer is the common identity every concrete serializer in this
// package satisfies: it knows what format it produces. Per-payload
// sub-interfaces (ScanResultWriter, RemediationResultWriter, etc.)
// extend Writer with a typed render method for one specific result
// shape, which keeps payload types statically checked at call sites
// while the fan-out (C-019) still has a common dispatch key.
//
// "Format" matches the lowercased Spec.Format value (e.g., "text",
// "json", "jsonl"); callers route by string-equality lookup against
// the registry maps below.
type Writer interface {
	// Format returns the format identifier this writer produces.
	// Always one of the values returned by KnownFormats().
	Format() string
}

// ScanResultWriter renders a ScanResult + rule index pair in one
// particular format. Implementations are stateless value types so
// they're safe to reuse across goroutines (C-019 fan-out).
type ScanResultWriter interface {
	Writer
	// WriteScanResult writes the given scan result to w in this
	// writer's format. rules is indexed in parallel with
	// result.Transactions so handlers without rule IDs in the
	// transaction record can recover them positionally.
	WriteScanResult(w io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult) error
}

// RemediationResultWriter renders a RemediationResult.
type RemediationResultWriter interface {
	Writer
	WriteRemediationResult(w io.Writer, hostID string, rules []*api.Rule, result *api.RemediationResult) error
}

// HistoryWriter renders a transaction history list.
type HistoryWriter interface {
	Writer
	WriteHistory(w io.Writer, txns []api.TransactionRecord) error
}

// CapsWriter renders a capability set probe result.
type CapsWriter interface {
	Writer
	WriteCaps(w io.Writer, hostID string, caps api.CapabilitySet) error
}

// JSONValueWriter renders an arbitrary JSON-encodable value. Used
// by subcommands (rollback, history detail, history aggregates)
// that emit single API value types rather than result aggregates.
//
// The "any" payload is unavoidable here because the callers pass
// heterogeneous types (TransactionRecord, AggregateResult,
// RollbackResult). All concrete implementations must accept any
// type that encoding/json can encode.
type JSONValueWriter interface {
	Writer
	WriteJSONValue(w io.Writer, v any) error
}

// ErrUnsupportedPayload is returned by a writer that received a
// payload whose type it does not know how to render. C-012's
// concrete writers cover every known shape, so this is a future-
// proofing sentinel rather than a current code path.
var ErrUnsupportedPayload = errors.New("output: payload type not supported by this renderer")

// scanResultWriters maps format identifier → ScanResultWriter.
// Populated in init() so tests and the fan-out can look up writers
// without reflection.
var scanResultWriters = map[string]ScanResultWriter{
	"text":  textScanWriter{},
	"json":  jsonScanWriter{},
	"jsonl": jsonlScanWriter{},
	"csv":   csvScanWriter{},
	"pdf":   pdfScanWriter{},
}

// remediationResultWriters maps format identifier → RemediationResultWriter.
//
// "oscal" and "evidence" are registered here only — both require a
// signed EvidenceEnvelope per transaction, which only the
// remediation path produces. ScanResult transactions all carry a nil
// Envelope by API contract, so scan-side writers for these formats
// would emit zero documents.
var remediationResultWriters = map[string]RemediationResultWriter{
	"text":     textRemediationWriter{},
	"json":     jsonRemediationWriter{},
	"csv":      csvRemediationWriter{},
	"pdf":      pdfRemediationWriter{},
	"oscal":    oscalRemediationWriter{},
	"evidence": evidenceRemediationWriter{},
}

// historyWriters maps format identifier → HistoryWriter.
//
// Only "text" and "csv" are registered: the live JSON path for
// history goes through JSONValueWriter with the full
// *api.QueryResult so OpenWatch consumers get the Total / Offset /
// Limit pagination metadata. Registering a HistoryWriter for "json"
// that took only []TransactionRecord would emit a different shape
// and silently break that contract.
//
// CSV is registered because spreadsheet ingestion of history rows
// has the same pagination requirement as the text view (the operator
// sees only the current page; pagination metadata is footer-style
// and not part of the row stream).
var historyWriters = map[string]HistoryWriter{
	"text": textHistoryWriter{},
	"csv":  csvHistoryWriter{},
}

// capsWriters maps format identifier → CapsWriter.
var capsWriters = map[string]CapsWriter{
	"text": textCapsWriter{},
	"json": jsonCapsWriter{},
}

// jsonValueWriters maps format identifier → JSONValueWriter. Today
// the only registered format is "json" — the value-typed payloads
// emitted by rollback / history detail / history aggregates have
// no useful text or csv representation, so callers fall back to
// JSON for anything that isn't a known result aggregate.
var jsonValueWriters = map[string]JSONValueWriter{
	"json": jsonValueWriter{},
}

// ScanWriterFor returns the ScanResultWriter registered for the
// given format. The bool reports whether a writer exists; callers
// should fall back to the text writer when false (or surface an
// "unsupported format" error to the operator).
func ScanWriterFor(format string) (ScanResultWriter, bool) {
	w, ok := scanResultWriters[format]
	return w, ok
}

// RemediationWriterFor returns the RemediationResultWriter for format.
func RemediationWriterFor(format string) (RemediationResultWriter, bool) {
	w, ok := remediationResultWriters[format]
	return w, ok
}

// HistoryWriterFor returns the HistoryWriter for format.
func HistoryWriterFor(format string) (HistoryWriter, bool) {
	w, ok := historyWriters[format]
	return w, ok
}

// CapsWriterFor returns the CapsWriter for format.
func CapsWriterFor(format string) (CapsWriter, bool) {
	w, ok := capsWriters[format]
	return w, ok
}

// JSONValueWriterFor returns the JSONValueWriter for format.
func JSONValueWriterFor(format string) (JSONValueWriter, bool) {
	w, ok := jsonValueWriters[format]
	return w, ok
}

// ScanWriterOrText returns the ScanResultWriter for the given format,
// falling back to the text writer if format is empty or unregistered.
// This is the canonical dispatch helper for cmd/kensa subcommands;
// using it in preference to manual `if !ok { … }` branches keeps the
// fallback policy in one place so a future change (e.g., changing the
// default to "json" or returning an error on unknown formats) edits
// one function instead of every call site.
func ScanWriterOrText(format string) ScanResultWriter {
	if format == "" {
		format = "text"
	}
	if w, ok := scanResultWriters[format]; ok {
		return w
	}
	return scanResultWriters["text"]
}

// RemediationWriterOrText is the ScanWriterOrText analog for
// RemediationResult payloads.
func RemediationWriterOrText(format string) RemediationResultWriter {
	if format == "" {
		format = "text"
	}
	if w, ok := remediationResultWriters[format]; ok {
		return w
	}
	return remediationResultWriters["text"]
}

// HistoryWriterOrText is the ScanWriterOrText analog for transaction
// history. Today only "text" is registered, so any non-empty format
// other than "text" still falls back to text. The history JSON path
// is special — see the doc on historyWriters and the runHistory call
// site in cmd/kensa for why.
func HistoryWriterOrText(format string) HistoryWriter {
	if format == "" {
		format = "text"
	}
	if w, ok := historyWriters[format]; ok {
		return w
	}
	return historyWriters["text"]
}

// CapsWriterOrText is the ScanWriterOrText analog for capability
// probe results.
func CapsWriterOrText(format string) CapsWriter {
	if format == "" {
		format = "text"
	}
	if w, ok := capsWriters[format]; ok {
		return w
	}
	return capsWriters["text"]
}
