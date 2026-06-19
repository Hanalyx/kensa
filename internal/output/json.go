package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// scanLine is the JSON Lines wire shape consumed by OpenWatch's
// ingestion pipeline. One line per host per scan run; compact
// (no internal newlines) so OpenWatch can stream-parse with jq or
// its own NDJSON reader.
//
// The scanLine type is internal to the output package because
// OpenWatch owns the consumer side; the producer is free to
// evolve internal
// representation as long as the wire shape stays stable.
type scanLine struct {
	ScannedAt time.Time      `json:"scanned_at"`
	HostID    string         `json:"host_id"`
	Passed    int            `json:"passed"`
	Failed    int            `json:"failed"`
	Skipped   int            `json:"skipped"`
	Errors    int            `json:"errors"`
	Rules     []scanLineRule `json:"rules"`
}

type scanLineRule struct {
	RuleID string `json:"rule_id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// jsonScanWriter renders a ScanResult as indented JSON.
type jsonScanWriter struct{}

func (jsonScanWriter) Format() string { return "json" }

func (jsonScanWriter) WriteScanResult(w io.Writer, _ string, _ []*api.Rule, result *api.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// jsonlScanWriter renders a ScanResult as a single compact NDJSON
// line. Each call emits exactly one newline-terminated JSON object —
// suitable for appending to a file or piping to OpenWatch's ingest
// endpoint.
//
// It maps from result.Outcomes — the canonical compliance verdict
// (api.ComplianceStatus pass/fail/skipped/error, carrying RuleID
// intrinsically) — NOT from result.Transactions. The Transactions
// surface overloads committed/rolled_back/errored as the compliance
// verdict and records a platform-gated or not-applicable rule as
// StatusErrored for back-compat; reading it here mislabelled those
// skips as "error" and gave no skipped count. Outcomes is the surface
// every other consumer is told to read, so the rules parameter (the
// old parallel-index source for rule IDs) is unused.
type jsonlScanWriter struct{}

func (jsonlScanWriter) Format() string { return "jsonl" }

func (jsonlScanWriter) WriteScanResult(w io.Writer, _ string, _ []*api.Rule, result *api.ScanResult) error {
	line := scanLine{
		ScannedAt: time.Now().UTC(),
		HostID:    result.HostID,
		Rules:     make([]scanLineRule, 0, len(result.Outcomes)),
	}
	for _, o := range result.Outcomes {
		// ComplianceStatus values are exactly the wire status strings
		// ("pass"/"fail"/"skipped"/"error"), so no remapping is needed.
		line.Rules = append(line.Rules, scanLineRule{
			RuleID: o.RuleID,
			Status: string(o.Status),
			Detail: o.Detail,
		})
		switch o.Status {
		case api.CompliancePass:
			line.Passed++
		case api.ComplianceFail:
			line.Failed++
		case api.ComplianceSkipped:
			line.Skipped++
		case api.ComplianceError:
			line.Errors++
		}
	}
	return json.NewEncoder(w).Encode(line)
}

// jsonRemediationWriter renders a RemediationResult as indented JSON.
type jsonRemediationWriter struct{}

func (jsonRemediationWriter) Format() string { return "json" }

func (jsonRemediationWriter) WriteRemediationResult(w io.Writer, _ string, _ []*api.Rule, result *api.RemediationResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// History JSON output deliberately does NOT have a HistoryWriter
// implementation: the live runHistory query path emits the full
// *api.QueryResult (with Transactions, Total, Offset, Limit) via
// JSONValueWriter so OpenWatch consumers get pagination metadata.
// A jsonHistoryWriter that took only []TransactionRecord would emit
// a different shape and silently break that contract if anything
// ever routed through it. If a future caller needs JSON history
// output, route through JSONValueWriter with the QueryResult or
// an equivalently-shaped value type.

// jsonCapsWriter renders a CapabilitySet as indented JSON.
type jsonCapsWriter struct{}

func (jsonCapsWriter) Format() string { return "json" }

func (jsonCapsWriter) WriteCaps(w io.Writer, _ string, caps api.CapabilitySet) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(caps)
}

// jsonValueWriter is the catch-all JSON encoder for arbitrary
// JSON-serializable values. Used by subcommands (rollback, history
// detail, history aggregates) that emit single API value types
// rather than result aggregates. Indented for human readability —
// non-pretty JSON is available via JSONL for streaming consumers.
type jsonValueWriter struct{}

func (jsonValueWriter) Format() string { return "json" }

func (jsonValueWriter) WriteJSONValue(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
