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
// endpoint. The rules slice is indexed in parallel with
// result.Transactions to supply rule IDs (the scan result does not
// embed them).
type jsonlScanWriter struct{}

func (jsonlScanWriter) Format() string { return "jsonl" }

func (jsonlScanWriter) WriteScanResult(w io.Writer, _ string, rules []*api.Rule, result *api.ScanResult) error {
	line := scanLine{
		ScannedAt: time.Now().UTC(),
		HostID:    result.HostID,
		Rules:     make([]scanLineRule, 0, len(result.Transactions)),
	}
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		r := scanLineRule{RuleID: ruleID}
		switch txr.Status {
		case api.StatusCommitted:
			r.Status = "pass"
			line.Passed++
		case api.StatusErrored:
			r.Status = "error"
			line.Errors++
			if txr.Error != nil {
				r.Detail = txr.Error.Error()
			}
		default:
			r.Status = "fail"
			line.Failed++
		}
		if r.Detail == "" && len(txr.Steps) > 0 {
			r.Detail = txr.Steps[0].Detail
		}
		line.Rules = append(line.Rules, r)
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
