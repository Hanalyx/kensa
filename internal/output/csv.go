package output

import (
	"encoding/csv"
	"io"

	"github.com/Hanalyx/kensa-go/api"
)

// csvScanWriter renders a ScanResult as CSV: one header row plus one
// data row per (host, rule) tuple. Format columns:
//
//	host_id, rule_id, status, detail
//
// status is one of "pass", "fail", "error" (not the raw API
// TransactionStatus values — CSV consumers want a small fixed
// vocabulary that doesn't include partially_applied).
//
// Each call to WriteScanResult emits the full document (header + rows).
// For inventory mode where multiple hosts feed into a single file,
// callers should wrap the destination writer with NewStreamingCSVScan
// so the header is emitted once across the whole stream.
type csvScanWriter struct{}

func (csvScanWriter) Format() string { return "csv" }

func (csvScanWriter) WriteScanResult(w io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"host_id", "rule_id", "status", "detail"}); err != nil {
		return err
	}
	if err := writeScanRows(cw, hostID, rules, result); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

// writeScanRows emits one CSV row per transaction. Reused by both the
// singleton csvScanWriter and the streaming wrapper.
func writeScanRows(cw *csv.Writer, hostID string, rules []*api.Rule, result *api.ScanResult) error {
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		var status, detail string
		switch txr.Status {
		case api.StatusCommitted:
			status = "pass"
		case api.StatusErrored:
			status = "error"
			if txr.Error != nil {
				detail = txr.Error.Error()
			}
		default:
			status = "fail"
		}
		if detail == "" && len(txr.Steps) > 0 {
			detail = txr.Steps[0].Detail
		}
		if err := cw.Write([]string{hostID, ruleID, status, detail}); err != nil {
			return err
		}
	}
	return nil
}

// csvRemediationWriter renders a RemediationResult as CSV: one row
// per (host, rule) tuple with the raw transaction status preserved
// (committed | rolled_back | partially_applied | errored).
//
// Columns: host_id, rule_id, status, detail.
type csvRemediationWriter struct{}

func (csvRemediationWriter) Format() string { return "csv" }

func (csvRemediationWriter) WriteRemediationResult(w io.Writer, hostID string, rules []*api.Rule, result *api.RemediationResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"host_id", "rule_id", "status", "detail"}); err != nil {
		return err
	}
	if err := writeRemediationRows(cw, hostID, rules, result); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

func writeRemediationRows(cw *csv.Writer, hostID string, rules []*api.Rule, result *api.RemediationResult) error {
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		detail := ""
		if txr.Error != nil {
			detail = txr.Error.Error()
		} else if len(txr.Steps) > 0 {
			detail = txr.Steps[0].Detail
		}
		if err := cw.Write([]string{hostID, ruleID, string(txr.Status), detail}); err != nil {
			return err
		}
	}
	return nil
}

// csvHistoryWriter renders a transaction history list as CSV.
// Columns: transaction_id, host_id, rule_id, status, finished_at.
type csvHistoryWriter struct{}

func (csvHistoryWriter) Format() string { return "csv" }

func (csvHistoryWriter) WriteHistory(w io.Writer, txns []api.TransactionRecord) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"transaction_id", "host_id", "rule_id", "status", "finished_at"}); err != nil {
		return err
	}
	if err := writeHistoryRows(cw, txns); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

func writeHistoryRows(cw *csv.Writer, txns []api.TransactionRecord) error {
	for _, t := range txns {
		if err := cw.Write([]string{
			t.ID.String(),
			t.HostID,
			t.RuleID,
			string(t.Status),
			t.FinishedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}); err != nil {
			return err
		}
	}
	return nil
}

// StreamingCSVScan wraps an io.Writer with header-once semantics for
// CSV scan output. The first WriteScanResult call emits the header;
// subsequent calls emit only data rows. Used by the C-019 fan-out
// when an operator passes `-o csv:results.csv` against an inventory
// (one file, many hosts).
//
// Per writer.spec.yaml C-01, this is NOT registered as a singleton —
// each fan-out target gets its own StreamingCSVScan via
// NewStreamingCSVScan so the header-emitted state is per-stream.
type StreamingCSVScan struct {
	w             *csv.Writer
	headerEmitted bool
}

// NewStreamingCSVScan returns a StreamingCSVScan writing to w.
// Caller is responsible for closing the underlying writer; this
// type does not own w.
func NewStreamingCSVScan(w io.Writer) *StreamingCSVScan {
	return &StreamingCSVScan{w: csv.NewWriter(w)}
}

// WriteScanResult emits the header on the first call and data rows
// on every call. Returns the underlying csv.Writer's flush error if
// any.
//
// The first parameter (the io.Writer) is INTENTIONALLY IGNORED:
// StreamingCSVScan owns the writer it was constructed with and
// always emits to that. The parameter exists only to satisfy
// ScanResultWriter so this type can be substituted into the
// inventory-mode dispatch loop. Callers that need to retarget the
// stream must construct a new StreamingCSVScan via
// NewStreamingCSVScan.
func (s *StreamingCSVScan) WriteScanResult(_ io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult) error {
	if !s.headerEmitted {
		if err := s.w.Write([]string{"host_id", "rule_id", "status", "detail"}); err != nil {
			return err
		}
		s.headerEmitted = true
	}
	if err := writeScanRows(s.w, hostID, rules, result); err != nil {
		return err
	}
	s.w.Flush()
	return s.w.Error()
}

// Format reports "csv". StreamingCSVScan satisfies Writer so callers
// can route it through generic dispatch logic if they want.
func (s *StreamingCSVScan) Format() string { return "csv" }

// StreamingCSVRemediation is the RemediationResult analog of
// StreamingCSVScan.
type StreamingCSVRemediation struct {
	w             *csv.Writer
	headerEmitted bool
}

// NewStreamingCSVRemediation returns a StreamingCSVRemediation
// writing to w.
func NewStreamingCSVRemediation(w io.Writer) *StreamingCSVRemediation {
	return &StreamingCSVRemediation{w: csv.NewWriter(w)}
}

// WriteRemediationResult emits the header on the first call and data
// rows on every call.
//
// As with StreamingCSVScan.WriteScanResult, the first parameter (the
// io.Writer) is INTENTIONALLY IGNORED: the stream owns its writer
// and always emits to that. The parameter exists only to satisfy
// RemediationResultWriter for inventory-mode dispatch.
func (s *StreamingCSVRemediation) WriteRemediationResult(_ io.Writer, hostID string, rules []*api.Rule, result *api.RemediationResult) error {
	if !s.headerEmitted {
		if err := s.w.Write([]string{"host_id", "rule_id", "status", "detail"}); err != nil {
			return err
		}
		s.headerEmitted = true
	}
	if err := writeRemediationRows(s.w, hostID, rules, result); err != nil {
		return err
	}
	s.w.Flush()
	return s.w.Error()
}

// Format reports "csv".
func (s *StreamingCSVRemediation) Format() string { return "csv" }
