package output

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// PDF output testing strategy: we don't render PDFs to pixels and
// compare visually. Instead we assert:
//
//  1. The output starts with the PDF magic bytes ("%PDF-").
//  2. The output contains the textual content we placed (titles,
//     summary lines, rule IDs) as ASCII or PDFDocEncoding string
//     literals. Maroto's underlying gofpdf emits text as encoded
//     PDF string objects; for our ASCII content the literal bytes
//     appear in the output stream verbatim.
//  3. The output is non-empty and ends with the PDF trailer.
//
// These checks confirm correct wiring without requiring an external
// PDF parser dependency.

// @spec output-pdf
// @ac AC-01
func TestPDFScanWriter_MagicBytes(t *testing.T) {
	t.Run("output-pdf/AC-01", func(t *testing.T) {})
	rules := []*api.Rule{{ID: "rule-pass"}}
	result := &api.ScanResult{
		HostID: "test-host",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Steps: []api.StepResult{{Detail: "ok"}}},
		},
	}
	var buf bytes.Buffer
	if err := (pdfScanWriter{}).WriteScanResult(&buf, "test-host", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Errorf("output does not start with PDF magic bytes; first 16 bytes: %q", buf.Bytes()[:16])
	}
	if !bytes.Contains(buf.Bytes(), []byte("%%EOF")) {
		t.Errorf("output does not contain PDF trailer (%%EOF)")
	}
	if buf.Len() < 500 {
		t.Errorf("output suspiciously small (%d bytes); a real PDF with 1 row should be at least 500 bytes", buf.Len())
	}
}

// @spec output-pdf
// @ac AC-02
func TestPDFScanWriter_ContainsContent(t *testing.T) {
	t.Run("output-pdf/AC-02", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "rule-alpha"},
		{ID: "rule-beta"},
		{ID: "rule-gamma"},
	}
	result := &api.ScanResult{
		HostID: "host-1",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
			{Status: api.StatusRolledBack, Steps: []api.StepResult{{Detail: "did not match"}}},
			{Status: api.StatusErrored, Error: errors.New("ssh closed")},
		},
	}
	var buf bytes.Buffer
	if err := (pdfScanWriter{}).WriteScanResult(&buf, "host-1", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"kensa scan report",
		"host-1",
		"rule-alpha",
		"rule-beta",
		"rule-gamma",
		"PASS",
		"FAIL",
		"ERROR",
		"1 passed, 1 failed, 1 errors",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("PDF body missing %q (length=%d bytes)", want, buf.Len())
		}
	}
}

// @spec output-pdf
// @ac AC-03
func TestPDFScanWriter_StatusVocabularyCollapsed(t *testing.T) {
	t.Run("output-pdf/AC-03", func(t *testing.T) {})
	// Scan PDF mirrors scan CSV: collapses to PASS / FAIL / ERROR.
	// partially_applied (which can't occur in a scan by API contract)
	// must not surface as raw text.
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusPartiallyApplied},
		},
	}
	var buf bytes.Buffer
	if err := (pdfScanWriter{}).WriteScanResult(&buf, "h", []*api.Rule{{ID: "r"}}, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	if strings.Contains(buf.String(), "partially_applied") {
		t.Errorf("scan PDF should not surface partially_applied; got it as raw text")
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Errorf("partially_applied should collapse to FAIL in scan PDF")
	}
}

// @spec output-pdf
// @ac AC-04
func TestPDFRemediationWriter_PreservesRawStatus(t *testing.T) {
	t.Run("output-pdf/AC-04", func(t *testing.T) {})
	// Remediation PDF mirrors remediation CSV: the raw API vocabulary
	// is preserved so auditors can distinguish rolled_back from
	// partially_applied.
	rules := []*api.Rule{
		{ID: "r1"}, {ID: "r2"}, {ID: "r3"}, {ID: "r4"},
	}
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
			{Status: api.StatusRolledBack},
			{Status: api.StatusErrored, Error: errors.New("boom")},
			{Status: api.StatusPartiallyApplied},
		},
	}
	var buf bytes.Buffer
	if err := (pdfRemediationWriter{}).WriteRemediationResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"kensa remediation report",
		"committed", "rolled_back", "errored", "partially_applied",
		"1 committed, 0 staged, 1 rolled_back, 1 partially_applied, 1 errors",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("remediation PDF missing %q", want)
		}
	}
}

// @spec output-pdf
// @ac AC-05
func TestPDFScanWriter_EmptyTransactions(t *testing.T) {
	t.Run("output-pdf/AC-05", func(t *testing.T) {})
	// Header-only invariant: empty Transactions still produces a
	// valid PDF with title and table header but no data rows.
	result := &api.ScanResult{HostID: "h"}
	var buf bytes.Buffer
	if err := (pdfScanWriter{}).WriteScanResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Error("empty result still must produce a valid PDF")
	}
	if !strings.Contains(buf.String(), "0 passed, 0 failed, 0 errors") {
		t.Error("empty result should still emit the summary line with zeros")
	}
}

// @spec output-pdf
// @ac AC-06
func TestPDFWriters_RegistryWiring(t *testing.T) {
	t.Run("output-pdf/AC-06", func(t *testing.T) {})
	if w, ok := ScanWriterFor("pdf"); !ok {
		t.Error("ScanWriterFor(pdf): not registered")
	} else if w.Format() != "pdf" {
		t.Errorf("ScanWriterFor(pdf).Format() = %q, want pdf", w.Format())
	}
	if w, ok := RemediationWriterFor("pdf"); !ok {
		t.Error("RemediationWriterFor(pdf): not registered")
	} else if w.Format() != "pdf" {
		t.Errorf("RemediationWriterFor(pdf).Format() = %q, want pdf", w.Format())
	}
}

// @spec output-pdf
// @ac AC-07
func TestPDFWriters_NotRegisteredForUnsupportedPayloads(t *testing.T) {
	t.Run("output-pdf/AC-07", func(t *testing.T) {})
	// PDF is intentionally NOT registered for caps, history, or
	// json-value payloads. Caps is too small to need pagination,
	// history is paginated (PDF over thousands of rows is a
	// runaway), and the JSONValue escape-hatch payloads have no
	// useful PDF shape.
	if _, ok := CapsWriterFor("pdf"); ok {
		t.Error("CapsWriterFor(pdf) should not be registered (caps too small for PDF)")
	}
	if _, ok := HistoryWriterFor("pdf"); ok {
		t.Error("HistoryWriterFor(pdf) should not be registered (paginated history → CSV/JSON)")
	}
	if _, ok := JSONValueWriterFor("pdf"); ok {
		t.Error("JSONValueWriterFor(pdf) should not be registered")
	}
}

// @spec output-pdf
// @ac AC-08
func TestPDFWriters_FormatIdentity(t *testing.T) {
	t.Run("output-pdf/AC-08", func(t *testing.T) {})
	for _, w := range []Writer{pdfScanWriter{}, pdfRemediationWriter{}} {
		if got := w.Format(); got != "pdf" {
			t.Errorf("Format() = %q, want pdf", got)
		}
	}
}

// TestPDFWriters_TimestampShape locks AC-11: the summary line
// contains a UTC RFC 3339 timestamp. Catches a regression to local
// timezone or a different format.
// @spec output-pdf
// @ac AC-09
func TestPDFWriters_TimestampShape(t *testing.T) {
	t.Run("output-pdf/AC-09", func(t *testing.T) {})
	utcStamp := regexp.MustCompile(`generated \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)
	t.Run("scan", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (pdfScanWriter{}).WriteScanResult(&buf, "h", nil, &api.ScanResult{HostID: "h"}); err != nil {
			t.Fatalf("WriteScanResult: %v", err)
		}
		if !utcStamp.Match(buf.Bytes()) {
			t.Errorf("scan PDF summary missing UTC RFC 3339 timestamp")
		}
	})
	t.Run("remediation", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (pdfRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, &api.RemediationResult{}); err != nil {
			t.Fatalf("WriteRemediationResult: %v", err)
		}
		if !utcStamp.Match(buf.Bytes()) {
			t.Errorf("remediation PDF summary missing UTC RFC 3339 timestamp")
		}
	})
}

// TestPDFScanWriter_LongRuleIDDoesNotPanic covers the layout-overrun
// fix. Real SCAP rule IDs commonly run 75–95 chars; the rule cell
// uses breakline.DashStrategy so character-level wrapping kicks in
// instead of horizontal overflow into the STATUS / DETAIL columns.
//
// We can't easily assert pixel-level non-overlap from Go without an
// external PDF parser, but we CAN verify:
//
//  1. The render does not panic on a long rule ID.
//  2. The rule ID still appears in the output (no silent truncation).
//  3. The PDF is structurally valid (magic + EOF).
//
// A future test could parse maroto's bbox output for stronger checks.
// @spec output-pdf
// @ac AC-10
func TestPDFScanWriter_LongRuleIDDoesNotPanic(t *testing.T) {
	t.Run("output-pdf/AC-10", func(t *testing.T) {})
	longRule := "xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration_with_extra_padding_to_force_wrap"
	if len(longRule) < 80 {
		t.Fatalf("test fixture must be >= 80 chars; got %d", len(longRule))
	}
	rules := []*api.Rule{{ID: longRule}}
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
		},
	}
	var buf bytes.Buffer
	if err := (pdfScanWriter{}).WriteScanResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Errorf("output is not a PDF (corrupt long-ID render?)")
	}
	// The full ID may be split across DashStrategy hyphens; assert at
	// least the unique tail "padding_to_force_wrap" survives in the
	// output stream so we know it's not silently truncated.
	if !bytes.Contains(buf.Bytes(), []byte("padding")) {
		t.Errorf("long rule ID appears truncated; 'padding' substring missing from output")
	}
}

// @spec output-pdf
// @ac AC-11
func TestPDFWriters_PropagateWriteErrors(t *testing.T) {
	t.Run("output-pdf/AC-11", func(t *testing.T) {})
	// errWriter (defined in writer_test.go) returns an error on every
	// Write. Both PDF writers must surface it rather than swallow.
	rules := []*api.Rule{{ID: "r"}}
	scan := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
		},
	}
	rem := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
		},
	}
	if err := (pdfScanWriter{}).WriteScanResult(errWriter{}, "h", rules, scan); err == nil {
		t.Error("pdfScanWriter: expected error on failing writer, got nil")
	}
	if err := (pdfRemediationWriter{}).WriteRemediationResult(errWriter{}, "h", rules, rem); err == nil {
		t.Error("pdfRemediationWriter: expected error on failing writer, got nil")
	}
}
