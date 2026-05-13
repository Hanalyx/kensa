package output

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// @spec output-csv
// @ac AC-01
func TestCSVScanWriter_HeaderAndRows(t *testing.T) {
	t.Run("output-csv/AC-01", func(t *testing.T) {})
	rules := []*api.Rule{
		{ID: "rule-pass"},
		{ID: "rule-fail"},
		{ID: "rule-error"},
	}
	result := &api.ScanResult{
		HostID: "host-1",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Steps: []api.StepResult{{Detail: "ok"}}},
			{Status: api.StatusRolledBack, Steps: []api.StepResult{{Detail: "did not match"}}},
			{Status: api.StatusErrored, Error: errors.New("ssh timeout")},
		},
	}
	var buf bytes.Buffer
	if err := (csvScanWriter{}).WriteScanResult(&buf, "host-1", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if len(rows) != 4 {
		t.Fatalf("expected 1 header + 3 data rows, got %d", len(rows))
	}
	want := [][]string{
		{"host_id", "rule_id", "status", "detail"},
		{"host-1", "rule-pass", "pass", "ok"},
		{"host-1", "rule-fail", "fail", "did not match"},
		{"host-1", "rule-error", "error", "ssh timeout"},
	}
	for i := range want {
		if !rowsEqual(rows[i], want[i]) {
			t.Errorf("row %d = %v, want %v", i, rows[i], want[i])
		}
	}
}

// @spec output-csv
// @ac AC-02
func TestCSVScanWriter_StatusVocabularyCollapsed(t *testing.T) {
	t.Run("output-csv/AC-02", func(t *testing.T) {})
	// AC-03: scan output must collapse to {pass, fail, error}; raw API
	// statuses like "rolled_back" or "partially_applied" must NOT
	// surface in scan CSV.
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusPartiallyApplied},
		},
	}
	var buf bytes.Buffer
	if err := (csvScanWriter{}).WriteScanResult(&buf, "h", []*api.Rule{{ID: "r"}}, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	// Row 1 is header, row 2 is data.
	if rows[1][2] != "fail" {
		t.Errorf("partially_applied should collapse to 'fail' in scan CSV; got %q", rows[1][2])
	}
}

// @spec output-csv
// @ac AC-03
func TestCSVRemediationWriter_PreservesRawStatus(t *testing.T) {
	t.Run("output-csv/AC-03", func(t *testing.T) {})
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
	if err := (csvRemediationWriter{}).WriteRemediationResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if len(rows) != 5 {
		t.Fatalf("expected 1 header + 4 data rows, got %d", len(rows))
	}
	wantStatuses := []string{"committed", "rolled_back", "errored", "partially_applied"}
	for i, want := range wantStatuses {
		got := rows[i+1][2]
		if got != want {
			t.Errorf("row %d status = %q, want %q (raw API status preserved)", i+1, got, want)
		}
	}
}

// @spec output-csv
// @ac AC-04
func TestCSVHistoryWriter(t *testing.T) {
	t.Run("output-csv/AC-04", func(t *testing.T) {})
	id := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	finished := time.Date(2026, 5, 8, 12, 30, 45, 0, time.UTC)
	txns := []api.TransactionRecord{
		{
			ID: id, Status: api.StatusCommitted, RuleID: "rule-a", HostID: "host-1",
			FinishedAt: finished,
		},
	}
	var buf bytes.Buffer
	if err := (csvHistoryWriter{}).WriteHistory(&buf, txns); err != nil {
		t.Fatalf("WriteHistory: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if len(rows) != 2 {
		t.Fatalf("expected 1 header + 1 data row, got %d", len(rows))
	}
	want := []string{
		"00000000-0000-0000-0000-000000000001",
		"host-1",
		"rule-a",
		"committed",
		"2026-05-08T12:30:45Z",
	}
	if !rowsEqual(rows[1], want) {
		t.Errorf("row = %v, want %v", rows[1], want)
	}
}

// @spec output-csv
// @ac AC-05
func TestCSVHistoryWriter_TimestampInUTC(t *testing.T) {
	t.Run("output-csv/AC-05", func(t *testing.T) {})
	// AC: finished_at must be UTC RFC 3339 even if the input time has
	// a non-UTC location attached. Use a fixed-offset zone so the test
	// doesn't depend on a system tzdata install.
	estMinusFive := time.FixedZone("EST", -5*3600)
	finished := time.Date(2026, 5, 8, 8, 30, 45, 0, estMinusFive) // 13:30:45 UTC
	txns := []api.TransactionRecord{
		{ID: uuid.New(), HostID: "h", RuleID: "r", Status: api.StatusCommitted, FinishedAt: finished},
	}
	var buf bytes.Buffer
	if err := (csvHistoryWriter{}).WriteHistory(&buf, txns); err != nil {
		t.Fatalf("WriteHistory: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if !strings.HasSuffix(rows[1][4], "Z") {
		t.Errorf("finished_at should end with Z (UTC); got %q", rows[1][4])
	}
	if !strings.Contains(rows[1][4], "13:30:45") {
		t.Errorf("finished_at should be UTC equivalent (13:30:45); got %q", rows[1][4])
	}
}

// @spec output-csv
// @ac AC-06
func TestCSVScanWriter_RFC4180Escaping(t *testing.T) {
	t.Run("output-csv/AC-06", func(t *testing.T) {})
	// AC-08: cells containing commas, quotes, or newlines must round-
	// trip through csv.NewReader unchanged.
	rules := []*api.Rule{{ID: "rule-with-quote-and-comma"}}
	tricky := `detail with, commas "quotes" and
newlines`
	result := &api.ScanResult{
		HostID: "host,with,commas",
		Transactions: []api.TransactionResult{
			{Status: api.StatusRolledBack, Steps: []api.StepResult{{Detail: tricky}}},
		},
	}
	var buf bytes.Buffer
	if err := (csvScanWriter{}).WriteScanResult(&buf, "host,with,commas", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if rows[1][0] != "host,with,commas" {
		t.Errorf("host_id round-trip failed: got %q, want %q", rows[1][0], "host,with,commas")
	}
	if rows[1][3] != tricky {
		t.Errorf("detail round-trip failed:\n  got:  %q\n  want: %q", rows[1][3], tricky)
	}
}

// @spec output-csv
// @ac AC-07
func TestStreamingCSVScan_HeaderOnce(t *testing.T) {
	t.Run("output-csv/AC-07", func(t *testing.T) {})
	// AC-09: two sequential WriteScanResult calls produce one header.
	// Locks both row count AND per-call data freshness — assert every
	// data column of every row so a state-carryover bug (where the
	// second call accidentally re-emitted the first call's data)
	// would fail this test.
	rules1 := []*api.Rule{{ID: "rule-pass"}}
	rules2 := []*api.Rule{{ID: "rule-error"}}
	r1 := &api.ScanResult{
		HostID: "host-1",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Steps: []api.StepResult{{Detail: "ok"}}},
		},
	}
	r2 := &api.ScanResult{
		HostID: "host-2",
		Transactions: []api.TransactionResult{
			{Status: api.StatusErrored, Error: errors.New("ssh closed")},
		},
	}
	var buf bytes.Buffer
	s := NewStreamingCSVScan(&buf)
	if err := s.WriteScanResult(nil, "host-1", rules1, r1); err != nil {
		t.Fatalf("first WriteScanResult: %v", err)
	}
	if err := s.WriteScanResult(nil, "host-2", rules2, r2); err != nil {
		t.Fatalf("second WriteScanResult: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if len(rows) != 3 {
		t.Fatalf("expected 1 header + 2 data rows, got %d:\n%s", len(rows), buf.String())
	}
	wantHeader := []string{"host_id", "rule_id", "status", "detail"}
	if !rowsEqual(rows[0], wantHeader) {
		t.Errorf("header = %v, want %v", rows[0], wantHeader)
	}
	wantRow1 := []string{"host-1", "rule-pass", "pass", "ok"}
	if !rowsEqual(rows[1], wantRow1) {
		t.Errorf("row 1 = %v, want %v (carryover regression?)", rows[1], wantRow1)
	}
	wantRow2 := []string{"host-2", "rule-error", "error", "ssh closed"}
	if !rowsEqual(rows[2], wantRow2) {
		t.Errorf("row 2 = %v, want %v (carryover regression?)", rows[2], wantRow2)
	}
}

// @spec output-csv
// @ac AC-08
func TestStreamingCSVScan_FreshInstancePerStream(t *testing.T) {
	t.Run("output-csv/AC-08", func(t *testing.T) {})
	// AC-11: two NewStreamingCSVScan calls against the same underlying
	// writer each emit their own header (per-stream state is fresh).
	var buf bytes.Buffer
	s1 := NewStreamingCSVScan(&buf)
	s2 := NewStreamingCSVScan(&buf)
	rules := []*api.Rule{{ID: "r"}}
	r := &api.ScanResult{HostID: "h", Transactions: []api.TransactionResult{{Status: api.StatusCommitted}}}
	if err := s1.WriteScanResult(nil, "h", rules, r); err != nil {
		t.Fatalf("s1: %v", err)
	}
	if err := s2.WriteScanResult(nil, "h", rules, r); err != nil {
		t.Fatalf("s2: %v", err)
	}
	// Two headers + two data rows = 4 rows total.
	rows := mustParseCSV(t, buf.Bytes())
	if len(rows) != 4 {
		t.Fatalf("expected 4 rows from two independent streams, got %d", len(rows))
	}
}

// @spec output-csv
// @ac AC-09
func TestStreamingCSVRemediation_HeaderOnce(t *testing.T) {
	t.Run("output-csv/AC-09", func(t *testing.T) {})
	rules := []*api.Rule{{ID: "r1"}}
	r1 := &api.RemediationResult{Transactions: []api.TransactionResult{{Status: api.StatusCommitted}}}
	r2 := &api.RemediationResult{Transactions: []api.TransactionResult{{Status: api.StatusRolledBack}}}
	var buf bytes.Buffer
	s := NewStreamingCSVRemediation(&buf)
	if err := s.WriteRemediationResult(nil, "h1", rules, r1); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := s.WriteRemediationResult(nil, "h2", rules, r2); err != nil {
		t.Fatalf("second: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if len(rows) != 3 {
		t.Fatalf("expected 1 header + 2 data rows, got %d", len(rows))
	}
}

// @spec output-csv
// @ac AC-10
func TestCSVWriters_FormatIdentity(t *testing.T) {
	t.Run("output-csv/AC-10", func(t *testing.T) {})
	tests := []struct {
		name string
		w    Writer
	}{
		{"scan", csvScanWriter{}},
		{"remediation", csvRemediationWriter{}},
		{"history", csvHistoryWriter{}},
		{"streaming scan", NewStreamingCSVScan(nil)},
		{"streaming remediation", NewStreamingCSVRemediation(nil)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.w.Format(); got != "csv" {
				t.Errorf("Format() = %q, want csv", got)
			}
		})
	}
}

// @spec output-csv
// @ac AC-11
func TestCSVWriters_RegistryWiring(t *testing.T) {
	t.Run("output-csv/AC-11", func(t *testing.T) {})
	if _, ok := ScanWriterFor("csv"); !ok {
		t.Error("ScanWriterFor(csv): not registered (AC-01)")
	}
	if _, ok := RemediationWriterFor("csv"); !ok {
		t.Error("RemediationWriterFor(csv): not registered (AC-04)")
	}
	if _, ok := HistoryWriterFor("csv"); !ok {
		t.Error("HistoryWriterFor(csv): not registered (AC-06)")
	}
}

// @spec output-csv
// @ac AC-12
func TestCSVWriters_NotInUnsupportedRegistries(t *testing.T) {
	t.Run("output-csv/AC-12", func(t *testing.T) {})
	// CSV is intentionally NOT registered for caps or json-value
	// payloads (per spec, those types have no useful CSV shape).
	if _, ok := CapsWriterFor("csv"); ok {
		t.Error("CapsWriterFor(csv) should not be registered (CSV doesn't fit caps payload)")
	}
	if _, ok := JSONValueWriterFor("csv"); ok {
		t.Error("JSONValueWriterFor(csv) should not be registered")
	}
}

// TestCSVWriters_EmptyPayload asserts header-only output is emitted
// (and is parseable) when the payload has zero rows. Locks the
// always-emit-header invariant so a future "skip header for empty
// payload" optimization can't break it.
func TestCSVWriters_EmptyPayload(t *testing.T) {
	t.Run("scan empty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (csvScanWriter{}).WriteScanResult(&buf, "h", nil, &api.ScanResult{HostID: "h"}); err != nil {
			t.Fatalf("WriteScanResult: %v", err)
		}
		rows := mustParseCSV(t, buf.Bytes())
		if len(rows) != 1 || rows[0][0] != "host_id" {
			t.Errorf("expected header-only output, got %d rows: %v", len(rows), rows)
		}
	})
	t.Run("remediation empty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (csvRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, &api.RemediationResult{}); err != nil {
			t.Fatalf("WriteRemediationResult: %v", err)
		}
		rows := mustParseCSV(t, buf.Bytes())
		if len(rows) != 1 || rows[0][0] != "host_id" {
			t.Errorf("expected header-only output, got %d rows: %v", len(rows), rows)
		}
	})
	t.Run("history empty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := (csvHistoryWriter{}).WriteHistory(&buf, nil); err != nil {
			t.Fatalf("WriteHistory: %v", err)
		}
		rows := mustParseCSV(t, buf.Bytes())
		if len(rows) != 1 || rows[0][0] != "transaction_id" {
			t.Errorf("expected header-only output, got %d rows: %v", len(rows), rows)
		}
	})
}

// TestCSVRemediationWriter_RFC4180Escaping mirrors the equivalent
// scan-side test on the remediation path so AC-08 explicitly covers
// every singleton.
func TestCSVRemediationWriter_RFC4180Escaping(t *testing.T) {
	tricky := `"quoted",
text with embedded
newlines`
	rules := []*api.Rule{{ID: "r,with,commas"}}
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusErrored, Error: errors.New(tricky)},
		},
	}
	var buf bytes.Buffer
	if err := (csvRemediationWriter{}).WriteRemediationResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if rows[1][1] != "r,with,commas" {
		t.Errorf("rule_id round-trip failed: got %q", rows[1][1])
	}
	if rows[1][3] != tricky {
		t.Errorf("detail round-trip failed:\n  got:  %q\n  want: %q", rows[1][3], tricky)
	}
}

// TestCSVHistoryWriter_RFC4180Escaping mirrors the same coverage on
// history.
func TestCSVHistoryWriter_RFC4180Escaping(t *testing.T) {
	id := uuid.New()
	txns := []api.TransactionRecord{
		{
			ID: id, HostID: `host,with,"quotes"`, RuleID: "r",
			Status: api.StatusCommitted, FinishedAt: time.Now().UTC(),
		},
	}
	var buf bytes.Buffer
	if err := (csvHistoryWriter{}).WriteHistory(&buf, txns); err != nil {
		t.Fatalf("WriteHistory: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if rows[1][1] != `host,with,"quotes"` {
		t.Errorf("host_id round-trip failed: got %q", rows[1][1])
	}
}

// TestStreamingCSVRemediation_FreshInstancePerStream mirrors AC-11
// coverage on the remediation streaming wrapper.
func TestStreamingCSVRemediation_FreshInstancePerStream(t *testing.T) {
	var buf bytes.Buffer
	s1 := NewStreamingCSVRemediation(&buf)
	s2 := NewStreamingCSVRemediation(&buf)
	rules := []*api.Rule{{ID: "r"}}
	r := &api.RemediationResult{Transactions: []api.TransactionResult{{Status: api.StatusCommitted}}}
	if err := s1.WriteRemediationResult(nil, "h", rules, r); err != nil {
		t.Fatalf("s1: %v", err)
	}
	if err := s2.WriteRemediationResult(nil, "h", rules, r); err != nil {
		t.Fatalf("s2: %v", err)
	}
	rows := mustParseCSV(t, buf.Bytes())
	if len(rows) != 4 {
		t.Fatalf("expected 4 rows from two independent streams, got %d", len(rows))
	}
}

// mustParseCSV parses the given CSV bytes and returns all rows. Fails
// the test on parse error.
func mustParseCSV(t *testing.T, b []byte) [][]string {
	t.Helper()
	rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v\n%s", err, string(b))
	}
	return rows
}

func rowsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
