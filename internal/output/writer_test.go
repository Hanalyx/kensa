package output

import (
	"errors"
	"io"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

// errWriter is an io.Writer that always returns errAlwaysFails. Used
// to verify writers surface underlying write errors rather than
// silently discarding them (AC-14).
type errWriter struct{}

var errAlwaysFails = errors.New("disk full (simulated)")

func (errWriter) Write([]byte) (int, error) { return 0, errAlwaysFails }

// partialErrWriter accepts the first n bytes successfully, then
// returns errAlwaysFails on every subsequent Write. Used to catch
// regressions where a writer drops the err return on a particular
// Fprintf call (the all-bytes-zero errWriter only catches the very
// first Fprintf — a writer with N+1 sequential Fprintfs needs a
// fail-late case to verify every err return is plumbed).
type partialErrWriter struct {
	remaining int
}

func (p *partialErrWriter) Write(b []byte) (int, error) {
	if p.remaining <= 0 {
		return 0, errAlwaysFails
	}
	if len(b) <= p.remaining {
		p.remaining -= len(b)
		return len(b), nil
	}
	n := p.remaining
	p.remaining = 0
	return n, errAlwaysFails
}

func TestScanWriterFor(t *testing.T) {
	tests := []struct {
		format    string
		want      bool
		wantClass string
	}{
		{"text", true, "output.textScanWriter"},
		{"json", true, "output.jsonScanWriter"},
		{"jsonl", true, "output.jsonlScanWriter"},
		{"csv", true, "output.csvScanWriter"},
		{"pdf", true, "output.pdfScanWriter"},
		{"unknown", false, ""},
		{"", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			w, ok := ScanWriterFor(tc.format)
			if ok != tc.want {
				t.Errorf("ScanWriterFor(%q): ok=%v, want %v", tc.format, ok, tc.want)
			}
			if ok && w.Format() != tc.format {
				t.Errorf("writer for %q has Format()=%q", tc.format, w.Format())
			}
		})
	}
}

func TestRemediationWriterFor(t *testing.T) {
	tests := []struct {
		format string
		want   bool
	}{
		{"text", true},
		{"json", true},
		{"jsonl", false},
		{"csv", true},
		{"unknown", false},
	}
	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			w, ok := RemediationWriterFor(tc.format)
			if ok != tc.want {
				t.Errorf("RemediationWriterFor(%q): ok=%v, want %v", tc.format, ok, tc.want)
			}
			if ok && w.Format() != tc.format {
				t.Errorf("writer for %q has Format()=%q", tc.format, w.Format())
			}
		})
	}
}

func TestHistoryWriterFor(t *testing.T) {
	w, ok := HistoryWriterFor("text")
	if !ok {
		t.Fatal("HistoryWriterFor(text): not registered")
	}
	if w.Format() != "text" {
		t.Errorf("writer for text has Format()=%q", w.Format())
	}
	// JSON history is not registered: the live runHistory query path
	// emits the full *api.QueryResult via JSONValueWriter so the
	// pagination metadata (Total/Offset/Limit) is preserved. A
	// HistoryWriter that took only []TransactionRecord would emit a
	// different shape; routing through JSONValueWriter is the
	// canonical path. Unit-test this absence so a future contributor
	// who adds back jsonHistoryWriter has to also update the assertion.
	if _, ok := HistoryWriterFor("json"); ok {
		t.Errorf("HistoryWriterFor(json) is registered; the live JSON history path should go through JSONValueWriter to preserve QueryResult shape")
	}
	if _, ok := HistoryWriterFor("xml"); ok {
		t.Errorf("HistoryWriterFor(xml) should not be registered")
	}
}

func TestCapsWriterFor(t *testing.T) {
	for _, f := range []string{"text", "json"} {
		t.Run(f, func(t *testing.T) {
			w, ok := CapsWriterFor(f)
			if !ok {
				t.Errorf("CapsWriterFor(%q): not registered", f)
				return
			}
			if w.Format() != f {
				t.Errorf("writer for %q has Format()=%q", f, w.Format())
			}
		})
	}
}

func TestJSONValueWriterFor(t *testing.T) {
	w, ok := JSONValueWriterFor("json")
	if !ok {
		t.Fatal("JSONValueWriterFor(json) should be registered")
	}
	if w.Format() != "json" {
		t.Errorf("Format() = %q, want json", w.Format())
	}
	if _, ok := JSONValueWriterFor("text"); ok {
		t.Errorf("JSONValueWriterFor(text) should not be registered (no useful text shape for arbitrary values)")
	}
}

// TestWriterOrText_Fallback locks the canonical fallback policy used
// by every cmd/kensa subcommand: empty format → "text"; unregistered
// format → "text"; registered format → that writer. Exists so a
// future change to the policy is forced through one update site
// rather than smearing across the call sites.
func TestWriterOrText_Fallback(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   string
	}{
		{"empty falls back to text", "", "text"},
		{"json registered for scan", "json", "json"},
		{"jsonl registered for scan", "jsonl", "jsonl"},
		{"csv registered for scan", "csv", "csv"},
		{"unknown falls back to text", "yaml", "text"},
	}
	for _, tc := range tests {
		t.Run("scan/"+tc.name, func(t *testing.T) {
			if got := ScanWriterOrText(tc.format).Format(); got != tc.want {
				t.Errorf("ScanWriterOrText(%q).Format() = %q, want %q", tc.format, got, tc.want)
			}
		})
	}
	// History registers "text" and "csv" — every other format must fall back.
	for _, f := range []string{"", "json", "jsonl", "xml"} {
		if got := HistoryWriterOrText(f).Format(); got != "text" {
			t.Errorf("HistoryWriterOrText(%q).Format() = %q, want text", f, got)
		}
	}
	if got := HistoryWriterOrText("csv").Format(); got != "csv" {
		t.Errorf("HistoryWriterOrText(csv).Format() = %q, want csv", got)
	}
	// Caps registers text + json.
	if got := CapsWriterOrText("json").Format(); got != "json" {
		t.Errorf("CapsWriterOrText(json).Format() = %q, want json", got)
	}
	if got := CapsWriterOrText("xml").Format(); got != "text" {
		t.Errorf("CapsWriterOrText(xml).Format() = %q, want text (fallback)", got)
	}
	// Remediation registers text + json.
	if got := RemediationWriterOrText("json").Format(); got != "json" {
		t.Errorf("RemediationWriterOrText(json).Format() = %q, want json", got)
	}
	if got := RemediationWriterOrText("xml").Format(); got != "text" {
		t.Errorf("RemediationWriterOrText(xml).Format() = %q, want text (fallback)", got)
	}
}

func TestErrUnsupportedPayload_Sentinel(t *testing.T) {
	// ErrUnsupportedPayload is exposed for future writers (csv, oscal,
	// evidence) that may not handle every payload type. C-012's writers
	// don't return it; this just locks the sentinel's existence.
	if ErrUnsupportedPayload == nil {
		t.Error("ErrUnsupportedPayload is nil")
	}
	if ErrUnsupportedPayload.Error() == "" {
		t.Error("ErrUnsupportedPayload has empty message")
	}
}

// TestRegistries_EagerInit asserts the package-level registries are
// populated before any test runs (AC-13). Failure here means a future
// refactor switched to sync.Once + lazy init, which would race with
// fan-out call sites that don't go through the eager-init path.
func TestRegistries_EagerInit(t *testing.T) {
	if len(scanResultWriters) == 0 {
		t.Error("scanResultWriters is empty at init time")
	}
	if len(remediationResultWriters) == 0 {
		t.Error("remediationResultWriters is empty at init time")
	}
	if len(historyWriters) == 0 {
		t.Error("historyWriters is empty at init time")
	}
	if len(capsWriters) == 0 {
		t.Error("capsWriters is empty at init time")
	}
	if len(jsonValueWriters) == 0 {
		t.Error("jsonValueWriters is empty at init time")
	}
}

// TestWriters_PropagateWriteErrors asserts every concrete writer
// returns the error from its underlying io.Writer (AC-14). Catches
// regressions where a writer accidentally swallows the error or
// returns nil instead.
func TestWriters_PropagateWriteErrors(t *testing.T) {
	rules := []*api.Rule{{ID: "r"}}
	scan := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Steps: []api.StepResult{{Detail: "ok"}}},
		},
	}
	rem := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
		},
	}
	caps := api.CapabilitySet{"x": true}

	tests := []struct {
		name  string
		write func(io.Writer) error
	}{
		{"text scan", func(w io.Writer) error { return textScanWriter{}.WriteScanResult(w, "h", rules, scan) }},
		{"text remediation", func(w io.Writer) error { return textRemediationWriter{}.WriteRemediationResult(w, "h", rules, rem) }},
		{"text history", func(w io.Writer) error {
			return textHistoryWriter{}.WriteHistory(w, []api.TransactionRecord{{RuleID: "r"}})
		}},
		{"text caps", func(w io.Writer) error { return textCapsWriter{}.WriteCaps(w, "h", caps) }},
		{"json scan", func(w io.Writer) error { return jsonScanWriter{}.WriteScanResult(w, "h", rules, scan) }},
		{"jsonl scan", func(w io.Writer) error { return jsonlScanWriter{}.WriteScanResult(w, "h", rules, scan) }},
		{"json remediation", func(w io.Writer) error {
			return jsonRemediationWriter{}.WriteRemediationResult(w, "h", rules, rem)
		}},
		{"json caps", func(w io.Writer) error { return jsonCapsWriter{}.WriteCaps(w, "h", caps) }},
		{"json value", func(w io.Writer) error { return jsonValueWriter{}.WriteJSONValue(w, map[string]int{"a": 1}) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.write(errWriter{})
			if err == nil {
				t.Errorf("%s: expected non-nil error from failing writer, got nil (write error swallowed)", tc.name)
			}
		})
	}

	// Fail-late case: the writer accepts some output and errors on
	// the next chunk. Catches regressions where one of several
	// sequential Fprintf calls drops its err return. n is chosen
	// small enough (5 bytes) that every test fixture is interrupted
	// mid-stream regardless of total output size.
	for _, tc := range tests {
		t.Run(tc.name+"/partial", func(t *testing.T) {
			w := &partialErrWriter{remaining: 5}
			if err := tc.write(w); err == nil {
				t.Errorf("%s: expected error after 5-byte prefix, got nil", tc.name)
			}
		})
	}
}
