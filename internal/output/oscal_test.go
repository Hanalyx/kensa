package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// makeEnvelope is a test helper for constructing a minimally-valid
// EvidenceEnvelope. The OSCAL writer does not validate signatures
// (signature production is M7 task #12); a placeholder envelope is
// sufficient to exercise the serializer.
func makeEnvelope(ruleID, hostID string, decision api.TransactionStatus) *api.EvidenceEnvelope {
	return &api.EvidenceEnvelope{
		TransactionID: uuid.New(),
		RuleID:        ruleID,
		HostID:        hostID,
		Decision:      decision,
		StartedAt:     time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 5, 8, 12, 0, 5, 0, time.UTC),
		SigningKeyID:  "test-key-1",
	}
}

// @spec output-oscal
// @ac AC-01
// @ac AC-09
func TestOSCALRemediationWriter_SingleTransaction(t *testing.T) {
	t.Run("output-oscal/AC-09", func(t *testing.T) {})
	t.Run("output-oscal/AC-01", func(t *testing.T) {})
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{
				Status:   api.StatusCommitted,
				Envelope: makeEnvelope("rule-pass", "host-1", api.StatusCommitted),
			},
		},
	}
	var buf bytes.Buffer
	if err := (oscalRemediationWriter{}).WriteRemediationResult(&buf, "host-1", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	// Output is one OSCAL Assessment Results JSON document.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if _, ok := doc["assessment-results"]; !ok {
		t.Errorf("OSCAL document missing top-level 'assessment-results' key; got %v", keysOf(doc))
	}
}

// @spec output-oscal
// @ac AC-02
func TestOSCALRemediationWriter_SkipsNilEnvelopes(t *testing.T) {
	t.Run("output-oscal/AC-02", func(t *testing.T) {})
	// Transactions without an envelope (e.g., non-capturable rule
	// that errored before commit) must be silently skipped, not
	// crash and not emit a document for them.
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusErrored, Envelope: nil}, // no envelope
			{
				Status:   api.StatusCommitted,
				Envelope: makeEnvelope("rule-pass", "host-1", api.StatusCommitted),
			},
			{Status: api.StatusErrored, Envelope: nil}, // no envelope
		},
	}
	var buf bytes.Buffer
	if err := (oscalRemediationWriter{}).WriteRemediationResult(&buf, "host-1", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	// Exactly one document was emitted.
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	count := 0
	for dec.More() {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("decode #%d: %v", count, err)
		}
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 OSCAL document, got %d", count)
	}
}

// @spec output-oscal
// @ac AC-03
func TestOSCALRemediationWriter_AllNilEnvelopesEmitsEmpty(t *testing.T) {
	t.Run("output-oscal/AC-03", func(t *testing.T) {})
	// Edge case: a result with zero envelopes (every transaction
	// errored before commit) must produce empty output without
	// erroring. Operators see no file or empty file rather than a
	// crash.
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusErrored, Envelope: nil},
		},
	}
	var buf bytes.Buffer
	if err := (oscalRemediationWriter{}).WriteRemediationResult(&buf, "host-1", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output for all-nil-envelopes; got %d bytes:\n%s", buf.Len(), buf.String())
	}
}

// @spec output-oscal
// @ac AC-04
func TestOSCALRemediationWriter_MultipleTransactions(t *testing.T) {
	t.Run("output-oscal/AC-04", func(t *testing.T) {})
	// N envelopes produce N OSCAL documents concatenated.
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Envelope: makeEnvelope("r1", "h1", api.StatusCommitted)},
			{Status: api.StatusRolledBack, Envelope: makeEnvelope("r2", "h1", api.StatusRolledBack)},
		},
	}
	var buf bytes.Buffer
	if err := (oscalRemediationWriter{}).WriteRemediationResult(&buf, "h1", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	count := 0
	for dec.More() {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("decode #%d: %v", count, err)
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 OSCAL documents, got %d", count)
	}
}

// @spec output-oscal
// @ac AC-05
func TestOSCALRemediationWriter_RegistryWiring(t *testing.T) {
	t.Run("output-oscal/AC-05", func(t *testing.T) {})
	w, ok := RemediationWriterFor("oscal")
	if !ok {
		t.Fatal("RemediationWriterFor(oscal): not registered")
	}
	if w.Format() != "oscal" {
		t.Errorf("Format() = %q, want oscal", w.Format())
	}
}

// @spec output-oscal
// @ac AC-06
func TestOSCALRemediationWriter_NotRegisteredForUnsupportedPayloads(t *testing.T) {
	t.Run("output-oscal/AC-06", func(t *testing.T) {})
	// OSCAL is RemediationResult-only because envelopes are produced
	// only during remediation. Scan / caps / history / json-value
	// payloads carry no envelopes and have no OSCAL representation.
	if _, ok := ScanWriterFor("oscal"); ok {
		t.Error("ScanWriterFor(oscal) should not be registered (scan produces no envelopes)")
	}
	if _, ok := HistoryWriterFor("oscal"); ok {
		t.Error("HistoryWriterFor(oscal) should not be registered")
	}
	if _, ok := CapsWriterFor("oscal"); ok {
		t.Error("CapsWriterFor(oscal) should not be registered")
	}
	if _, ok := JSONValueWriterFor("oscal"); ok {
		t.Error("JSONValueWriterFor(oscal) should not be registered")
	}
}

// @spec output-oscal
// @ac AC-07
func TestOSCALRemediationWriter_PropagateWriteErrors(t *testing.T) {
	t.Run("output-oscal/AC-07", func(t *testing.T) {})
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Envelope: makeEnvelope("r1", "h1", api.StatusCommitted)},
		},
	}
	if err := (oscalRemediationWriter{}).WriteRemediationResult(errWriter{}, "h1", nil, result); err == nil {
		t.Error("expected error from failing writer, got nil (write error swallowed)")
	}
}

// @spec output-oscal
// @ac AC-08
func TestOSCALRemediationWriter_PropagateWriteErrors_NoEnvelopes(t *testing.T) {
	t.Run("output-oscal/AC-08", func(t *testing.T) {})
	// When there are no envelopes to write, the writer is never
	// invoked — and a failing io.Writer should NOT see any writes at
	// all (no spurious empty-document write).
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusErrored, Envelope: nil},
		},
	}
	if err := (oscalRemediationWriter{}).WriteRemediationResult(errWriter{}, "h1", nil, result); err != nil {
		t.Errorf("zero envelopes should not invoke the writer; got error %v", err)
	}
}

// keysOf returns the keys of m as a slice (used for diagnostic error
// messages so the test failure surfaces what the document actually
// contains).
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
