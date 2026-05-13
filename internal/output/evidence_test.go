package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/google/uuid"
)

// @spec output-evidence
// @ac AC-01
// @ac AC-15
func TestEvidenceWriter_SingleEnvelope(t *testing.T) {
	t.Run("output-evidence/AC-15", func(t *testing.T) {})
	t.Run("output-evidence/AC-01", func(t *testing.T) {})
	env := makeEnvelope("rule-pass", "host-1", api.StatusCommitted)
	env.SchemaVersion = "v1"
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Envelope: env},
		},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "host-1", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	// Decode as a single envelope.
	var got api.EvidenceEnvelope
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.RuleID != "rule-pass" {
		t.Errorf("RuleID = %q, want rule-pass", got.RuleID)
	}
	if got.HostID != "host-1" {
		t.Errorf("HostID = %q, want host-1", got.HostID)
	}
	if got.Decision != api.StatusCommitted {
		t.Errorf("Decision = %q, want committed", got.Decision)
	}
}

// @spec output-evidence
// @ac AC-02
func TestEvidenceWriter_IndentedJSON(t *testing.T) {
	t.Run("output-evidence/AC-02", func(t *testing.T) {})
	// AC: output is indented JSON for human inspection (operators
	// read evidence files when debugging signature failures or
	// auditing transactions).
	env := makeEnvelope("r", "h", api.StatusCommitted)
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{{Envelope: env}},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	// Indented JSON contains "\n  " (newline + 2-space indent).
	if !strings.Contains(buf.String(), "\n  ") {
		t.Errorf("expected indented JSON; got compact:\n%s", buf.String())
	}
}

// @spec output-evidence
// @ac AC-03
func TestEvidenceWriter_SkipsNilEnvelopes(t *testing.T) {
	t.Run("output-evidence/AC-03", func(t *testing.T) {})
	// Transactions without an envelope are silently skipped (matches
	// the OSCAL writer's contract; partial-failure remediation runs
	// must not crash the writer).
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusErrored, Envelope: nil},
			{Status: api.StatusCommitted, Envelope: makeEnvelope("r1", "h1", api.StatusCommitted)},
			{Status: api.StatusErrored, Envelope: nil},
		},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h1", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	count := 0
	for dec.More() {
		var doc api.EvidenceEnvelope
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("decode #%d: %v", count, err)
		}
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 document, got %d", count)
	}
}

// @spec output-evidence
// @ac AC-04
func TestEvidenceWriter_AllNilEnvelopesEmitsEmpty(t *testing.T) {
	t.Run("output-evidence/AC-04", func(t *testing.T) {})
	// All-nil envelopes produce zero output — same contract as the
	// OSCAL writer. cmd/kensa surface (when -o evidence: lands in
	// C-018) can then short-circuit before file creation.
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusErrored, Envelope: nil},
		},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output for all-nil-envelopes; got %d bytes:\n%s", buf.Len(), buf.String())
	}
}

// @spec output-evidence
// @ac AC-05
func TestEvidenceWriter_MultipleEnvelopes(t *testing.T) {
	t.Run("output-evidence/AC-05", func(t *testing.T) {})
	// N envelopes produce N concatenated JSON documents that a
	// json.Decoder iterates cleanly.
	envA := makeEnvelope("rule-a", "h1", api.StatusCommitted)
	envB := makeEnvelope("rule-b", "h1", api.StatusRolledBack)
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Envelope: envA},
			{Status: api.StatusRolledBack, Envelope: envB},
		},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h1", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	var rules []string
	for dec.More() {
		var env api.EvidenceEnvelope
		if err := dec.Decode(&env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		rules = append(rules, env.RuleID)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 envelopes, got %d", len(rules))
	}
	if rules[0] != "rule-a" || rules[1] != "rule-b" {
		t.Errorf("envelope order lost: got %v, want [rule-a rule-b]", rules)
	}
}

// @spec output-evidence
// @ac AC-06
func TestEvidenceWriter_PreservesEmptySignature(t *testing.T) {
	t.Run("output-evidence/AC-06", func(t *testing.T) {})
	// The writer must not crash on an envelope with empty Signature
	// bytes (the M7 placeholder state). Documents emit even when
	// unsigned; consumers verifying signatures use len(Signature) > 0
	// as the signal that real signature production has rolled out.
	env := makeEnvelope("r", "h", api.StatusCommitted)
	env.Signature = nil // explicit empty
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{{Envelope: env}},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	var got api.EvidenceEnvelope
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got.Signature) != 0 {
		t.Errorf("expected empty signature in output; got %d bytes", len(got.Signature))
	}
}

// @spec output-evidence
// @ac AC-07
func TestEvidenceWriter_PreservesNonEmptySignature(t *testing.T) {
	t.Run("output-evidence/AC-07", func(t *testing.T) {})
	// Once M7 task #12 lands and signatures are real, the writer
	// must round-trip them faithfully. Locks the wire-shape contract
	// against future signature-stripping bugs.
	//
	// Use a 64-byte fixture matching Ed25519 signature size (RFC 8032)
	// so the test exercises the full base64 encoding length the real
	// signer will produce.
	env := makeEnvelope("r", "h", api.StatusCommitted)
	env.Signature = make([]byte, 64)
	for i := range env.Signature {
		env.Signature[i] = byte(i)
	}
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{{Envelope: env}},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	var got api.EvidenceEnvelope
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !bytes.Equal(got.Signature, env.Signature) {
		t.Errorf("signature round-trip failed: got %x, want %x", got.Signature, env.Signature)
	}
	if len(got.Signature) != 64 {
		t.Errorf("signature length = %d, want 64 (Ed25519 RFC 8032)", len(got.Signature))
	}
}

// @spec output-evidence
// @ac AC-08
func TestEvidenceWriter_PreservesFrameworkRefs(t *testing.T) {
	t.Run("output-evidence/AC-08", func(t *testing.T) {})
	// FrameworkRefs is critical for compliance audit trails. Locks
	// the full round-trip contract: every entry, both ControlID
	// AND FrameworkID, in declared order.
	env := makeEnvelope("r", "h", api.StatusCommitted)
	want := []api.FrameworkRef{
		{FrameworkID: "CIS", ControlID: "CIS-1.1.1"},
		{FrameworkID: "NIST-800-53", ControlID: "AC-2(1)"},
		{FrameworkID: "STIG", ControlID: "V-230223"},
	}
	env.FrameworkRefs = want
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{{Envelope: env}},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	var got api.EvidenceEnvelope
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got.FrameworkRefs) != len(want) {
		t.Fatalf("expected %d framework refs, got %d", len(want), len(got.FrameworkRefs))
	}
	for i := range want {
		if got.FrameworkRefs[i].FrameworkID != want[i].FrameworkID {
			t.Errorf("FrameworkRefs[%d].FrameworkID = %q, want %q", i, got.FrameworkRefs[i].FrameworkID, want[i].FrameworkID)
		}
		if got.FrameworkRefs[i].ControlID != want[i].ControlID {
			t.Errorf("FrameworkRefs[%d].ControlID = %q, want %q", i, got.FrameworkRefs[i].ControlID, want[i].ControlID)
		}
	}
}

// @spec output-evidence
// @ac AC-09
func TestEvidenceWriter_TimestampUTC(t *testing.T) {
	t.Run("output-evidence/AC-09", func(t *testing.T) {})
	// StartedAt and FinishedAt round-trip through JSON as RFC 3339.
	// Locks the time-zone contract; auditors expect UTC.
	env := makeEnvelope("r", "h", api.StatusCommitted)
	env.StartedAt = time.Date(2026, 5, 8, 12, 30, 45, 0, time.UTC)
	env.FinishedAt = time.Date(2026, 5, 8, 12, 30, 50, 0, time.UTC)
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{{Envelope: env}},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	if !strings.Contains(buf.String(), "2026-05-08T12:30:45Z") {
		t.Errorf("StartedAt missing or not UTC RFC3339:\n%s", buf.String())
	}
}

// @spec output-evidence
// @ac AC-10
func TestEvidenceWriter_RegistryWiring(t *testing.T) {
	t.Run("output-evidence/AC-10", func(t *testing.T) {})
	w, ok := RemediationWriterFor("evidence")
	if !ok {
		t.Fatal("RemediationWriterFor(evidence): not registered")
	}
	if w.Format() != "evidence" {
		t.Errorf("Format() = %q, want evidence", w.Format())
	}
}

// @spec output-evidence
// @ac AC-11
func TestEvidenceWriter_NotRegisteredForUnsupportedPayloads(t *testing.T) {
	t.Run("output-evidence/AC-11", func(t *testing.T) {})
	if _, ok := ScanWriterFor("evidence"); ok {
		t.Error("ScanWriterFor(evidence) should not be registered (scan produces no envelopes)")
	}
	if _, ok := HistoryWriterFor("evidence"); ok {
		t.Error("HistoryWriterFor(evidence) should not be registered")
	}
	if _, ok := CapsWriterFor("evidence"); ok {
		t.Error("CapsWriterFor(evidence) should not be registered")
	}
	if _, ok := JSONValueWriterFor("evidence"); ok {
		t.Error("JSONValueWriterFor(evidence) should not be registered")
	}
}

// @spec output-evidence
// @ac AC-12
func TestEvidenceWriter_PropagateWriteErrors(t *testing.T) {
	t.Run("output-evidence/AC-12", func(t *testing.T) {})
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Envelope: makeEnvelope("r", "h", api.StatusCommitted)},
		},
	}
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(errWriter{}, "h", nil, result); err == nil {
		t.Error("expected error from failing writer, got nil")
	}
}

// TestEvidenceWriter_PreservesPreStateBundle locks AC-13: the
// PreStateBundle round-trips with all entries faithfully preserved.
// PreStateBundle is the rollback-relevant data — auditors querying
// an old evidence file to verify rollback completeness MUST see
// the same captured pre-state the engine recorded. A custom
// MarshalJSON that silently drops Data fields would corrupt the
// audit trail; this test catches it.
// @spec output-evidence
// @ac AC-13
func TestEvidenceWriter_PreservesPreStateBundle(t *testing.T) {
	t.Run("output-evidence/AC-13", func(t *testing.T) {})
	env := makeEnvelope("r", "h", api.StatusCommitted)
	env.PreStateBundle = []api.PreState{
		{
			StepIndex:  0,
			Mechanism:  "file_permissions",
			Capturable: true,
			Data:       map[string]interface{}{"path": "/etc/ssh/sshd_config", "mode": "0600"},
			CapturedAt: time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC),
		},
		{
			StepIndex:  1,
			Mechanism:  "service_enabled",
			Capturable: true,
			Data:       map[string]interface{}{"unit": "sshd.service", "enabled": false},
			CapturedAt: time.Date(2026, 5, 8, 12, 0, 1, 0, time.UTC),
		},
	}
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{{Envelope: env}},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	var got api.EvidenceEnvelope
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got.PreStateBundle) != 2 {
		t.Fatalf("expected 2 PreState entries, got %d", len(got.PreStateBundle))
	}
	if got.PreStateBundle[0].Mechanism != "file_permissions" {
		t.Errorf("PreStateBundle[0].Mechanism = %q, want file_permissions", got.PreStateBundle[0].Mechanism)
	}
	if got.PreStateBundle[0].Data["path"] != "/etc/ssh/sshd_config" {
		t.Errorf("PreStateBundle[0].Data[path] = %v, want /etc/ssh/sshd_config", got.PreStateBundle[0].Data["path"])
	}
	if got.PreStateBundle[1].Data["unit"] != "sshd.service" {
		t.Errorf("PreStateBundle[1].Data[unit] = %v, want sshd.service", got.PreStateBundle[1].Data["unit"])
	}
}

// @spec output-evidence
// @ac AC-14
func TestEvidenceWriter_TransactionIDInJSON(t *testing.T) {
	t.Run("output-evidence/AC-14", func(t *testing.T) {})
	// AC: TransactionID round-trips through the JSON encoding (it's
	// the primary key auditors use to correlate envelope to log).
	id := uuid.MustParse("00000000-0000-0000-0000-00000000beef")
	env := makeEnvelope("r", "h", api.StatusCommitted)
	env.TransactionID = id
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{{Envelope: env}},
	}
	var buf bytes.Buffer
	if err := (evidenceRemediationWriter{}).WriteRemediationResult(&buf, "h", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	if !strings.Contains(buf.String(), id.String()) {
		t.Errorf("output missing TransactionID %q", id.String())
	}
}
