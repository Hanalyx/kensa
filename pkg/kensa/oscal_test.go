package kensa

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

func sampleScanResult() *api.ScanResult {
	return &api.ScanResult{
		HostID: "host-a.example.com",
		Outcomes: []api.RuleOutcome{{
			RuleID:        "rule_sysctl_aslr",
			Status:        api.CompliancePass,
			Severity:      "medium",
			Detail:        "kernel.randomize_va_space is 2",
			FrameworkRefs: []api.FrameworkRef{{FrameworkID: "cis_rhel9_v2", ControlID: "1.5.3"}},
			Evidence: []api.CheckEvidence{{
				Method:   "sysctl_value",
				Command:  "sysctl -n kernel.randomize_va_space",
				Stdout:   "2\n",
				ExitCode: 0,
				Expected: "2",
			}},
		}},
	}
}

// hasAssessmentResults reports whether b is a JSON object with a top-level
// "assessment-results" key — the OSCAL AR document root.
func hasAssessmentResults(t *testing.T, b []byte) {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not a JSON object: %v", err)
	}
	if _, ok := doc["assessment-results"]; !ok {
		t.Errorf("missing top-level \"assessment-results\" key; got keys %v", keysOf(doc))
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// @spec oscal-public-export
// @ac AC-01
func TestExportOSCALScan_PublicReachable(t *testing.T) {
	t.Log("// @spec oscal-public-export")
	t.Log("// @ac AC-01")
	b, err := ExportOSCALScan(sampleScanResult(), "host-a.example.com")
	if err != nil {
		t.Fatalf("ExportOSCALScan: %v", err)
	}
	hasAssessmentResults(t, b)
}

// @spec oscal-public-export
// @ac AC-02
func TestExportOSCALScan_EmbedsEvidence(t *testing.T) {
	t.Log("// @spec oscal-public-export")
	t.Log("// @ac AC-02")
	b, err := ExportOSCALScan(sampleScanResult(), "host-a.example.com")
	if err != nil {
		t.Fatalf("ExportOSCALScan: %v", err)
	}
	// The check command must survive into the document (it lives in
	// relevant-evidence remarks) — proof the public path carries the full
	// CheckEvidence through, not just the verdict.
	if !strings.Contains(string(b), "sysctl -n kernel.randomize_va_space") {
		t.Error("embedded check command not found in public OSCAL output")
	}
	// And the framework ref renders as a control-id.
	if !strings.Contains(string(b), "cis_rhel9_v2-1.5.3") {
		t.Error("framework control-id not found in public OSCAL output")
	}
}

// @spec oscal-public-export
// @ac AC-03
func TestWriteOSCALScan_Public(t *testing.T) {
	t.Log("// @spec oscal-public-export")
	t.Log("// @ac AC-03")
	var buf bytes.Buffer
	if err := WriteOSCALScan(&buf, sampleScanResult(), "host-a.example.com"); err != nil {
		t.Fatalf("WriteOSCALScan: %v", err)
	}
	hasAssessmentResults(t, buf.Bytes())
}

// @spec oscal-public-export
// @ac AC-04
func TestExportOSCAL_EnvelopePublic(t *testing.T) {
	t.Log("// @spec oscal-public-export")
	t.Log("// @ac AC-04")
	now := time.Now().UTC()
	env := &api.EvidenceEnvelope{
		SchemaVersion: "v1",
		TransactionID: uuid.New(),
		RuleID:        "test_rule_001",
		HostID:        "host-a.example.com",
		StartedAt:     now.Add(-5 * time.Second),
		FinishedAt:    now,
		Decision:      api.StatusCommitted,
		SigningKeyID:  "deadbeef",
		FrameworkRefs: []api.FrameworkRef{{FrameworkID: "nist_800_53", ControlID: "AU-5(2)"}},
	}
	b, err := ExportOSCAL(env)
	if err != nil {
		t.Fatalf("ExportOSCAL: %v", err)
	}
	hasAssessmentResults(t, b)
	// Parenthesized NIST id is coerced to a token-valid control-id, even
	// through the public path.
	if strings.Contains(string(b), "AU-5(2)") {
		t.Error("raw parenthesized control-id leaked into OSCAL output")
	}
	var buf bytes.Buffer
	if err := WriteOSCAL(&buf, env); err != nil {
		t.Fatalf("WriteOSCAL: %v", err)
	}
	hasAssessmentResults(t, buf.Bytes())
}

// @spec oscal-public-export
// @ac AC-05
func TestExportOSCAL_NilInputsError(t *testing.T) {
	t.Log("// @spec oscal-public-export")
	t.Log("// @ac AC-05")
	if _, err := ExportOSCALScan(nil, "host"); err == nil {
		t.Error("ExportOSCALScan(nil) should error")
	}
	if _, err := ExportOSCAL(nil); err == nil {
		t.Error("ExportOSCAL(nil) should error")
	}
}
