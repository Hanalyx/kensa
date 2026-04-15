package evidence

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

func makeTestEnvelope(status api.TransactionStatus, refs []api.FrameworkRef) *api.EvidenceEnvelope {
	now := time.Now().UTC()
	return &api.EvidenceEnvelope{
		SchemaVersion:  "v1",
		TransactionID:  uuid.New(),
		RuleID:         "test_rule_001",
		HostID:         "host-a.example.com",
		StartedAt:      now.Add(-5 * time.Second),
		FinishedAt:     now,
		Decision:       status,
		SigningKeyID:   "deadbeef",
		FrameworkRefs:  refs,
		PreStateBundle: []api.PreState{{StepIndex: 0, Mechanism: "file_permissions"}},
	}
}

func TestExportOSCAL_CommittedIsSatisfied(t *testing.T) {
	env := makeTestEnvelope(api.StatusCommitted, nil)
	b, err := ExportOSCAL(env)
	if err != nil {
		t.Fatalf("ExportOSCAL returned error: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	results := doc.AssessmentResults.Results
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	findings := results[0].Findings
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	state := findings[0].Target.Status.State
	if state != "satisfied" {
		t.Errorf("expected state %q, got %q", "satisfied", state)
	}
}

func TestExportOSCAL_RolledBackIsNotSatisfied(t *testing.T) {
	env := makeTestEnvelope(api.StatusRolledBack, nil)
	b, err := ExportOSCAL(env)
	if err != nil {
		t.Fatalf("ExportOSCAL returned error: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	state := doc.AssessmentResults.Results[0].Findings[0].Target.Status.State
	if state != "not-satisfied" {
		t.Errorf("expected state %q, got %q", "not-satisfied", state)
	}
}

func TestExportOSCAL_ValidJSON(t *testing.T) {
	env := makeTestEnvelope(api.StatusCommitted, nil)
	b, err := ExportOSCAL(env)
	if err != nil {
		t.Fatalf("ExportOSCAL returned error: %v", err)
	}
	var raw interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Errorf("json.Unmarshal failed: %v", err)
	}
}

func TestExportOSCAL_FrameworkRefsAsControlSelections(t *testing.T) {
	refs := []api.FrameworkRef{
		{FrameworkID: "cis_rhel9_v2", ControlID: "5.2.3"},
		{FrameworkID: "nist_800_53_r5", ControlID: "AC-6(2)"},
	}
	env := makeTestEnvelope(api.StatusCommitted, refs)
	b, err := ExportOSCAL(env)
	if err != nil {
		t.Fatalf("ExportOSCAL returned error: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	selections := doc.AssessmentResults.Results[0].ReviewedControls.ControlSelections
	if len(selections) != 1 {
		t.Fatalf("expected 1 control-selection group, got %d", len(selections))
	}
	controls := selections[0].IncludeControls
	if len(controls) != 2 {
		t.Fatalf("expected 2 include-controls entries, got %d", len(controls))
	}
	if controls[0].ControlID != "5.2.3" {
		t.Errorf("expected control-id %q, got %q", "5.2.3", controls[0].ControlID)
	}
	if controls[1].ControlID != "AC-6(2)" {
		t.Errorf("expected control-id %q, got %q", "AC-6(2)", controls[1].ControlID)
	}
}

func TestWriteOSCAL(t *testing.T) {
	env := makeTestEnvelope(api.StatusCommitted, nil)
	var buf bytes.Buffer
	if err := WriteOSCAL(&buf, env); err != nil {
		t.Fatalf("WriteOSCAL returned error: %v", err)
	}
	var raw interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Errorf("WriteOSCAL output is not valid JSON: %v", err)
	}
}

func TestExportOSCAL_MetadataFields(t *testing.T) {
	env := makeTestEnvelope(api.StatusCommitted, nil)
	b, err := ExportOSCAL(env)
	if err != nil {
		t.Fatalf("ExportOSCAL returned error: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	meta := doc.AssessmentResults.Metadata
	if meta.Title != "Kensa Assessment Results" {
		t.Errorf("unexpected title: %q", meta.Title)
	}
	if meta.OSCALVersion != "1.0.6" {
		t.Errorf("unexpected oscal-version: %q", meta.OSCALVersion)
	}
	if meta.Version != "1.0.0" {
		t.Errorf("unexpected version: %q", meta.Version)
	}
	if doc.AssessmentResults.ImportAP.Href != "#" {
		t.Errorf("unexpected import-ap href: %q", doc.AssessmentResults.ImportAP.Href)
	}
}

func TestExportOSCAL_ObservationLinkedToFinding(t *testing.T) {
	env := makeTestEnvelope(api.StatusCommitted, nil)
	b, err := ExportOSCAL(env)
	if err != nil {
		t.Fatalf("ExportOSCAL returned error: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	result := doc.AssessmentResults.Results[0]
	if len(result.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(result.Observations))
	}
	obsUUID := result.Observations[0].UUID
	relObs := result.Findings[0].RelatedObservations
	if len(relObs) != 1 {
		t.Fatalf("expected 1 related-observation, got %d", len(relObs))
	}
	if relObs[0].ObservationUUID != obsUUID {
		t.Errorf("finding.related-observations[0].observation-uuid %q does not match observation.uuid %q",
			relObs[0].ObservationUUID, obsUUID)
	}
}
