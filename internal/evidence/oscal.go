package evidence

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// OSCALAssessmentResults is the top-level wrapper for an OSCAL
// Assessment Results document (OSCAL 1.0.6).
type OSCALAssessmentResults struct {
	AssessmentResults oscalAssessmentResultsBody `json:"assessment-results"`
}

type oscalAssessmentResultsBody struct {
	UUID     string        `json:"uuid"`
	Metadata oscalMetadata `json:"metadata"`
	ImportAP oscalImportAP `json:"import-ap"`
	Results  []oscalResult `json:"results"`
}

type oscalMetadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

type oscalImportAP struct {
	Href string `json:"href"`
}

type oscalResult struct {
	UUID             string                `json:"uuid"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Start            string                `json:"start"`
	End              string                `json:"end"`
	ReviewedControls oscalReviewedControls `json:"reviewed-controls"`
	Findings         []oscalFinding        `json:"findings"`
	Observations     []oscalObservation    `json:"observations"`
}

type oscalReviewedControls struct {
	ControlSelections []oscalControlSelection `json:"control-selections"`
}

type oscalControlSelection struct {
	IncludeControls []oscalControlRef `json:"include-controls"`
}

type oscalControlRef struct {
	ControlID string `json:"control-id"`
}

type oscalFinding struct {
	UUID                string                    `json:"uuid"`
	Title               string                    `json:"title"`
	Description         string                    `json:"description"`
	Target              oscalFindingTarget        `json:"target"`
	RelatedObservations []oscalRelatedObservation `json:"related-observations"`
}

type oscalFindingTarget struct {
	Type     string            `json:"type"`
	TargetID string            `json:"target-id"`
	Status   oscalTargetStatus `json:"status"`
}

type oscalTargetStatus struct {
	State string `json:"state"`
}

type oscalRelatedObservation struct {
	ObservationUUID string `json:"observation-uuid"`
}

type oscalObservation struct {
	UUID             string                  `json:"uuid"`
	Description      string                  `json:"description"`
	Methods          []string                `json:"methods"`
	Collected        string                  `json:"collected"`
	RelevantEvidence []oscalRelevantEvidence `json:"relevant-evidence"`
}

type oscalRelevantEvidence struct {
	Description string      `json:"description"`
	Props       []oscalProp `json:"props"`
}

type oscalProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// satisfiedState maps a [api.TransactionStatus] to the OSCAL finding
// state: "satisfied" for [api.StatusCommitted], "not-satisfied"
// otherwise.
func satisfiedState(status api.TransactionStatus) string {
	if status == api.StatusCommitted {
		return "satisfied"
	}
	return "not-satisfied"
}

// ExportOSCAL converts envelope to an OSCAL Assessment Results document.
// The returned bytes are valid JSON.
func ExportOSCAL(envelope *api.EvidenceEnvelope) ([]byte, error) {
	if envelope == nil {
		return nil, fmt.Errorf("evidence: ExportOSCAL: nil envelope")
	}

	docUUID := uuid.New().String()
	findingUUID := uuid.New().String()
	observationUUID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	startStr := envelope.StartedAt.UTC().Format(time.RFC3339)
	endStr := envelope.FinishedAt.UTC().Format(time.RFC3339)
	txnIDStr := envelope.TransactionID.String()

	// Build control selections from FrameworkRefs.
	var controlRefs []oscalControlRef
	for _, ref := range envelope.FrameworkRefs {
		controlRefs = append(controlRefs, oscalControlRef{ControlID: ref.ControlID})
	}
	if len(controlRefs) == 0 {
		controlRefs = []oscalControlRef{}
	}

	observation := oscalObservation{
		UUID:        observationUUID,
		Description: fmt.Sprintf("Pre-state captured: %d steps", len(envelope.PreStateBundle)),
		Methods:     []string{"EXAMINE"},
		Collected:   startStr,
		RelevantEvidence: []oscalRelevantEvidence{
			{
				Description: fmt.Sprintf("Evidence envelope signed by key %s", envelope.SigningKeyID),
				Props: []oscalProp{
					{Name: "signing-key-id", Value: envelope.SigningKeyID},
					{Name: "transaction-id", Value: txnIDStr},
				},
			},
		},
	}

	finding := oscalFinding{
		UUID:        findingUUID,
		Title:       envelope.RuleID,
		Description: fmt.Sprintf("Transaction decision: %s", envelope.Decision),
		Target: oscalFindingTarget{
			Type:     "objective-id",
			TargetID: envelope.RuleID,
			Status: oscalTargetStatus{
				State: satisfiedState(envelope.Decision),
			},
		},
		RelatedObservations: []oscalRelatedObservation{
			{ObservationUUID: observationUUID},
		},
	}

	result := oscalResult{
		UUID:        txnIDStr,
		Title:       fmt.Sprintf("%s on %s", envelope.RuleID, envelope.HostID),
		Description: "Automated remediation result from Kensa",
		Start:       startStr,
		End:         endStr,
		ReviewedControls: oscalReviewedControls{
			ControlSelections: []oscalControlSelection{
				{IncludeControls: controlRefs},
			},
		},
		Findings:     []oscalFinding{finding},
		Observations: []oscalObservation{observation},
	}

	doc := OSCALAssessmentResults{
		AssessmentResults: oscalAssessmentResultsBody{
			UUID: docUUID,
			Metadata: oscalMetadata{
				Title:        "Kensa Assessment Results",
				LastModified: now,
				Version:      "1.0.0",
				OSCALVersion: "1.0.6",
			},
			ImportAP: oscalImportAP{Href: "#"},
			Results:  []oscalResult{result},
		},
	}

	b, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("evidence: ExportOSCAL: marshal: %w", err)
	}
	return b, nil
}

// WriteOSCAL encodes envelope as an OSCAL Assessment Results document
// and writes it to w.
func WriteOSCAL(w io.Writer, envelope *api.EvidenceEnvelope) error {
	b, err := ExportOSCAL(envelope)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
