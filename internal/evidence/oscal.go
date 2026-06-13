package evidence

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// OSCALAssessmentResults is the top-level wrapper for an OSCAL
// Assessment Results document (OSCAL 1.0.6).
type OSCALAssessmentResults struct {
	AssessmentResults oscalAssessmentResultsBody `json:"assessment-results"`
}

type oscalAssessmentResultsBody struct {
	UUID       string           `json:"uuid"`
	Metadata   oscalMetadata    `json:"metadata"`
	ImportAP   oscalImportAP    `json:"import-ap"`
	Results    []oscalResult    `json:"results"`
	BackMatter *oscalBackMatter `json:"back-matter,omitempty"`
}

// oscalBackMatter holds embedded resources — raw check output, base64-encoded —
// referenced from relevant-evidence by href. The OSCAL-sanctioned home for
// arbitrary/large blobs.
type oscalBackMatter struct {
	Resources []oscalResource `json:"resources"`
}

type oscalResource struct {
	UUID   string       `json:"uuid"`
	Title  string       `json:"title,omitempty"`
	Base64 *oscalBase64 `json:"base64,omitempty"`
}

type oscalBase64 struct {
	MediaType string `json:"media-type,omitempty"`
	Value     string `json:"value"`
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
	Subjects         []oscalSubject          `json:"subjects,omitempty"`
	Collected        string                  `json:"collected"`
	RelevantEvidence []oscalRelevantEvidence `json:"relevant-evidence"`
}

// oscalSubject identifies what an observation assessed — here, the host, as an
// inventory item.
type oscalSubject struct {
	SubjectUUID string `json:"subject-uuid"`
	Type        string `json:"type"`
}

type oscalRelevantEvidence struct {
	Description string      `json:"description"`
	Href        string      `json:"href,omitempty"`
	Props       []oscalProp `json:"props,omitempty"`
}

type oscalProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// NS qualifies a non-OSCAL-standard prop name with the owning vocabulary's
	// namespace, per the OSCAL prop model. Kensa's custom props carry
	// [kensaOSCALNamespace]; omitted for OSCAL-standard names.
	NS string `json:"ns,omitempty"`
}

// kensaOSCALNamespace is the namespace URI Kensa stamps on every non-standard
// OSCAL prop (signing-key-id, transaction-id, …) so it does not squat in the
// OSCAL default namespace. Part of the public OSCAL artifact contract.
const kensaOSCALNamespace = "https://hanalyx.com/kensa/ns/oscal/v1/"

// oscalControlID renders a framework reference as a valid OSCAL control-id
// token. OSCAL control-id must match `^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$` — it
// must start with a letter/underscore — but native control identifiers like
// CIS "3.3.1" or PCI "2.2.6" start with a digit. Prefixing with the framework
// id (which starts with a letter) yields a valid token AND disambiguates which
// framework a control belongs to inside one include-controls list.
func oscalControlID(ref api.FrameworkRef) string {
	if ref.FrameworkID == "" {
		return ref.ControlID
	}
	return ref.FrameworkID + "-" + ref.ControlID
}

// hostSubjectUUID derives a stable subject UUID for a host id. A v5 (SHA-1)
// UUID is deterministic per host (so re-emitting an assessment for the same
// host yields the same subject) and satisfies the OSCAL uuid pattern (version
// nibble 5 ∈ [45]; RFC4122 variant).
func hostSubjectUUID(hostID string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("kensa-host:"+hostID)).String()
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

	// Build control selections from FrameworkRefs. control-id is the
	// framework-prefixed token (see oscalControlID) so digit-leading native
	// ids (CIS "3.3.1", PCI "2.2.6") are valid OSCAL tokens.
	var controlRefs []oscalControlRef
	for _, ref := range envelope.FrameworkRefs {
		controlRefs = append(controlRefs, oscalControlRef{ControlID: oscalControlID(ref)})
	}
	if len(controlRefs) == 0 {
		controlRefs = []oscalControlRef{}
	}

	observation := oscalObservation{
		UUID:        observationUUID,
		Description: fmt.Sprintf("Pre-state captured: %d steps", len(envelope.PreStateBundle)),
		// TEST: the remediation was applied and validated by exercising the
		// host, not merely examining static documentation.
		Methods: []string{"TEST"},
		Subjects: []oscalSubject{
			{SubjectUUID: hostSubjectUUID(envelope.HostID), Type: "inventory-item"},
		},
		Collected: startStr,
		RelevantEvidence: []oscalRelevantEvidence{
			{
				Description: fmt.Sprintf("Evidence envelope signed by key %s", envelope.SigningKeyID),
				Props: []oscalProp{
					{Name: "signing-key-id", Value: envelope.SigningKeyID, NS: kensaOSCALNamespace},
					{Name: "transaction-id", Value: txnIDStr, NS: kensaOSCALNamespace},
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
