package evidence

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// ExportOSCALScan converts a read-only [api.ScanResult] into an OSCAL 1.0.6
// Assessment Results document. Each [api.RuleOutcome] becomes a finding plus an
// observation, and the observation embeds the rule's structured observation
// evidence: the command, exit code, and expected value as namespaced props, and
// the raw stdout as a base64 back-matter resource referenced by href. This is
// what makes the OSCAL artifact carry reproducible proof, not just a verdict.
//
// The output validates against the vendored NIST OSCAL 1.0.6 AR schema (the
// hard conformance gate covers it).
func ExportOSCALScan(result *api.ScanResult, hostname string) ([]byte, error) {
	if result == nil {
		return nil, fmt.Errorf("evidence: ExportOSCALScan: nil result")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	hostSubj := hostSubjectUUID(hostname)

	var findings []oscalFinding
	var observations []oscalObservation
	var resources []oscalResource
	var controlRefs []oscalControlRef
	seenControl := map[string]bool{}

	for _, o := range result.Outcomes {
		obsUUID := uuid.New().String()

		var relEv []oscalRelevantEvidence
		for _, ev := range o.Evidence {
			re := oscalRelevantEvidence{
				Description: evidenceDescription(ev),
				Props: []oscalProp{
					{Name: "method", Value: ev.Method, NS: kensaOSCALNamespace},
					{Name: "command", Value: ev.Command, NS: kensaOSCALNamespace},
					{Name: "exit-code", Value: strconv.Itoa(ev.ExitCode), NS: kensaOSCALNamespace},
				},
			}
			if ev.Expected != "" {
				re.Props = append(re.Props, oscalProp{Name: "expected", Value: ev.Expected, NS: kensaOSCALNamespace})
			}
			if ev.Truncated {
				re.Props = append(re.Props, oscalProp{Name: "truncated", Value: "true", NS: kensaOSCALNamespace})
			}
			// Raw stdout goes to a base64 back-matter resource, referenced by
			// href — keeps the inline observation small while staying valid.
			if ev.Stdout != "" {
				resUUID := uuid.New().String()
				resources = append(resources, oscalResource{
					UUID:   resUUID,
					Title:  "stdout of: " + ev.Command,
					Base64: &oscalBase64{MediaType: "text/plain", Value: base64.StdEncoding.EncodeToString([]byte(ev.Stdout))},
				})
				re.Href = "#" + resUUID
			}
			relEv = append(relEv, re)
		}
		if len(relEv) == 0 {
			// A rule with no command (e.g. skipped) still needs a valid
			// observation; carry the human detail.
			relEv = []oscalRelevantEvidence{{Description: nonEmpty(o.Detail, "no observation evidence")}}
		}

		observations = append(observations, oscalObservation{
			UUID:             obsUUID,
			Description:      fmt.Sprintf("Check of rule %s: %s", o.RuleID, nonEmpty(o.Detail, string(o.Status))),
			Methods:          []string{"TEST"},
			Subjects:         []oscalSubject{{SubjectUUID: hostSubj, Type: "inventory-item"}},
			Collected:        now,
			RelevantEvidence: relEv,
		})

		findings = append(findings, oscalFinding{
			UUID:        uuid.New().String(),
			Title:       o.RuleID,
			Description: fmt.Sprintf("Compliance verdict: %s", o.Status),
			Target: oscalFindingTarget{
				Type:     "objective-id",
				TargetID: o.RuleID,
				Status:   oscalTargetStatus{State: complianceState(o.Status)},
			},
			RelatedObservations: []oscalRelatedObservation{{ObservationUUID: obsUUID}},
		})

		for _, ref := range o.FrameworkRefs {
			cid := oscalControlID(ref)
			if !seenControl[cid] {
				seenControl[cid] = true
				controlRefs = append(controlRefs, oscalControlRef{ControlID: cid})
			}
		}
	}
	if controlRefs == nil {
		controlRefs = []oscalControlRef{}
	}

	var backMatter *oscalBackMatter
	if len(resources) > 0 {
		backMatter = &oscalBackMatter{Resources: resources}
	}

	doc := OSCALAssessmentResults{
		AssessmentResults: oscalAssessmentResultsBody{
			UUID: uuid.New().String(),
			Metadata: oscalMetadata{
				Title:        "Kensa Assessment Results",
				LastModified: now,
				Version:      "1.0.0",
				OSCALVersion: "1.0.6",
			},
			ImportAP: oscalImportAP{Href: "#"},
			Results: []oscalResult{{
				UUID:        uuid.New().String(),
				Title:       fmt.Sprintf("Compliance scan on %s", nonEmpty(hostname, "host")),
				Description: "Automated compliance scan result from Kensa",
				Start:       now,
				End:         now,
				ReviewedControls: oscalReviewedControls{
					ControlSelections: []oscalControlSelection{{IncludeControls: controlRefs}},
				},
				Findings:     findings,
				Observations: observations,
			}},
			BackMatter: backMatter,
		},
	}

	return json.Marshal(doc)
}

// WriteOSCALScan encodes a scan result as OSCAL and writes it to w.
func WriteOSCALScan(w io.Writer, result *api.ScanResult, hostname string) error {
	b, err := ExportOSCALScan(result, hostname)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// complianceState maps a compliance verdict to the OSCAL finding state. Only a
// pass is "satisfied"; fail/skipped/error are "not-satisfied".
func complianceState(s api.ComplianceStatus) string {
	if s == api.CompliancePass {
		return "satisfied"
	}
	return "not-satisfied"
}

// evidenceDescription renders a human-readable summary of one check's
// observation evidence.
func evidenceDescription(ev api.CheckEvidence) string {
	if ev.Expected != "" {
		return fmt.Sprintf("Check %s: `%s` -> exit %d; expected %q", ev.Method, ev.Command, ev.ExitCode, ev.Expected)
	}
	return fmt.Sprintf("Check %s: `%s` -> exit %d", ev.Method, ev.Command, ev.ExitCode)
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
