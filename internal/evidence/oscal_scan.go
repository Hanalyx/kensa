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
			}
			// Props carry ONLY single-line StringDatatype-valid tokens. method
			// and exit-code are clean by construction; expected is guarded. The
			// command is deliberately NOT a prop — it is frequently a multi-line
			// shell script, which can never satisfy the prop-value pattern
			// (^\S(.*\S)?$); it goes to remarks (below) instead.
			re.Props = appendValidProp(re.Props, "method", ev.Method)
			re.Props = appendValidProp(re.Props, "exit-code", strconv.Itoa(ev.ExitCode))
			re.Props = appendValidProp(re.Props, "expected", ev.Expected)
			if ev.Truncated {
				re.Props = appendValidProp(re.Props, "truncated", "true")
			}
			// The verbatim command — multi-line-safe — lives in remarks (OSCAL
			// markup-multiline, no value pattern) so an auditor can reproduce the
			// check exactly.
			if ev.Command != "" {
				re.Remarks = "Command:\n" + ev.Command
			}
			// Raw stdout goes to a base64 back-matter resource, referenced by
			// href — keeps the inline observation small while staying valid.
			if ev.Stdout != "" {
				resUUID := uuid.New().String()
				resources = append(resources, oscalResource{
					UUID:   resUUID,
					Title:  "stdout (" + ev.Method + ")",
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
					ControlSelections: []oscalControlSelection{controlSelection(controlRefs)},
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

// appendValidProp appends a Kensa-namespaced prop only when value is a legal
// OSCAL StringDatatype token (see oscalValidToken). A value that would violate
// the prop-value pattern — empty, whitespace-bounded, or multi-line — is
// dropped rather than emitted as schema-invalid OSCAL; such content is carried
// in remarks/description instead. This keeps the emitted document conformant
// regardless of what a check's params contain.
func appendValidProp(props []oscalProp, name, value string) []oscalProp {
	if !oscalValidToken(value) {
		return props
	}
	return append(props, oscalProp{Name: name, Value: value, NS: kensaOSCALNamespace})
}

// evidenceDescription renders a single-line human summary of one check's
// observation evidence. It deliberately does NOT inline the command (which may
// be a multi-line script — that lives verbatim in the relevant-evidence
// remarks); the description stays a short, queryable one-liner.
func evidenceDescription(ev api.CheckEvidence) string {
	if ev.Expected != "" {
		return fmt.Sprintf("Check %s (exit %d; expected %q)", ev.Method, ev.ExitCode, ev.Expected)
	}
	return fmt.Sprintf("Check %s (exit %d)", ev.Method, ev.ExitCode)
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
