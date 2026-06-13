package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// nativeEvidenceVersion is the schema version stamped into emitted documents;
// it tracks schemas/kensa-evidence-v1.schema.json.
const nativeEvidenceVersion = "1.0.0"

// NativeEvidenceInput is the full context a native-evidence document needs.
// It deliberately spans both scan-side data (carried on the [api.ScanResult]:
// outcomes, capabilities, platform) and CLI-side data (the session command,
// hostname, and the resolved effective variables) that the ScanResult does not
// carry — assembled at the one point where both converge.
type NativeEvidenceInput struct {
	SessionID          string
	Timestamp          time.Time
	Command            string // "check" | "remediate" | "rollback"
	Hostname           string
	Result             *api.ScanResult
	Rules              []*api.Rule
	EffectiveVariables map[string]string
}

// WriteNativeEvidence assembles the Kensa native-evidence document (full-file
// shape: session + host context + per-rule results with observation evidence +
// summary) and writes it as indented JSON. The output validates against
// schemas/kensa-evidence-v1.schema.json.
func WriteNativeEvidence(w io.Writer, in NativeEvidenceInput) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(buildNativeEvidence(in))
}

func buildNativeEvidence(in NativeEvidenceInput) nativeEvidenceDoc {
	byID := make(map[string]*api.Rule, len(in.Rules))
	for _, r := range in.Rules {
		byID[r.ID] = r
	}

	var pass, fail, skip, errc int
	results := make([]nativeResult, 0, len(outcomesOf(in.Result)))
	for _, o := range outcomesOf(in.Result) {
		nr := nativeResult{
			RuleID:     o.RuleID,
			Severity:   o.Severity,
			Detail:     o.Detail,
			Evidence:   o.Evidence,
			Frameworks: groupFrameworks(o.FrameworkRefs),
		}
		if rule := byID[o.RuleID]; rule != nil {
			nr.Title = rule.Title
		}
		switch o.Status {
		case api.CompliancePass:
			nr.Passed = true
			pass++
		case api.ComplianceFail:
			fail++
		case api.ComplianceSkipped:
			nr.Skipped = true
			skip++
		case api.ComplianceError:
			nr.Errored = true
			errc++
		}
		results = append(results, nr)
	}

	var plat nativePlatform
	var caps map[string]bool
	if in.Result != nil {
		plat = nativePlatform{Family: in.Result.Platform.Family, Version: in.Result.Platform.Version}
		caps = in.Result.Capabilities
	}

	return nativeEvidenceDoc{
		Version: nativeEvidenceVersion,
		Session: nativeSession{
			ID:        in.SessionID,
			Timestamp: in.Timestamp.UTC().Format(time.RFC3339),
			Command:   in.Command,
		},
		Host: nativeHost{
			Hostname:           in.Hostname,
			Platform:           plat,
			Capabilities:       caps,
			EffectiveVariables: in.EffectiveVariables,
		},
		Results: results,
		Summary: nativeSummary{Total: len(results), Pass: pass, Fail: fail, Skip: skip, Error: errc},
	}
}

func outcomesOf(r *api.ScanResult) []api.RuleOutcome {
	if r == nil {
		return nil
	}
	return r.Outcomes
}

// groupFrameworks collapses the flat []FrameworkRef into a framework-id ->
// control-ids map. A rule may cite several controls within one framework, so
// the values are slices.
func groupFrameworks(refs []api.FrameworkRef) map[string][]string {
	if len(refs) == 0 {
		return nil
	}
	out := make(map[string][]string)
	for _, r := range refs {
		out[r.FrameworkID] = append(out[r.FrameworkID], r.ControlID)
	}
	return out
}

// ─── document shape (mirrors schemas/kensa-evidence-v1.schema.json) ───────────

type nativeEvidenceDoc struct {
	Version string         `json:"version"`
	Session nativeSession  `json:"session"`
	Host    nativeHost     `json:"host"`
	Results []nativeResult `json:"results"`
	Summary nativeSummary  `json:"summary"`
}

type nativeSession struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Command   string `json:"command"`
}

type nativeHost struct {
	Hostname           string            `json:"hostname"`
	Platform           nativePlatform    `json:"platform"`
	Capabilities       map[string]bool   `json:"capabilities,omitempty"`
	EffectiveVariables map[string]string `json:"effective_variables,omitempty"`
}

type nativePlatform struct {
	Family  string `json:"family"`
	Version string `json:"version,omitempty"`
}

type nativeResult struct {
	RuleID     string              `json:"rule_id"`
	Title      string              `json:"title,omitempty"`
	Severity   string              `json:"severity"`
	Passed     bool                `json:"passed"`
	Skipped    bool                `json:"skipped"`
	Errored    bool                `json:"errored,omitempty"`
	Detail     string              `json:"detail,omitempty"`
	Evidence   []api.CheckEvidence `json:"evidence,omitempty"`
	Frameworks map[string][]string `json:"frameworks,omitempty"`
}

type nativeSummary struct {
	Total int `json:"total"`
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Skip  int `json:"skip"`
	Error int `json:"error,omitempty"`
}
