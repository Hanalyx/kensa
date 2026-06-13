package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Hanalyx/kensa/api"
)

// sampleScanResult builds a ScanResult exercising the evidence-embedding
// paths: a pass and a fail outcome, framework refs (digit-leading native
// ids), and CheckEvidence carrying a command + stdout (→ base64 back-matter)
// and an expected value.
func sampleScanResult() *api.ScanResult {
	return &api.ScanResult{
		HostID: "host-a.example.com",
		Outcomes: []api.RuleOutcome{
			{
				RuleID:   "rule_sysctl_aslr",
				Status:   api.CompliancePass,
				Severity: "medium",
				Detail:   "kernel.randomize_va_space is 2",
				FrameworkRefs: []api.FrameworkRef{
					{FrameworkID: "cis_rhel9_v2", ControlID: "1.5.3"},
					{FrameworkID: "nist_800_53_r5", ControlID: "SC-30"},
				},
				Evidence: []api.CheckEvidence{
					{
						Method:   "sysctl_value",
						Command:  "sysctl -n kernel.randomize_va_space",
						Stdout:   "2\n",
						ExitCode: 0,
						Expected: "2",
					},
				},
			},
			{
				RuleID:   "rule_ssh_root_login",
				Status:   api.ComplianceFail,
				Severity: "high",
				Detail:   "PermitRootLogin is yes",
				FrameworkRefs: []api.FrameworkRef{
					{FrameworkID: "cis_rhel9_v2", ControlID: "5.2.3"},
				},
				Evidence: []api.CheckEvidence{
					{
						Method:   "config_value",
						Command:  "sshd -T | grep -i permitrootlogin",
						Stdout:   "permitrootlogin yes\n",
						ExitCode: 0,
						Expected: "no",
					},
				},
			},
		},
	}
}

// @spec evidence-oscal-scan
// @ac AC-01
func TestExportOSCALScan_ValidatesAgainst106Schema(t *testing.T) {
	t.Log("// @spec evidence-oscal-scan")
	t.Log("// @ac AC-01")
	schema := loadOSCALSchema(t)
	b, err := ExportOSCALScan(sampleScanResult(), "host-a.example.com")
	if err != nil {
		t.Fatalf("ExportOSCALScan: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("decode emitted OSCAL: %v", err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("scan-path OSCAL is not valid OSCAL 1.0.6 AR:\n%v", err)
	}
}

// @spec evidence-oscal-scan
// @ac AC-02
func TestExportOSCALScan_EmbedsCheckEvidence(t *testing.T) {
	t.Log("// @spec evidence-oscal-scan")
	t.Log("// @ac AC-02")
	b, err := ExportOSCALScan(sampleScanResult(), "host-a.example.com")
	if err != nil {
		t.Fatalf("ExportOSCALScan: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	res := doc.AssessmentResults.Results[0]
	if len(res.Observations) != 2 {
		t.Fatalf("expected 2 observations, got %d", len(res.Observations))
	}

	// First observation carries the sysctl evidence: command/method/exit-code
	// as namespaced props, expected="2", and an href into back-matter.
	obs := res.Observations[0]
	if len(obs.RelevantEvidence) != 1 {
		t.Fatalf("expected 1 relevant-evidence, got %d", len(obs.RelevantEvidence))
	}
	re := obs.RelevantEvidence[0]
	props := map[string]string{}
	for _, p := range re.Props {
		if p.NS != kensaOSCALNamespace {
			t.Errorf("prop %q has ns %q, want %q", p.Name, p.NS, kensaOSCALNamespace)
		}
		props[p.Name] = p.Value
	}
	if props["command"] != "sysctl -n kernel.randomize_va_space" {
		t.Errorf("command prop = %q", props["command"])
	}
	if props["method"] != "sysctl_value" {
		t.Errorf("method prop = %q", props["method"])
	}
	if props["exit-code"] != "0" {
		t.Errorf("exit-code prop = %q", props["exit-code"])
	}
	if props["expected"] != "2" {
		t.Errorf("expected prop = %q", props["expected"])
	}
	if re.Href == "" || !strings.HasPrefix(re.Href, "#") {
		t.Errorf("relevant-evidence href = %q, want a #-fragment", re.Href)
	}
}

// @spec evidence-oscal-scan
// @ac AC-03
func TestExportOSCALScan_RawStdoutInBackMatter(t *testing.T) {
	t.Log("// @spec evidence-oscal-scan")
	t.Log("// @ac AC-03")
	b, err := ExportOSCALScan(sampleScanResult(), "host-a.example.com")
	if err != nil {
		t.Fatalf("ExportOSCALScan: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	bm := doc.AssessmentResults.BackMatter
	if bm == nil {
		t.Fatal("expected back-matter, got nil")
	}
	if len(bm.Resources) != 2 {
		t.Fatalf("expected 2 back-matter resources, got %d", len(bm.Resources))
	}

	// Build href → resource index and confirm each observation's href resolves
	// to a resource whose decoded base64 is the original stdout.
	byUUID := map[string]oscalResource{}
	for _, r := range bm.Resources {
		byUUID[r.UUID] = r
	}
	res := doc.AssessmentResults.Results[0]
	wantStdout := map[string]string{
		"rule_sysctl_aslr":    "2\n",
		"rule_ssh_root_login": "permitrootlogin yes\n",
	}
	for i, obs := range res.Observations {
		href := obs.RelevantEvidence[0].Href
		ruleID := res.Findings[i].Title
		r, ok := byUUID[strings.TrimPrefix(href, "#")]
		if !ok {
			t.Fatalf("href %q does not resolve to a back-matter resource", href)
		}
		if r.Base64 == nil {
			t.Fatalf("resource %q has no base64 payload", r.UUID)
		}
		decoded, derr := base64.StdEncoding.DecodeString(r.Base64.Value)
		if derr != nil {
			t.Fatalf("base64 decode: %v", derr)
		}
		if string(decoded) != wantStdout[ruleID] {
			t.Errorf("rule %s: decoded stdout = %q, want %q", ruleID, decoded, wantStdout[ruleID])
		}
	}
}

// @spec evidence-oscal-scan
// @ac AC-04
func TestExportOSCALScan_ComplianceStateMapping(t *testing.T) {
	t.Log("// @spec evidence-oscal-scan")
	t.Log("// @ac AC-04")
	b, err := ExportOSCALScan(sampleScanResult(), "host-a.example.com")
	if err != nil {
		t.Fatalf("ExportOSCALScan: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	want := map[string]string{
		"rule_sysctl_aslr":    "satisfied",     // CompliancePass
		"rule_ssh_root_login": "not-satisfied", // ComplianceFail
	}
	for _, f := range doc.AssessmentResults.Results[0].Findings {
		if got := f.Target.Status.State; got != want[f.Title] {
			t.Errorf("rule %s: state = %q, want %q", f.Title, got, want[f.Title])
		}
	}
}

// @spec evidence-oscal-scan
// @ac AC-05
func TestExportOSCALScan_ControlIDsFrameworkPrefixed(t *testing.T) {
	t.Log("// @spec evidence-oscal-scan")
	t.Log("// @ac AC-05")
	b, err := ExportOSCALScan(sampleScanResult(), "host-a.example.com")
	if err != nil {
		t.Fatalf("ExportOSCALScan: %v", err)
	}

	var doc OSCALAssessmentResults
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	got := map[string]bool{}
	for _, sel := range doc.AssessmentResults.Results[0].ReviewedControls.ControlSelections {
		for _, c := range sel.IncludeControls {
			got[c.ControlID] = true
		}
	}
	for _, want := range []string{"cis_rhel9_v2-1.5.3", "nist_800_53_r5-SC-30", "cis_rhel9_v2-5.2.3"} {
		if !got[want] {
			t.Errorf("missing control-id %q in %v", want, got)
		}
	}
}

// @spec evidence-oscal-scan
// @ac AC-06
func TestExportOSCALScan_NilResult(t *testing.T) {
	t.Log("// @spec evidence-oscal-scan")
	t.Log("// @ac AC-06")
	if _, err := ExportOSCALScan(nil, "host"); err == nil {
		t.Fatal("expected error for nil result, got nil")
	}
}

// @spec evidence-oscal-scan
// @ac AC-01
func TestWriteOSCALScan(t *testing.T) {
	t.Log("// @spec evidence-oscal-scan")
	t.Log("// @ac AC-01")
	var buf bytes.Buffer
	if err := WriteOSCALScan(&buf, sampleScanResult(), "host-a.example.com"); err != nil {
		t.Fatalf("WriteOSCALScan: %v", err)
	}
	var raw interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Errorf("WriteOSCALScan output is not valid JSON: %v", err)
	}
}
