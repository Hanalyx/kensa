package output

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Hanalyx/kensa/api"
)

const nativeSchemaPath = "../../schemas/kensa-evidence-v1.schema.json"

func loadNativeSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(nativeSchemaPath)
	if err != nil {
		t.Fatalf("open native schema: %v", err)
	}
	defer func() { _ = f.Close() }()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("decode native schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("kensa-evidence.json", doc); err != nil {
		t.Fatalf("add native schema: %v", err)
	}
	s, err := c.Compile("kensa-evidence.json")
	if err != nil {
		t.Fatalf("compile native schema: %v", err)
	}
	return s
}

// sampleInput builds a NativeEvidenceInput exercising every result kind
// (pass/fail/skip/error), structured evidence, framework refs, capabilities,
// and effective variables — i.e. the full document surface.
func sampleInput() NativeEvidenceInput {
	return NativeEvidenceInput{
		SessionID: "abc123",
		Timestamp: time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC),
		Command:   "check",
		Hostname:  "web01",
		EffectiveVariables: map[string]string{
			"pam_faillock_deny": "3",
			"login_defs_umask":  "077",
		},
		Rules: []*api.Rule{
			{ID: "rule-pass", Title: "Disable DCCP", Severity: "medium"},
			{ID: "rule-fail", Title: "ASLR", Severity: "high"},
		},
		Result: &api.ScanResult{
			Capabilities: api.CapabilitySet{"selinux": true, "fips_mode": false},
			Platform:     api.DetectedPlatform{Family: "rhel", Version: "9.6"},
			Outcomes: []api.RuleOutcome{
				{
					RuleID: "rule-pass", Status: api.CompliancePass, Severity: "medium",
					Detail:        "kernel_module_state: dccp blacklisted",
					FrameworkRefs: []api.FrameworkRef{{FrameworkID: "nist_800_53", ControlID: "CM-7"}, {FrameworkID: "cis_rhel9", ControlID: "3.2.1"}},
					Evidence: []api.CheckEvidence{{
						Method: "kernel_module_state", Command: "modprobe -n -v dccp 2>&1",
						Stdout: "install /bin/false", ExitCode: 0, Expected: "disabled",
					}},
				},
				{
					RuleID: "rule-fail", Status: api.ComplianceFail, Severity: "high",
					Detail:        "sysctl_value: kernel.randomize_va_space = 1, expected 2",
					FrameworkRefs: []api.FrameworkRef{{FrameworkID: "nist_800_53", ControlID: "SC-30"}},
					Evidence: []api.CheckEvidence{{
						Method: "sysctl_value", Command: "sysctl -n kernel.randomize_va_space",
						Stdout: "1", ExitCode: 0, Expected: "2",
					}},
				},
				{RuleID: "rule-skip", Status: api.ComplianceSkipped, Severity: "low", Detail: "not applicable"},
				{RuleID: "rule-err", Status: api.ComplianceError, Severity: "high", Detail: "transport error", Err: nil},
			},
		},
	}
}

// TestNativeEvidence_ValidatesAgainstSchema is the gate: every document
// WriteNativeEvidence emits MUST validate against the v1 native-evidence
// schema (the schema landed in the v0.4.0 foundation PR).
//
// @spec output-native-evidence
func TestNativeEvidence_ValidatesAgainstSchema(t *testing.T) {
	t.Run("output-native-evidence/AC-01", func(t *testing.T) {
		// @spec output-native-evidence
		// @ac AC-01
		schema := loadNativeSchema(t)
		var buf bytes.Buffer
		if err := WriteNativeEvidence(&buf, sampleInput()); err != nil {
			t.Fatalf("WriteNativeEvidence: %v", err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("decode emitted evidence: %v", err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("emitted native evidence is not schema-valid:\n%v\n--- doc ---\n%s", err, buf.String())
		}
	})
}

// TestNativeEvidence_FullContext asserts the document carries the host context
// and per-rule evidence/frameworks/summary — the full-file parity surface.
//
// @spec output-native-evidence
func TestNativeEvidence_FullContext(t *testing.T) {
	t.Run("output-native-evidence/AC-02", func(t *testing.T) {
		// @spec output-native-evidence
		// @ac AC-02
		doc := buildNativeEvidence(sampleInput())

		if doc.Host.Platform.Family != "rhel" || doc.Host.Platform.Version != "9.6" {
			t.Errorf("platform: got %+v", doc.Host.Platform)
		}
		if doc.Host.Capabilities["selinux"] != true {
			t.Errorf("capabilities not carried: %+v", doc.Host.Capabilities)
		}
		if doc.Host.EffectiveVariables["pam_faillock_deny"] != "3" {
			t.Errorf("effective_variables not carried: %+v", doc.Host.EffectiveVariables)
		}
		if doc.Summary.Total != 4 || doc.Summary.Pass != 1 || doc.Summary.Fail != 1 || doc.Summary.Skip != 1 || doc.Summary.Error != 1 {
			t.Errorf("summary wrong: %+v", doc.Summary)
		}
		// per-rule: evidence + frameworks grouped per framework id.
		var passResult nativeResult
		for _, r := range doc.Results {
			if r.RuleID == "rule-pass" {
				passResult = r
			}
		}
		if len(passResult.Evidence) != 1 || passResult.Evidence[0].Command == "" {
			t.Errorf("pass-result evidence missing: %+v", passResult.Evidence)
		}
		if got := passResult.Frameworks["nist_800_53"]; len(got) != 1 || got[0] != "CM-7" {
			t.Errorf("frameworks not grouped: %+v", passResult.Frameworks)
		}
		if !passResult.Passed {
			t.Errorf("rule-pass should be passed")
		}
	})
}

// TestFanOutNativeEvidence_WritesSchemaValid asserts the fan-out path (which
// the CLI `-o evidence:` wiring uses) writes a schema-valid document to a spec
// destination.
//
// @spec output-native-evidence
func TestFanOutNativeEvidence_WritesSchemaValid(t *testing.T) {
	t.Run("output-native-evidence/AC-04", func(t *testing.T) {
		// @spec output-native-evidence
		// @ac AC-04
		schema := loadNativeSchema(t)
		var buf bytes.Buffer
		// Spec with empty Path => the fan-out writes to the stdout override.
		specs := []Spec{{Format: "evidence", Path: ""}}
		if err := FanOutNativeEvidence(specs, &buf, sampleInput()); err != nil {
			t.Fatalf("FanOutNativeEvidence: %v", err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("decode fan-out evidence: %v", err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("fan-out native evidence not schema-valid:\n%v", err)
		}
	})
}
