package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// goldenFixture is one canonical OSCAL test case. The envelope is
// deterministic (fixed UUID, fixed timestamps, fixed framework
// refs); the *Output* is non-deterministic (ExportOSCAL generates
// new UUIDs and uses time.Now()), so the golden-compare path runs
// the output through normalizeOSCAL before diffing.
type goldenFixture struct {
	name     string // file basename without extension
	envelope *api.EvidenceEnvelope
}

// fixtureUUID is a stable UUID used in the input envelope's
// transaction-id. ExportOSCAL surfaces it (see oscalResult.UUID =
// txnIDStr at oscal.go:169) so it stays deterministic across runs
// and acts as a pinpoint anchor in the golden file.
var fixtureUUID = uuid.MustParse("11111111-2222-3333-4444-555555555555")

// fixtureTime is a stable instant used in the envelope's
// StartedAt / FinishedAt. ExportOSCAL emits these as RFC3339
// strings; deterministic input → deterministic input-derived
// fields. The other timestamps (metadata.last-modified,
// observation.collected) are time.Now() inside ExportOSCAL and
// get normalized.
var fixtureTime = time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)

// goldenFixtures enumerates the three regression cases per spec
// C-02: committed → satisfied, rolled_back → not-satisfied,
// multi-framework refs.
var goldenFixtures = []goldenFixture{
	{
		name: "committed",
		envelope: &api.EvidenceEnvelope{
			SchemaVersion: "v1",
			TransactionID: fixtureUUID,
			RuleID:        "sysctl-ip-forward-disabled",
			HostID:        "host-fixture-a",
			StartedAt:     fixtureTime,
			FinishedAt:    fixtureTime.Add(2 * time.Second),
			Decision:      api.StatusCommitted,
			Severity:      "high",
			SigningKeyID:  "test-key-1",
			FrameworkRefs: []api.FrameworkRef{
				{FrameworkID: "cis_rhel9", ControlID: "3.3.1"},
			},
		},
	},
	{
		name: "rolled_back",
		envelope: &api.EvidenceEnvelope{
			SchemaVersion: "v1",
			TransactionID: fixtureUUID,
			RuleID:        "sysctl-ip-forward-disabled",
			HostID:        "host-fixture-a",
			StartedAt:     fixtureTime,
			FinishedAt:    fixtureTime.Add(2 * time.Second),
			Decision:      api.StatusRolledBack,
			Severity:      "high",
			SigningKeyID:  "test-key-1",
			FrameworkRefs: []api.FrameworkRef{
				{FrameworkID: "cis_rhel9", ControlID: "3.3.1"},
			},
		},
	},
	{
		name: "multi_framework",
		envelope: &api.EvidenceEnvelope{
			SchemaVersion: "v1",
			TransactionID: fixtureUUID,
			RuleID:        "sysctl-ip-forward-disabled",
			HostID:        "host-fixture-a",
			StartedAt:     fixtureTime,
			FinishedAt:    fixtureTime.Add(2 * time.Second),
			Decision:      api.StatusCommitted,
			Severity:      "high",
			SigningKeyID:  "test-key-1",
			FrameworkRefs: []api.FrameworkRef{
				{FrameworkID: "cis_rhel8", ControlID: "3.3.2.1"},
				{FrameworkID: "cis_rhel9", ControlID: "3.3.1"},
				{FrameworkID: "nist_800_53", ControlID: "CM-7"},
				{FrameworkID: "stig_rhel9", ControlID: "V-257936"},
			},
		},
	},
}

// uuidRE matches the canonical 8-4-4-4-12 hex UUID format.
// ExportOSCAL generates UUIDs for the document, the finding, and
// the observation (oscal.go:118-120). All three need normalization.
// We keep the input transactionID (fixtureUUID) by NOT replacing
// it: it appears as oscalResult.UUID and as transaction-id prop;
// since we know its exact bytes, the regex won't match if we
// use a token like UUID_ZERO_PLACEHOLDER below.
var uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// timestampRE matches an RFC3339 timestamp. ExportOSCAL emits
// metadata.last-modified and observation.collected as time.Now();
// the input envelope's StartedAt/FinishedAt are deterministic
// from fixtureTime and need NOT be normalized. We replace all
// matches uniformly — the deterministic ones happen to equal the
// non-deterministic ones structurally so the placeholder is the
// same.
var timestampRE = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z`)

// normalizeOSCAL replaces non-deterministic UUIDs and timestamps
// with placeholders so the byte-diff against the golden file is
// stable across runs. fixtureUUID is preserved (replaced with a
// distinct placeholder) so the golden distinguishes "the input
// transaction ID" from "a generated UUID."
func normalizeOSCAL(b []byte) []byte {
	s := string(b)
	// Replace fixtureUUID first with a distinct token, otherwise
	// the generic uuidRE would also catch it.
	s = strings.ReplaceAll(s, fixtureUUID.String(), "FIXTURE_TXN_UUID")
	s = uuidRE.ReplaceAllString(s, "GENERATED_UUID")
	s = timestampRE.ReplaceAllString(s, "FIXTURE_TIMESTAMP")
	// Pretty-print with stable key order so structural diffs
	// surface as line diffs (jq --sort-keys -style).
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		// Normalization failed — return the partially-replaced
		// string as-is; the test will fail on diff and the
		// caller sees the unparseable output.
		return []byte(s)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte(s)
	}
	return append(out, '\n')
}

// TestOSCALGolden_All exercises every fixture against its golden
// file. UPDATE_GOLDEN=1 rewrites; otherwise diff-fail.
func TestOSCALGolden_All(t *testing.T) {
	update := os.Getenv("UPDATE_GOLDEN") == "1"
	for _, fx := range goldenFixtures {
		t.Run(fx.name, func(t *testing.T) {
			b, err := ExportOSCAL(fx.envelope)
			if err != nil {
				t.Fatalf("ExportOSCAL: %v", err)
			}
			actual := normalizeOSCAL(b)

			path := filepath.Join("testdata", "oscal_golden_"+fx.name+".json")
			if update {
				if err := os.WriteFile(path, actual, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				t.Logf("wrote %s (%d bytes)", path, len(actual))
				return
			}
			expected, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v (run with UPDATE_GOLDEN=1 to create it)", path, err)
			}
			if !bytes.Equal(actual, expected) {
				t.Fatalf("OSCAL golden diff for %s:\n--- expected (%s) ---\n%s\n--- actual ---\n%s\n--- end ---\n(rerun with UPDATE_GOLDEN=1 if the change is intentional)",
					fx.name, path, string(expected), string(actual))
			}
		})
	}
}

// TestOSCALGolden_StructuralPaths is the defense-in-depth
// complement to the byte-diff golden-file approach. Even if the
// goldens drift in lockstep with the code (e.g., contributor
// regenerates without thinking), these assertions catch the high-
// traffic load-bearing paths.
func TestOSCALGolden_StructuralPaths(t *testing.T) {
	b, err := ExportOSCAL(goldenFixtures[0].envelope)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse OSCAL: %v", err)
	}
	body, ok := doc["assessment-results"].(map[string]any)
	if !ok {
		t.Fatal("missing assessment-results envelope")
	}
	for _, key := range []string{"uuid", "metadata", "import-ap", "results"} {
		if _, ok := body[key]; !ok {
			t.Errorf("assessment-results missing %q", key)
		}
	}
	results, _ := body["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	result := results[0].(map[string]any)
	for _, key := range []string{"uuid", "title", "description", "start", "end",
		"reviewed-controls", "findings", "observations"} {
		if _, ok := result[key]; !ok {
			t.Errorf("result missing %q", key)
		}
	}
	findings, _ := result["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	finding := findings[0].(map[string]any)
	target, _ := finding["target"].(map[string]any)
	status, _ := target["status"].(map[string]any)
	state, _ := status["state"].(string)
	if state != "satisfied" {
		t.Errorf("committed envelope: state should be 'satisfied'; got %q", state)
	}
}

// TestOSCALGolden_RegenerateRoundTrip locks AC-04: rewriting
// goldens then re-running without UPDATE_GOLDEN produces zero
// diffs. Verifies the normalize-write-read pipeline doesn't
// introduce a transient mismatch.
func TestOSCALGolden_RegenerateRoundTrip(t *testing.T) {
	// Use a temp testdata path so we don't clobber the committed
	// goldens during a normal go test run.
	tmp := t.TempDir()
	for _, fx := range goldenFixtures {
		b, err := ExportOSCAL(fx.envelope)
		if err != nil {
			t.Fatal(err)
		}
		actual := normalizeOSCAL(b)
		path := filepath.Join(tmp, "oscal_golden_"+fx.name+".json")
		if err := os.WriteFile(path, actual, 0o644); err != nil {
			t.Fatal(err)
		}

		// Regenerate output and compare to the just-written file.
		b2, err := ExportOSCAL(fx.envelope)
		if err != nil {
			t.Fatal(err)
		}
		actual2 := normalizeOSCAL(b2)
		expected, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual2, expected) {
			t.Errorf("round-trip mismatch for %s — normalize is non-idempotent", fx.name)
		}
	}
}
