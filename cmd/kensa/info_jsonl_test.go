// Tests for the C-052 `kensa info --format jsonl` (QUERY mode)
// flow — including the document-mode rejection.
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRunInfo_QueryJSONLFormat locks AC-02: --format jsonl on
// QUERY mode emits one SearchHit per line.
func TestRunInfo_QueryJSONLFormat(t *testing.T) {
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "test", "--rules-dir", dir, "--format", "jsonl"}, t,
	)
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	// makeCoverageCorpus has 3 rules whose title contains "Test".
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (one per hit); got %d:\n%s", len(lines), stdout)
	}
	for i, line := range lines {
		if line == "" {
			continue
		}
		if line[0] != '{' {
			t.Errorf("line %d should start with '{'; got %q", i, line)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d not parseable: %v\nline: %q", i, err, line)
		}
		if _, ok := got["id"]; !ok {
			t.Errorf("line %d missing 'id' field; line: %q", i, line)
		}
	}
}

// TestRunInfo_DocumentModesRejectJSONL locks AC-03: jsonl on the
// three single-document modes is rejected with usage error.
func TestRunInfo_DocumentModesRejectJSONL(t *testing.T) {
	dir := makeCoverageCorpus(t)
	cases := [][]string{
		{"info", "--rule", "rule-a", "--rules-dir", dir, "--format", "jsonl"},
		{"info", "--control", "cis_rhel9:5.1.12", "--rules-dir", dir, "--format", "jsonl"},
		{"info", "--list-controls", "nist_800_53", "--rules-dir", dir, "--format", "jsonl"},
	}
	for _, args := range cases {
		exit := runCLI(args)
		if exit != 2 {
			t.Errorf("runCLI(%v) = %d, want 2", args, exit)
		}
	}
	// Error message must redirect to --format json.
	_, stderr := captureRunCLI(
		[]string{"info", "--rule", "rule-a", "--rules-dir", dir, "--format", "jsonl"}, t,
	)
	if !strings.Contains(stderr, "--format json") {
		t.Errorf("error should redirect at --format json; got:\n%s", stderr)
	}
}

// TestRunInfo_QueryJSONLShapeMatchesJSON locks AC-04: per-line
// jsonl shape matches per-element JSON envelope `hits[]` shape.
func TestRunInfo_QueryJSONLShapeMatchesJSON(t *testing.T) {
	dir := makeCoverageCorpus(t)

	stdoutJSON, _ := captureRunCLI(
		[]string{"info", "test", "--rules-dir", dir, "--format", "json"}, t,
	)
	var env struct {
		Query string            `json:"query"`
		Hits  []json.RawMessage `json:"hits"`
	}
	if err := json.Unmarshal([]byte(stdoutJSON), &env); err != nil {
		t.Fatalf("unmarshal --format json: %v\n%s", err, stdoutJSON)
	}

	stdoutJSONL, _ := captureRunCLI(
		[]string{"info", "test", "--rules-dir", dir, "--format", "jsonl"}, t,
	)
	jsonlLines := strings.Split(strings.TrimRight(stdoutJSONL, "\n"), "\n")

	if len(env.Hits) != len(jsonlLines) {
		t.Fatalf("count mismatch: json=%d jsonl=%d", len(env.Hits), len(jsonlLines))
	}
	for i := range env.Hits {
		var fromArray, fromLine map[string]any
		if err := json.Unmarshal(env.Hits[i], &fromArray); err != nil {
			t.Fatalf("array element %d: %v", i, err)
		}
		if err := json.Unmarshal([]byte(jsonlLines[i]), &fromLine); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if fromArray["id"] != fromLine["id"] {
			t.Errorf("element %d id mismatch: array=%v jsonl=%v",
				i, fromArray["id"], fromLine["id"])
		}
	}
}

// TestRunInfo_QueryJSONLEmptyHits locks the zero-results path:
// when QUERY matches nothing under jsonl, output is empty (no
// envelope, no banner — that's text-mode behavior).
func TestRunInfo_QueryJSONLEmptyHits(t *testing.T) {
	dir := makeCoverageCorpus(t)
	stdout, _ := captureRunCLI(
		[]string{"info", "no-such-rule-substring", "--rules-dir", dir, "--format", "jsonl"}, t,
	)
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("empty hits under jsonl should produce zero output; got:\n%s", stdout)
	}
}
