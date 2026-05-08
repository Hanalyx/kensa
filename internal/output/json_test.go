package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
)

func TestJSONScanWriter(t *testing.T) {
	result := &api.ScanResult{
		HostID: "host-1",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
		},
	}
	var buf bytes.Buffer
	if err := (jsonScanWriter{}).WriteScanResult(&buf, "host-1", nil, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	// Indented JSON: must contain "  " after a newline (two-space indent).
	if !strings.Contains(buf.String(), "\n  ") {
		t.Errorf("expected indented JSON output; got:\n%s", buf.String())
	}
	// Round-trip: must decode to a structurally valid JSON value.
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got["HostID"] != "host-1" {
		t.Errorf("HostID = %v, want host-1", got["HostID"])
	}
}

func TestJSONLScanWriter(t *testing.T) {
	rules := []*api.Rule{{ID: "rule-a"}, {ID: "rule-b"}, {ID: "rule-c"}}
	result := &api.ScanResult{
		HostID: "host-1",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
			{Status: api.StatusRolledBack, Steps: []api.StepResult{{Detail: "did not match"}}},
			{Status: api.StatusErrored, Error: errors.New("ssh closed")},
		},
	}
	var buf bytes.Buffer
	if err := (jsonlScanWriter{}).WriteScanResult(&buf, "host-1", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	// Compact NDJSON: must end with exactly one newline and contain no
	// internal newlines before that.
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("JSONL must end with newline; got %q", out)
	}
	body := strings.TrimSuffix(out, "\n")
	if strings.Contains(body, "\n") {
		t.Errorf("JSONL body must be a single line; got:\n%s", body)
	}
	// Decode and check the wire shape.
	var line scanLine
	if err := json.Unmarshal([]byte(body), &line); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if line.HostID != "host-1" {
		t.Errorf("HostID = %q, want host-1", line.HostID)
	}
	if line.Passed != 1 || line.Failed != 1 || line.Errors != 1 {
		t.Errorf("counts: passed=%d failed=%d errors=%d, want 1/1/1", line.Passed, line.Failed, line.Errors)
	}
	if len(line.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(line.Rules))
	}
	if line.Rules[0].RuleID != "rule-a" || line.Rules[0].Status != "pass" {
		t.Errorf("rule[0] = %+v, want {rule-a pass}", line.Rules[0])
	}
	if line.Rules[2].RuleID != "rule-c" || line.Rules[2].Status != "error" {
		t.Errorf("rule[2] = %+v, want {rule-c error}", line.Rules[2])
	}
	if line.Rules[2].Detail != "ssh closed" {
		t.Errorf("rule[2].Detail = %q, want %q", line.Rules[2].Detail, "ssh closed")
	}
}

func TestJSONLScanWriter_RuleIDFromStep(t *testing.T) {
	// When result.Transactions has more entries than rules, RuleID is "".
	rules := []*api.Rule{{ID: "rule-a"}}
	result := &api.ScanResult{
		HostID: "host-1",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
			{Status: api.StatusCommitted}, // no rule at index 1
		},
	}
	var buf bytes.Buffer
	if err := (jsonlScanWriter{}).WriteScanResult(&buf, "host-1", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	var line scanLine
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if line.Rules[0].RuleID != "rule-a" {
		t.Errorf("rule[0].RuleID = %q, want rule-a", line.Rules[0].RuleID)
	}
	if line.Rules[1].RuleID != "" {
		t.Errorf("rule[1].RuleID = %q, want empty (no rule at index)", line.Rules[1].RuleID)
	}
}

func TestJSONRemediationWriter(t *testing.T) {
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
		},
	}
	var buf bytes.Buffer
	if err := (jsonRemediationWriter{}).WriteRemediationResult(&buf, "host-1", nil, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	if !strings.Contains(buf.String(), "\n  ") {
		t.Errorf("expected indented JSON; got:\n%s", buf.String())
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestJSONCapsWriter(t *testing.T) {
	caps := api.CapabilitySet{"a": true, "b": false}
	var buf bytes.Buffer
	if err := (jsonCapsWriter{}).WriteCaps(&buf, "h", caps); err != nil {
		t.Fatalf("WriteCaps: %v", err)
	}
	var got api.CapabilitySet
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !got["a"] || got["b"] {
		t.Errorf("round-trip lost values: %+v", got)
	}
}

func TestJSONValueWriter(t *testing.T) {
	val := struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}{"test", 42}
	var buf bytes.Buffer
	if err := (jsonValueWriter{}).WriteJSONValue(&buf, val); err != nil {
		t.Fatalf("WriteJSONValue: %v", err)
	}
	if !strings.Contains(buf.String(), "\n  ") {
		t.Errorf("expected indented JSON; got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `"name": "test"`) || !strings.Contains(buf.String(), `"count": 42`) {
		t.Errorf("unexpected encoding:\n%s", buf.String())
	}
}

func TestJSONWriters_FormatIdentity(t *testing.T) {
	tests := []struct {
		name string
		w    Writer
		want string
	}{
		{"scan", jsonScanWriter{}, "json"},
		{"jsonl scan", jsonlScanWriter{}, "jsonl"},
		{"remediation", jsonRemediationWriter{}, "json"},
		{"caps", jsonCapsWriter{}, "json"},
		{"value", jsonValueWriter{}, "json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.w.Format(); got != tc.want {
				t.Errorf("Format() = %q, want %q", got, tc.want)
			}
		})
	}
}
