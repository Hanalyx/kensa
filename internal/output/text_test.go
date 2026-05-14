package output

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// @spec output-text-scan
// @ac AC-01
func TestTextCapsWriter(t *testing.T) {
	t.Run("output-text-scan/AC-01", func(t *testing.T) {})
	caps := api.CapabilitySet{
		"selinux":   true,
		"firewalld": true,
		"apparmor":  false,
	}
	var buf bytes.Buffer
	if err := (textCapsWriter{}).WriteCaps(&buf, "test-host", caps); err != nil {
		t.Fatalf("WriteCaps: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Capabilities for test-host:") {
		t.Errorf("missing host header in output:\n%s", out)
	}
	if !strings.Contains(out, "✓  firewalld") {
		t.Errorf("missing capability check mark for firewalld:\n%s", out)
	}
	if !strings.Contains(out, "✗  apparmor") {
		t.Errorf("missing capability cross mark for apparmor:\n%s", out)
	}
	posApparmor := strings.Index(out, "apparmor")
	posFirewalld := strings.Index(out, "firewalld")
	posSelinux := strings.Index(out, "selinux")
	if !(posApparmor < posFirewalld && posFirewalld < posSelinux) {
		t.Errorf("capabilities not sorted alphabetically:\n%s", out)
	}
}

// @spec output-text-scan
// @ac AC-02
func TestTextScanWriter(t *testing.T) {
	t.Run("output-text-scan/AC-02", func(t *testing.T) {})
	// C-022 layout: FAILED/WARN/PASSED grouped, host banner first,
	// summary line at the bottom.
	rules := []*api.Rule{
		{ID: "rule-pass", Severity: "high"},
		{ID: "rule-fail", Severity: "medium"},
		{ID: "rule-error", Severity: "low"},
	}
	result := &api.ScanResult{
		HostID: "test-host",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted, Steps: []api.StepResult{{Detail: "ok"}}},
			{Status: api.StatusRolledBack, Steps: []api.StepResult{{Detail: "did not match"}}},
			{Status: api.StatusErrored, Error: errors.New("ssh timeout")},
		},
	}
	var buf bytes.Buffer
	if err := (textScanWriter{}).WriteScanResult(&buf, "test-host", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "test-host") {
		t.Errorf("missing host banner with hostID:\n%s", out)
	}
	if !strings.Contains(out, "FAILED   (  1)") {
		t.Errorf("missing FAILED group header:\n%s", out)
	}
	if !strings.Contains(out, "WARN     (  1)") {
		t.Errorf("missing WARN group header:\n%s", out)
	}
	if !strings.Contains(out, "PASSED   (  1)") {
		t.Errorf("missing PASSED group header:\n%s", out)
	}
	if !strings.Contains(out, "1 passed  ·  1 failed  ·  1 warnings") {
		t.Errorf("missing summary line:\n%s", out)
	}
	if !strings.Contains(out, "rule-pass") || !strings.Contains(out, "rule-fail") || !strings.Contains(out, "rule-error") {
		t.Errorf("missing one or more rule IDs:\n%s", out)
	}
	if !strings.Contains(out, "ssh timeout") {
		t.Errorf("warn detail (errored) should still be surfaced:\n%s", out)
	}
	// Severity badge for the FAIL row.
	if !strings.Contains(out, "MED") {
		t.Errorf("missing MED severity badge for rule-fail:\n%s", out)
	}
}

// @spec output-text-scan
// @ac AC-03
func TestTextScanWriter_TruncatesLongDetail(t *testing.T) {
	t.Run("output-text-scan/AC-03", func(t *testing.T) {})
	long := strings.Repeat("a", 200)
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusRolledBack, Steps: []api.StepResult{{Detail: long}}},
		},
	}
	rules := []*api.Rule{{ID: "long-detail"}}
	var buf bytes.Buffer
	if err := (textScanWriter{}).WriteScanResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	if !strings.Contains(buf.String(), "…") {
		t.Errorf("expected ellipsis from truncation; got:\n%s", buf.String())
	}
}

// @spec output-text-scan
// @ac AC-04
func TestTextScanWriter_AllPassedNoFailedSection(t *testing.T) {
	t.Run("output-text-scan/AC-04", func(t *testing.T) {})
	// When everything passes, the FAILED and WARN sections are
	// elided. The PASSED section + summary still emit.
	rules := []*api.Rule{
		{ID: "rule-a"}, {ID: "rule-b"}, {ID: "rule-c"},
	}
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted}, {Status: api.StatusCommitted}, {Status: api.StatusCommitted},
		},
	}
	var buf bytes.Buffer
	if err := (textScanWriter{}).WriteScanResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "FAILED") || strings.Contains(out, "WARN") {
		t.Errorf("FAILED/WARN should not appear when all pass:\n%s", out)
	}
	if !strings.Contains(out, "PASSED   (  3)") {
		t.Errorf("missing PASSED group with count 3:\n%s", out)
	}
	if !strings.Contains(out, "3 passed  ·  0 failed  ·  0 warnings") {
		t.Errorf("missing 3/0/0 summary:\n%s", out)
	}
}

// @spec output-text-scan
// @ac AC-05
func TestTextScanWriter_StripsMechanismPrefix(t *testing.T) {
	t.Run("output-text-scan/AC-05", func(t *testing.T) {})
	// detail like "command: \"awk -F: '($2 == ...)'\"" should
	// surface as "\"awk -F: '($2 == ...)\"" without the
	// "command:" prefix.
	rules := []*api.Rule{{ID: "r"}}
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusRolledBack, Steps: []api.StepResult{{Detail: "config_value: key \"foo\" not found"}}},
		},
	}
	var buf bytes.Buffer
	if err := (textScanWriter{}).WriteScanResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "config_value:") {
		t.Errorf("mechanism prefix should be stripped:\n%s", out)
	}
	if !strings.Contains(out, "key") {
		t.Errorf("the detail body should still appear:\n%s", out)
	}
}

// @spec output-text-scan
// @ac AC-06
func TestTextScanWriter_PassedCompactionAboveThreshold(t *testing.T) {
	t.Run("output-text-scan/AC-06", func(t *testing.T) {})
	// 9+ passed rules → compacted via glob patterns.
	rules := []*api.Rule{
		{ID: "accounts-a"}, {ID: "accounts-b"}, {ID: "accounts-c"},
		{ID: "audit-a"}, {ID: "audit-b"}, {ID: "audit-c"},
		{ID: "lone-rule"},
		{ID: "service-a"}, {ID: "service-b"},
	}
	txns := make([]api.TransactionResult, len(rules))
	for i := range txns {
		txns[i].Status = api.StatusCommitted
	}
	result := &api.ScanResult{HostID: "h", Transactions: txns}
	var buf bytes.Buffer
	if err := (textScanWriter{}).WriteScanResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "accounts-*") {
		t.Errorf("expected accounts-* glob compaction:\n%s", out)
	}
	if !strings.Contains(out, "audit-*") {
		t.Errorf("expected audit-* glob compaction:\n%s", out)
	}
	if !strings.Contains(out, "service-*") {
		t.Errorf("expected service-* glob compaction:\n%s", out)
	}
	// The "-v to expand" hint shows when compaction is in effect.
	if !strings.Contains(out, "run with -v to expand") {
		t.Errorf("missing -v hint:\n%s", out)
	}
}

// @spec output-text-scan
// @ac AC-07
func TestTextScanWriter_PassedInlineBelowThreshold(t *testing.T) {
	t.Run("output-text-scan/AC-07", func(t *testing.T) {})
	// ≤8 passed rules → listed inline (no glob compaction).
	rules := []*api.Rule{{ID: "rule-a"}, {ID: "rule-b"}}
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted}, {Status: api.StatusCommitted},
		},
	}
	var buf bytes.Buffer
	if err := (textScanWriter{}).WriteScanResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "rule-a") || !strings.Contains(out, "rule-b") {
		t.Errorf("expected inline rule IDs:\n%s", out)
	}
	if strings.Contains(out, "run with -v to expand") {
		t.Errorf("-v hint should not appear for small sets:\n%s", out)
	}
}

// @spec output-text-scan
// @ac AC-08
func TestTextScanWriter_FixLineSynthesis(t *testing.T) {
	t.Run("output-text-scan/AC-08", func(t *testing.T) {})
	// A failing rule with file_permissions remediation should
	// surface a "└ fix: chmod ... && chown ..." line.
	rules := []*api.Rule{
		{
			ID:       "fp-rule",
			Severity: "high",
			Implementations: []api.Implementation{
				{
					Remediation: api.Remediation{
						Mechanism: "file_permissions",
						Params: api.Params{
							"path":  "/etc/at.allow",
							"mode":  "0600",
							"owner": "root",
							"group": "root",
						},
					},
				},
			},
		},
	}
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusRolledBack, Steps: []api.StepResult{{Detail: "/etc/at.allow not found"}}},
		},
	}
	var buf bytes.Buffer
	if err := (textScanWriter{}).WriteScanResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "└ fix:") {
		t.Errorf("expected fix line for failing rule:\n%s", out)
	}
	if !strings.Contains(out, "chmod 0600") || !strings.Contains(out, "/etc/at.allow") {
		t.Errorf("fix line should describe chmod + path:\n%s", out)
	}
	if !strings.Contains(out, "chown root:root") {
		t.Errorf("fix line should include chown when owner+group set:\n%s", out)
	}
}

// @spec output-text-scan
// @ac AC-09
func TestSeverityBadge(t *testing.T) {
	t.Run("output-text-scan/AC-09", func(t *testing.T) {})
	tests := []struct {
		in, want string
	}{
		{"critical", "CRIT"},
		{"high", "HIGH"},
		{"HIGH", "HIGH"}, // case-insensitive
		{"medium", "MED "},
		{"low", "LOW "},
		{"", "    "},
		{"unknown", "    "},
	}
	for _, tc := range tests {
		if got := severityBadge(tc.in); got != tc.want {
			t.Errorf("severityBadge(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// @spec output-text-scan
// @ac AC-10
func TestCompactPasses(t *testing.T) {
	t.Run("output-text-scan/AC-10", func(t *testing.T) {})
	tests := []struct {
		name string
		in   []string
		want string // substring expectation
	}{
		{"empty", nil, ""},
		{"single", []string{"rule-a"}, "rule-a"},
		{"two-same-prefix", []string{"accounts-a", "accounts-b"}, "accounts-*"},
		{"mixed", []string{"accounts-a", "accounts-b", "lone"}, "accounts-* lone"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := compactPasses(tc.in)
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("compactPasses(%v) = %q, want substring %q", tc.in, got, tc.want)
			}
			if tc.want == "" && got != "" {
				t.Errorf("compactPasses(empty) = %q, want empty", got)
			}
		})
	}
}

// @spec output-text-scan
// @ac AC-11
func TestProgressBar(t *testing.T) {
	t.Run("output-text-scan/AC-11", func(t *testing.T) {})
	// All passed: bar is all '#'.
	if got := progressBar(10, 0, 0, 10); got != "##########" {
		t.Errorf("all-pass progressBar = %q, want ##########", got)
	}
	// All failed: bar is all 'x'.
	if got := progressBar(0, 0, 10, 10); got != "xxxxxxxxxx" {
		t.Errorf("all-fail progressBar = %q, want xxxxxxxxxx", got)
	}
	// Mixed: counts roughly proportional, total length = width.
	got := progressBar(50, 25, 25, 100)
	if len(got) != 100 {
		t.Errorf("progressBar width = %d, want 100", len(got))
	}
	hashes := strings.Count(got, "#")
	tildes := strings.Count(got, "~")
	xes := strings.Count(got, "x")
	if hashes+tildes+xes != 100 {
		t.Errorf("progressBar cells should sum to width: got %d+%d+%d = %d",
			hashes, tildes, xes, hashes+tildes+xes)
	}
	// Empty: defaults to dots so callers can see the empty state.
	if got := progressBar(0, 0, 0, 5); got != "....." {
		t.Errorf("empty progressBar = %q, want .....", got)
	}
}

// @spec output-text-scan
// @ac AC-12
func TestSynthesizeFix_AllSupportedHandlers(t *testing.T) {
	t.Run("output-text-scan/AC-12", func(t *testing.T) {})
	tests := []struct {
		name      string
		mechanism string
		params    api.Params
		wantSub   string // expected substring in synthesized line
		wantEmpty bool
	}{
		{"file_permissions+owner", "file_permissions",
			api.Params{"path": "/etc/x", "mode": "0600", "owner": "root", "group": "wheel"},
			"chmod 0600 /etc/x && chown root:wheel /etc/x", false},
		{"file_permissions+mode-only", "file_permissions",
			api.Params{"path": "/etc/x", "mode": "0644"},
			"chmod 0644 /etc/x", false},
		{"file_absent", "file_absent",
			api.Params{"path": "/etc/junk"},
			"rm -f /etc/junk", false},
		{"package_present", "package_present",
			api.Params{"name": "auditd"},
			"install package auditd", false},
		{"package_absent", "package_absent",
			api.Params{"name": "telnet"},
			"remove package telnet", false},
		{"service_enabled", "service_enabled",
			api.Params{"unit": "auditd.service"},
			"systemctl enable auditd.service", false},
		{"service_disabled", "service_disabled",
			api.Params{"unit": "telnet.socket"},
			"systemctl disable telnet.socket", false},
		{"service_masked", "service_masked",
			api.Params{"unit": "ctrl-alt-del.target"},
			"systemctl mask ctrl-alt-del.target", false},
		{"config_set", "config_set",
			api.Params{"path": "/etc/login.defs", "key": "PASS_MAX_DAYS", "value": "365"},
			"set PASS_MAX_DAYS = 365 in /etc/login.defs", false},
		{"sysctl_set", "sysctl_set",
			api.Params{"key": "net.ipv4.conf.all.rp_filter", "value": "1"},
			"sysctl -w net.ipv4.conf.all.rp_filter=1", false},
		{"unknown-handler", "some-future-mechanism",
			api.Params{"foo": "bar"},
			"", true},
		{"missing-required-param", "file_permissions",
			api.Params{}, // no path
			"", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &api.Rule{
				Implementations: []api.Implementation{
					{Remediation: api.Remediation{Mechanism: tc.mechanism, Params: tc.params}},
				},
			}
			got := synthesizeFix(r)
			if tc.wantEmpty && got != "" {
				t.Errorf("synthesizeFix(%s) = %q, want empty", tc.mechanism, got)
			}
			if !tc.wantEmpty && !strings.Contains(got, tc.wantSub) {
				t.Errorf("synthesizeFix(%s) = %q, want substring %q", tc.mechanism, got, tc.wantSub)
			}
		})
	}
}

// @spec output-text-scan
// @ac AC-13
func TestSynthesizeFix_NilRule(t *testing.T) {
	t.Run("output-text-scan/AC-13", func(t *testing.T) {})
	if got := synthesizeFix(nil); got != "" {
		t.Errorf("synthesizeFix(nil) = %q, want empty", got)
	}
}

// @spec output-text-scan
// @ac AC-14
func TestSynthesizeFix_NoImplementations(t *testing.T) {
	t.Run("output-text-scan/AC-14", func(t *testing.T) {})
	r := &api.Rule{}
	if got := synthesizeFix(r); got != "" {
		t.Errorf("synthesizeFix(no-impls) = %q, want empty", got)
	}
}

// @spec output-text-scan
// @ac AC-15
func TestSynthesizeFix_MultiStepReturnsEmpty(t *testing.T) {
	t.Run("output-text-scan/AC-15", func(t *testing.T) {})
	// Multi-step remediations emit no fix line: surfacing only
	// step 1 would silently hide steps 2..N from the operator.
	r := &api.Rule{
		Implementations: []api.Implementation{
			{
				Remediation: api.Remediation{
					Steps: []api.RemediationStep{
						{Mechanism: "package_present", Params: api.Params{"name": "auditd"}},
						{Mechanism: "service_enabled", Params: api.Params{"unit": "auditd.service"}},
					},
				},
			},
		},
	}
	if got := synthesizeFix(r); got != "" {
		t.Errorf("multi-step rule should return empty fix line; got %q", got)
	}
}

// @spec output-text-scan
// @ac AC-16
func TestTextScanWriter_PartiallyAppliedRendersAsFail(t *testing.T) {
	t.Run("output-text-scan/AC-16", func(t *testing.T) {})
	// Per spec C-07, StatusPartiallyApplied (which can't actually
	// occur during a scan today, but is defensive) → FAIL bucket.
	// Locks the mapping so a future change can't silently demote
	// it to WARN.
	rules := []*api.Rule{{ID: "rule-partial", Severity: "high"}}
	result := &api.ScanResult{
		HostID: "h",
		Transactions: []api.TransactionResult{
			{Status: api.StatusPartiallyApplied},
		},
	}
	var buf bytes.Buffer
	if err := (textScanWriter{}).WriteScanResult(&buf, "h", rules, result); err != nil {
		t.Fatalf("WriteScanResult: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "FAILED") {
		t.Errorf("partially_applied should render as FAILED; got:\n%s", out)
	}
	if strings.Contains(out, "WARN") {
		t.Errorf("partially_applied should NOT render as WARN; got:\n%s", out)
	}
}

func TestWriteHostBanner_RuneWidth(t *testing.T) {
	// Banner width must be 60 runes regardless of hostID's UTF-8
	// byte count. Catches the byte-vs-rune bug R1 flagged.
	for _, host := range []string{"h", "192.168.1.211", "тест-хост", "测试-host", "fe80::1"} {
		var buf bytes.Buffer
		if err := writeHostBanner(&buf, host, ""); err != nil {
			t.Errorf("writeHostBanner(%q): %v", host, err)
			continue
		}
		line := strings.TrimRight(buf.String(), "\n")
		runeCount := 0
		for range line {
			runeCount++
		}
		if runeCount != 60 {
			t.Errorf("banner for %q = %d runes, want 60", host, runeCount)
		}
	}
}

func TestHumanizeDetail_MultiLineScriptBody(t *testing.T) {
	// Multi-line bash script bodies leaked from rules using
	// `check.method: command` with multi-line `run:` blocks.
	// humanizeDetail replaces them with a pointer to -o json:
	// rather than truncating the script body uselessly.
	cases := []string{
		"command: \"# Find accounts with nologin/false shell\nawk -F: ...\"",
		"# multi-line\nbash\nscript",
	}
	for _, raw := range cases {
		txr := api.TransactionResult{
			Steps: []api.StepResult{{Detail: raw}},
		}
		got := humanizeDetail(txr)
		if !strings.Contains(got, "-o json") && !strings.Contains(got, "unexpected exit") {
			t.Errorf("humanizeDetail should pointer to -o json: for multi-line script; got %q for raw %q", got, raw)
		}
	}
}

func TestHumanizeDetail_ExitCodePattern(t *testing.T) {
	// "exited with code N (expected M)" patterns should extract
	// the actionable signal rather than truncating the script.
	cases := []struct {
		raw  string
		want string
	}{
		{
			"command: \"awk -F: ...\" exited with code 0 (expected 1)",
			"unexpected exit (got 0, want 1)",
		},
		{
			"\"foo\" exited with code 42 (expected 0)",
			"unexpected exit (got 42, want 0)",
		},
	}
	for _, tc := range cases {
		txr := api.TransactionResult{Steps: []api.StepResult{{Detail: tc.raw}}}
		got := humanizeDetail(txr)
		if got != tc.want {
			t.Errorf("humanizeDetail(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestRenderScanResult_VerboseExpandsPassed(t *testing.T) {
	// In verbose mode, the PASSED section emits one rule ID per
	// line with a ✓ marker, NOT the glob-compacted summary.
	rules := []*api.Rule{
		{ID: "accounts-a"}, {ID: "accounts-b"}, {ID: "accounts-c"},
		{ID: "audit-a"}, {ID: "audit-b"}, {ID: "audit-c"},
		{ID: "rule-g"}, {ID: "rule-h"}, {ID: "rule-i"},
	}
	txns := make([]api.TransactionResult, len(rules))
	for i := range txns {
		txns[i].Status = api.StatusCommitted
	}
	result := &api.ScanResult{HostID: "h", Transactions: txns}
	var buf bytes.Buffer
	if err := RenderScanResult(&buf, "h", rules, result, ScanRenderOptions{Verbose: true}); err != nil {
		t.Fatalf("RenderScanResult: %v", err)
	}
	out := buf.String()
	// Each rule appears on its own line with the ✓ marker.
	for _, id := range []string{"accounts-a", "audit-c", "rule-i"} {
		if !strings.Contains(out, "✓ "+id) {
			t.Errorf("verbose mode should expand to ✓ <id> per rule; missing %q:\n%s", id, out)
		}
	}
	// Compaction patterns and -v hint should NOT appear.
	if strings.Contains(out, "accounts-*") || strings.Contains(out, "run with -v to expand") {
		t.Errorf("verbose mode should not show compaction or hint:\n%s", out)
	}
}

func TestRenderScanResult_OSLabelInBanner(t *testing.T) {
	rules := []*api.Rule{{ID: "r"}}
	result := &api.ScanResult{
		HostID:       "h",
		Transactions: []api.TransactionResult{{Status: api.StatusCommitted}},
	}
	var buf bytes.Buffer
	if err := RenderScanResult(&buf, "192.168.1.211", rules, result, ScanRenderOptions{OSLabel: "RHEL 9.6"}); err != nil {
		t.Fatalf("RenderScanResult: %v", err)
	}
	first := strings.SplitN(buf.String(), "\n", 2)[0]
	if !strings.Contains(first, "192.168.1.211") {
		t.Errorf("banner missing hostID: %q", first)
	}
	if !strings.Contains(first, "· RHEL 9.6") {
		t.Errorf("banner missing OS label: %q", first)
	}
	// Banner is still 60 runes total.
	runeCount := 0
	for range first {
		runeCount++
	}
	if runeCount != 60 {
		t.Errorf("banner with OS label = %d runes, want 60", runeCount)
	}
}

func TestRenderScanResult_OSLabelEmpty_NoOSegment(t *testing.T) {
	// Empty OSLabel: banner falls back to host-only (no "·" separator).
	rules := []*api.Rule{{ID: "r"}}
	result := &api.ScanResult{
		HostID:       "h",
		Transactions: []api.TransactionResult{{Status: api.StatusCommitted}},
	}
	var buf bytes.Buffer
	if err := RenderScanResult(&buf, "h", rules, result, ScanRenderOptions{OSLabel: ""}); err != nil {
		t.Fatalf("RenderScanResult: %v", err)
	}
	first := strings.SplitN(buf.String(), "\n", 2)[0]
	if strings.Contains(first, "·") {
		t.Errorf("empty OSLabel should produce no '·' separator: %q", first)
	}
}

func TestCompactPasses_DeepestPrefix(t *testing.T) {
	// pam-faillock-* family should NOT collapse to pam-* alongside
	// pam-pwhistory-*; deepest-common-prefix preserves both.
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{
			"deep-pam-faillock",
			[]string{"pam-faillock-audit", "pam-faillock-deny", "pam-faillock-silent"},
			"pam-faillock-*",
		},
		{
			"deep-audit-cmd",
			[]string{"audit-cmd-chage", "audit-cmd-chcon", "audit-cmd-chsh"},
			"audit-cmd-*",
		},
		{
			"different-deep-prefixes-collapse-to-shallow",
			// pam-faillock-deny, pam-pwhistory-remember share only
			// "pam-".
			[]string{"pam-faillock-deny", "pam-pwhistory-remember"},
			"pam-*",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := compactPasses(tc.in)
			if !strings.Contains(got, tc.want) {
				t.Errorf("compactPasses(%v) = %q, want substring %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestTextRemediationWriter(t *testing.T) {
	rules := []*api.Rule{
		{ID: "rule-applied"},
		{ID: "rule-compliant"},
		{ID: "rule-rolledback"},
		{ID: "rule-errored"},
		{ID: "rule-partial"},
	}
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			// Status=committed, real apply (no skip marker)
			{Status: api.StatusCommitted, Steps: []api.StepResult{
				{Mechanism: "file_permissions", Success: true, Detail: "applied"},
			}},
			// Status=committed, the scanner's already-compliant
			// synthetic record. B6 (2026-05-13) split this out
			// from the "applied" count so operators can tell
			// "kensa did work" from "kensa verified state".
			{Status: api.StatusCommitted, Steps: []api.StepResult{
				{Mechanism: "check", Success: true, Detail: "already in desired state — skipped"},
			}},
			{Status: api.StatusRolledBack},
			{Status: api.StatusErrored, Error: errors.New("boom")},
			{Status: api.StatusPartiallyApplied},
		},
	}
	var buf bytes.Buffer
	if err := (textRemediationWriter{}).WriteRemediationResult(&buf, "test-host", rules, result); err != nil {
		t.Fatalf("WriteRemediationResult: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 applied, 1 already-compliant, 1 rolled_back, 1 errors, 1 skipped") {
		t.Errorf("expected 1/1/1/1/1 tally with split applied/already-compliant:\n%s", out)
	}
	if !strings.Contains(out, "errored: boom") {
		t.Errorf("expected errored prefix in status:\n%s", out)
	}
	if !strings.Contains(out, "rule-compliant") || !strings.Contains(out, "already-compliant") {
		t.Errorf("rule-compliant row should show status=already-compliant:\n%s", out)
	}
	if !strings.Contains(out, "rule-applied") || !strings.Contains(out, "applied") {
		t.Errorf("rule-applied row should show status=applied:\n%s", out)
	}
}

func TestTextHistoryWriter(t *testing.T) {
	finished := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	id1 := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	id2 := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	txns := []api.TransactionRecord{
		{
			ID:         id1,
			Status:     api.StatusCommitted,
			RuleID:     "ssh-disable-root-login",
			HostID:     "host-1",
			FinishedAt: finished,
		},
		{
			ID:         id2,
			Status:     api.StatusRolledBack,
			RuleID:     "filesystem-mount-options",
			HostID:     "host-2",
			FinishedAt: finished,
		},
	}
	var buf bytes.Buffer
	if err := (textHistoryWriter{}).WriteHistory(&buf, txns); err != nil {
		t.Fatalf("WriteHistory: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "TRANSACTION-ID") {
		t.Errorf("missing header row:\n%s", out)
	}
	if !strings.Contains(out, "ssh-disable-root-login") || !strings.Contains(out, "filesystem-mount-options") {
		t.Errorf("missing rule IDs:\n%s", out)
	}
	if !strings.Contains(out, "2026-05-08T12:00:00Z") {
		t.Errorf("missing RFC3339 timestamp:\n%s", out)
	}
}

func TestTextHistoryWriter_EmptyList(t *testing.T) {
	var buf bytes.Buffer
	if err := (textHistoryWriter{}).WriteHistory(&buf, nil); err != nil {
		t.Fatalf("WriteHistory(nil): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "TRANSACTION-ID") {
		t.Errorf("expected header even with no rows:\n%s", out)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 5, "abc"},
		{"abcde", 5, "abcde"},
		{"abcdef", 5, "abcd…"},
		{"hello world", 8, "hello w…"},
		{"x", 1, "x"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q-%d", tc.in, tc.n), func(t *testing.T) {
			if got := truncate(tc.in, tc.n); got != tc.want {
				t.Errorf("truncate(%q, %d) = %q; want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}

func TestTextWriters_FormatIdentity(t *testing.T) {
	tests := []struct {
		name string
		w    Writer
	}{
		{"caps", textCapsWriter{}},
		{"scan", textScanWriter{}},
		{"remediation", textRemediationWriter{}},
		{"history", textHistoryWriter{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.w.Format(); got != "text" {
				t.Errorf("Format() = %q, want \"text\"", got)
			}
		})
	}
}
