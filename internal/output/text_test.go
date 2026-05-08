package output

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/google/uuid"
)

func TestTextCapsWriter(t *testing.T) {
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

func TestTextScanWriter(t *testing.T) {
	rules := []*api.Rule{
		{ID: "rule-pass"},
		{ID: "rule-fail"},
		{ID: "rule-error"},
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
	if !strings.Contains(out, "Check results for test-host:") {
		t.Errorf("missing host header:\n%s", out)
	}
	if !strings.Contains(out, "1 passed, 1 failed, 1 errors") {
		t.Errorf("expected 1/1/1 tally:\n%s", out)
	}
	if !strings.Contains(out, "rule-pass") || !strings.Contains(out, "rule-fail") || !strings.Contains(out, "rule-error") {
		t.Errorf("missing one or more rule IDs:\n%s", out)
	}
	if !strings.Contains(out, "ssh timeout") {
		t.Errorf("error detail not surfaced:\n%s", out)
	}
}

func TestTextScanWriter_TruncatesLongDetail(t *testing.T) {
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

func TestTextRemediationWriter(t *testing.T) {
	rules := []*api.Rule{
		{ID: "rule-committed"},
		{ID: "rule-rolledback"},
		{ID: "rule-errored"},
		{ID: "rule-partial"},
	}
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
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
	if !strings.Contains(out, "1 committed, 1 rolled_back, 1 errors, 1 skipped") {
		t.Errorf("expected 1/1/1/1 tally:\n%s", out)
	}
	if !strings.Contains(out, "errored: boom") {
		t.Errorf("expected errored prefix in status:\n%s", out)
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
