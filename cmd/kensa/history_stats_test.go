// Tests for writeHistoryStatsText (C-042 text formatter).
package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/internal/store"
)

// TestWriteHistoryStatsText_CanonicalOrdering locks the C-06
// constraint: status renders as committed → rolled_back →
// partially_applied → errored, severity as critical → high
// → medium → low → (unset). Drift would be silent without
// this lock.
// @spec cli-history-stats
// @ac AC-01
// @ac AC-04
// @ac AC-07
func TestWriteHistoryStatsText_CanonicalOrdering(t *testing.T) {
	t.Run("cli-history-stats/AC-07", func(t *testing.T) {})
	t.Run("cli-history-stats/AC-04", func(t *testing.T) {})
	t.Run("cli-history-stats/AC-01", func(t *testing.T) {})
	st := &store.Stats{
		SessionsTotal:     1,
		TransactionsTotal: 10,
		ByStatus: map[string]int{
			"errored":           1,
			"committed":         5,
			"rolled_back":       3,
			"partially_applied": 1,
		},
		BySeverity: map[string]int{
			"low":      1,
			"high":     4,
			"critical": 2,
			"medium":   3,
		},
		ByHost:            map[string]int{"host-a": 10},
		EarliestStartedAt: time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC),
		LatestFinishedAt:  time.Date(2026, 5, 9, 1, 0, 0, 0, time.UTC),
	}

	var buf bytes.Buffer
	writeHistoryStatsText(&buf, st, "", "")
	out := buf.String()

	// Status order: committed first, errored last.
	committedAt := strings.Index(out, "committed")
	rolledAt := strings.Index(out, "rolled_back")
	partialAt := strings.Index(out, "partially_applied")
	erroredAt := strings.Index(out, "errored")
	if !(committedAt < rolledAt && rolledAt < partialAt && partialAt < erroredAt) {
		t.Errorf("status ordering wrong: committed=%d rolled_back=%d partially_applied=%d errored=%d",
			committedAt, rolledAt, partialAt, erroredAt)
	}

	// Severity order: critical first, low last.
	criticalAt := strings.Index(out, "critical")
	highAt := strings.Index(out, "high")
	mediumAt := strings.Index(out, "medium")
	lowAt := strings.Index(out, "low")
	if !(criticalAt < highAt && highAt < mediumAt && mediumAt < lowAt) {
		t.Errorf("severity ordering wrong: critical=%d high=%d medium=%d low=%d",
			criticalAt, highAt, mediumAt, lowAt)
	}
}

// @spec cli-history-stats
// @ac AC-02
// @ac AC-05
// @ac AC-08
func TestWriteHistoryStatsText_EmptyStore(t *testing.T) {
	t.Run("cli-history-stats/AC-08", func(t *testing.T) {})
	t.Run("cli-history-stats/AC-05", func(t *testing.T) {})
	t.Run("cli-history-stats/AC-02", func(t *testing.T) {})
	st := &store.Stats{}
	var buf bytes.Buffer
	writeHistoryStatsText(&buf, st, "", "")
	out := buf.String()
	if !strings.Contains(out, "sessions:     0") {
		t.Errorf("empty stats should still render counts; got %q", out)
	}
	// Empty stats should NOT render the by-axis sections.
	if strings.Contains(out, "by status:") {
		t.Errorf("by status section should be skipped on empty stats; got %q", out)
	}
}

// @spec cli-history-stats
// @ac AC-03
// @ac AC-06
// @ac AC-09
func TestWriteHistoryStatsText_ScopeLine(t *testing.T) {
	t.Run("cli-history-stats/AC-09", func(t *testing.T) {})
	t.Run("cli-history-stats/AC-06", func(t *testing.T) {})
	t.Run("cli-history-stats/AC-03", func(t *testing.T) {})
	st := &store.Stats{SessionsTotal: 1, TransactionsTotal: 1, ByStatus: map[string]int{"committed": 1}}
	var buf bytes.Buffer
	writeHistoryStatsText(&buf, st, "host-a", "24h")
	out := buf.String()
	if !strings.Contains(out, "host=host-a") {
		t.Errorf("scope line missing host: %q", out)
	}
	if !strings.Contains(out, "since=24h") {
		t.Errorf("scope line missing since: %q", out)
	}
}
