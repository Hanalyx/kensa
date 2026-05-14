//go:build ignore
// +build ignore

// bench_aggregate.go — Synthetic benchmark for LogQuery.Aggregate.
//
// Builds a synthetic corpus of 500K transactions across 1000 hosts and
// benchmarks the AggregateByHost and AggregateByRule query paths.
//
// The benchmark verifies the <500ms p95 commitment to OpenWatch that
// was described in docs/KENSA_OPENWATCH_PROGRESS_2026-04-15.md.
//
// Usage:
//
//	go run scripts/bench_aggregate.go [--rows N] [--hosts N] [--runs N]
//
// Defaults:
//
//	--rows  500000   number of synthetic transactions to insert
//	--hosts 1000     number of distinct host IDs
//	--runs  10       number of Aggregate calls per query path for p95
//
// Output: printed to stdout as a JSON summary.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/store"
)

// rules is a small static list used to vary rule_id across the corpus.
var rules = []string{
	"cis_rhel9_1_1_1", "cis_rhel9_1_1_2", "cis_rhel9_2_2_1",
	"cis_rhel9_4_1_1", "cis_rhel9_5_2_1", "cis_rhel9_5_2_2",
	"stig_v257947", "stig_v257948", "stig_v257949",
	"pci_dss_2_2_1", "pci_dss_6_3_3",
}

var statuses = []api.TransactionStatus{
	api.StatusCommitted, api.StatusRolledBack, api.StatusErrored,
}

func main() {
	rows := flag.Int("rows", 500_000, "number of synthetic transactions to insert")
	hosts := flag.Int("hosts", 1000, "number of distinct host IDs")
	runs := flag.Int("runs", 10, "number of Aggregate calls per query path for p95")
	flag.Parse()

	dbPath, err := os.CreateTemp("", "kensa-bench-*.db")
	if err != nil {
		log.Fatalf("tempfile: %v", err)
	}
	dbPath.Close()
	defer os.Remove(dbPath.Name())

	ctx := context.Background()
	s, err := store.OpenSQLite(ctx, dbPath.Name())
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer s.Close()

	// ─── Phase 1: Insert synthetic corpus ────────────────────────────────
	fmt.Fprintf(os.Stderr, "Inserting %d transactions across %d hosts... ", *rows, *hosts)
	start := time.Now()

	hostIDs := make([]string, *hosts)
	for i := range hostIDs {
		hostIDs[i] = fmt.Sprintf("host-%04d.example.com", i)
	}

	rng := rand.New(rand.NewSource(42))
	for i := 0; i < *rows; i++ {
		txnID := uuid.New()
		hostID := hostIDs[rng.Intn(len(hostIDs))]
		ruleID := rules[rng.Intn(len(rules))]
		status := statuses[rng.Intn(len(statuses))]
		now := time.Now().UTC()

		result := &api.TransactionResult{
			TransactionID: txnID,
			Status:        status,
			StartedAt:     now,
			FinishedAt:    now,
			Envelope: &api.EvidenceEnvelope{
				SchemaVersion: "v1",
				TransactionID: txnID,
				RuleID:        ruleID,
				HostID:        hostID,
				StartedAt:     now,
				FinishedAt:    now,
				Decision:      status,
				SigningKeyID:  "noop",
			},
		}
		// We use PersistResult directly to bypass the engine's host-lock
		// overhead and populate the corpus as fast as possible.
		if err := s.PersistResult(ctx, result); err != nil {
			log.Fatalf("insert row %d: %v", i, err)
		}
		if i > 0 && i%50_000 == 0 {
			fmt.Fprintf(os.Stderr, "%dk ", i/1000)
		}
	}
	insertDur := time.Since(start)
	fmt.Fprintf(os.Stderr, "\nInserted %d rows in %s (%.0f rows/s)\n",
		*rows, insertDur.Round(time.Millisecond), float64(*rows)/insertDur.Seconds())

	// ─── Phase 2: Benchmark AggregateByHost ──────────────────────────────
	byHostLatencies := bench(ctx, s, api.AggregateByHost, *runs)
	fmt.Fprintf(os.Stderr, "AggregateByHost: %d runs\n", *runs)

	// ─── Phase 3: Benchmark AggregateByRule ──────────────────────────────
	byRuleLatencies := bench(ctx, s, api.AggregateByRule, *runs)
	fmt.Fprintf(os.Stderr, "AggregateByRule: %d runs\n", *runs)

	// ─── Phase 4: Report ─────────────────────────────────────────────────
	report := map[string]interface{}{
		"rows":         *rows,
		"hosts":        *hosts,
		"runs_per_key": *runs,
		"insert_ms":    insertDur.Milliseconds(),
		"by_host":      latencyReport(byHostLatencies),
		"by_rule":      latencyReport(byRuleLatencies),
		"p95_committed": byHostLatencies[int(float64(len(byHostLatencies))*0.95)] < 500*time.Millisecond &&
			byRuleLatencies[int(float64(len(byRuleLatencies))*0.95)] < 500*time.Millisecond,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		log.Fatalf("encode report: %v", err)
	}

	// Non-zero exit if p95 commitment is violated.
	byHostP95 := p95(byHostLatencies)
	byRuleP95 := p95(byRuleLatencies)
	if byHostP95 >= 500*time.Millisecond || byRuleP95 >= 500*time.Millisecond {
		fmt.Fprintf(os.Stderr, "\nFAIL: p95 commitment violated (by_host=%s by_rule=%s; limit=500ms)\n",
			byHostP95.Round(time.Millisecond), byRuleP95.Round(time.Millisecond))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\nPASS: p95 by_host=%s by_rule=%s (< 500ms)\n",
		byHostP95.Round(time.Millisecond), byRuleP95.Round(time.Millisecond))
}

// bench runs Aggregate n times with an empty filter and returns sorted latencies.
func bench(ctx context.Context, s *store.SQLite, key api.AggregateKey, n int) []time.Duration {
	latencies := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		_, err := s.Aggregate(ctx, api.LogFilter{}, key)
		d := time.Since(start)
		if err != nil {
			log.Fatalf("Aggregate(%s) run %d: %v", key, i, err)
		}
		latencies = append(latencies, d)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return latencies
}

// p95 returns the 95th percentile of a sorted slice.
func p95(sorted []time.Duration) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)) * 0.95)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// latencyReport builds a map of p50/p95/p99/max latencies in milliseconds.
func latencyReport(sorted []time.Duration) map[string]float64 {
	if len(sorted) == 0 {
		return nil
	}
	pct := func(p float64) float64 {
		idx := int(float64(len(sorted)) * p)
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return float64(sorted[idx].Microseconds()) / 1000.0
	}
	return map[string]float64{
		"p50_ms": pct(0.50),
		"p95_ms": pct(0.95),
		"p99_ms": pct(0.99),
		"max_ms": float64(sorted[len(sorted)-1].Microseconds()) / 1000.0,
		"min_ms": float64(sorted[0].Microseconds()) / 1000.0,
	}
}
