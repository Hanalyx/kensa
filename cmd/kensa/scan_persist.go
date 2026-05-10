package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/mappings"
	"github.com/Hanalyx/kensa-go/internal/store"
)

// summarizeCheckArgs builds a short operator-readable summary
// of the filter inputs that selected the rule set. Stored on
// the session so `kensa history` and `kensa diff` can show
// the operator what filters were in effect for a past run.
// Empty values omitted.
//
// Output mirrors the CLI form an operator would actually type:
// `-s critical -s high -t pci -f cis_rhel9` rather than
// debug-formatted Go slice strings.
func summarizeCheckArgs(severities, tags []string, category, framework string, controls []controlFilter) string {
	parts := []string{}
	for _, s := range severities {
		parts = append(parts, "-s "+s)
	}
	for _, t := range tags {
		parts = append(parts, "-t "+t)
	}
	if category != "" {
		parts = append(parts, "-c "+category)
	}
	if framework != "" {
		parts = append(parts, "-f "+framework)
	}
	if len(controls) > 0 {
		parts = append(parts, fmt.Sprintf("--control x%d", len(controls)))
	}
	return strings.Join(parts, " ")
}

// persistScanResult writes a check-mode ScanResult into the
// store as one session with N transactions attached. C-041
// makes this opt-in via --store on `kensa check`; pre-Phase-4
// check was strictly read-only.
//
// The rules slice MUST be the same ordered list scan iterated;
// result.Transactions[i] corresponds to rules[i]. The scan
// layer (internal/scan) preserves this positional alignment.
//
// The scan layer doesn't populate TransactionResult.Envelope
// (that's the engine's job during remediate's commit phase).
// For check-only persistence we construct minimal envelopes
// here from the rule + host context: rule_id, host_id,
// severity, framework_refs from the rule's references block.
// Signature is empty (the noopSigner placeholder covers
// remediate too — see security.md for the M7 task #12 gap).
//
// Returns the session ID for diagnostics and any error from
// the store. Best-effort on per-transaction writes: one
// failed PersistResult is logged but doesn't abort remaining
// writes — matches the engine's commit.go "_ = e.store.
// PersistResult(...)" pattern. Session creation and finish
// are required and propagate errors.
func persistScanResult(ctx context.Context, s *store.SQLite, host string, rules []*api.Rule, result *api.ScanResult, sess *store.Session) (uuid.UUID, error) {
	if sess == nil {
		return uuid.Nil, fmt.Errorf("persistScanResult: nil session")
	}
	if err := s.CreateSession(ctx, sess); err != nil {
		return uuid.Nil, fmt.Errorf("create session: %w", err)
	}

	for i := range result.Transactions {
		// Positional alignment: rules[i] produced
		// result.Transactions[i]. Skip out-of-bounds entries
		// rather than crash — the scan layer COULD insert
		// errored transactions in a future change.
		if i >= len(rules) {
			break
		}
		rl := rules[i]
		txn := &result.Transactions[i]
		// Construct a minimal envelope so PersistResult will
		// accept the transaction. PersistResult requires
		// Envelope != nil and pulls RuleID / HostID / FleetID /
		// Severity / FrameworkRefs / Signature from it.
		txn.Envelope = &api.EvidenceEnvelope{
			SchemaVersion: "v1",
			TransactionID: txn.TransactionID,
			RuleID:        rl.ID,
			HostID:        host,
			StartedAt:     txn.StartedAt,
			FinishedAt:    txn.FinishedAt,
			Decision:      txn.Status,
			Severity:      rl.Severity,
			FrameworkRefs: mappings.RefsFromReferences(rl.References),
			ApplySteps:    txn.Steps,
			Signature:     []byte{}, // noopSigner — empty until M7 task #12
		}
		if err := s.PersistResult(ctx, txn); err != nil {
			fmt.Fprintf(os.Stderr, "warn: persist scan result for %s: %v\n", rl.ID, err)
			continue
		}
		if err := s.AttachTransaction(ctx, txn.TransactionID, sess.ID); err != nil {
			fmt.Fprintf(os.Stderr, "warn: attach %s to session: %v\n", txn.TransactionID, err)
		}
	}

	if err := s.FinishSession(ctx, sess.ID, time.Now().UTC()); err != nil {
		return sess.ID, fmt.Errorf("finish session: %w", err)
	}
	return sess.ID, nil
}
