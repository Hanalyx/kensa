// Package engine implements the four-phase transaction coordinator
// (capture → apply → validate → commit-or-rollback) defined by the
// engine-transaction spec (specs/engine/transaction.spec.yaml).
//
// The engine is Tier 1: its correctness IS the atomicity commitment
// in docs/TRANSACTION_CONTRACT_V1.md. Every change to this package
// requires a human-authored failure-mode analysis in the PR per
// CONTRIBUTING.md, and the rollback path requires two-human review.
package engine

import (
	"context"

	"github.com/Hanalyx/kensa-go/api"
)

// Engine coordinates transaction execution. It is the implementation
// behind api.Kensa's execution methods.
//
// The public api.Kensa wraps an Engine; the split exists so internal/
// implementations can evolve freely while the api/ surface stays v1-stable.
type Engine struct {
	// unexported internals land in Week 2 per KENSA_GO_DAY1_PLAN.md §11.1
}

// New constructs an Engine. Configuration lives in api.Config.
func New(cfg api.Config) (*Engine, error) {
	return &Engine{}, nil
}

// Run executes a transaction against a host via the provided transport.
// The full run loop per engine-transaction spec AC-01 through AC-11
// lands in Week 2 (milestone M1 at Week 4).
//
// Returns api.ErrNotYetImplemented until the run loop implementation
// lands. See docs/KENSA_GO_DAY1_PLAN.md §11.1 for the milestone schedule.
func (e *Engine) Run(ctx context.Context, transport api.Transport, txn *api.Transaction) (*api.TransactionResult, error) {
	return nil, api.ErrNotYetImplemented
}
