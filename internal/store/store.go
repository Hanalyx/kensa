// Package store implements the persistent transaction log defined by
// the transaction-log spec (specs/store/transaction_log.spec.yaml).
//
// The default backend is SQLite (see [SQLite]). The package also
// exposes a [LogQuery] adapter that satisfies the [api.LogQuery]
// interface, so consumers can use any [Store] implementation behind
// the public Kensa API.
//
// The engine writes through a [Store] before any apply step runs
// (engine-transaction spec C-02), so a crash between write and apply
// leaves the captured pre-state recoverable for out-of-band rollback
// via `kensa rollback --start N`.
package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// Store is the persistence interface the engine writes through. The
// SQLite backend is the production implementation; tests may provide
// an in-memory implementation.
type Store interface {
	// PersistPreStates writes the pre-state bundle for a transaction.
	// Must complete (write + fsync) before the engine enters the apply
	// phase.
	PersistPreStates(ctx context.Context, txnID uuid.UUID, preStates []api.PreState) error

	// PersistResult writes the terminal [api.TransactionResult].
	// Called once per transaction at the commit-or-rollback terminus.
	PersistResult(ctx context.Context, result *api.TransactionResult) error

	// LoadPreStates returns the persisted pre-state bundle for a
	// transaction. Used by `kensa rollback --start N`.
	LoadPreStates(ctx context.Context, txnID uuid.UUID) ([]api.PreState, error)

	// Query returns transactions matching filter, paginated.
	Query(ctx context.Context, filter api.LogFilter, page api.Page) (*api.QueryResult, error)

	// Get returns the [api.TransactionRecord] for txnID.
	Get(ctx context.Context, txnID uuid.UUID, opts ...api.GetOption) (*api.TransactionRecord, error)

	// Aggregate returns posture summaries.
	Aggregate(ctx context.Context, filter api.LogFilter, groupBy api.AggregateKey, opts ...api.AggregateOption) (*api.AggregateResult, error)

	// Close releases any resources (open file handles, prepared
	// statements). Safe to call multiple times.
	Close() error
}
