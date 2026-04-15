// Package kensa is the assembly layer that wires the public api/
// surface to the standard internal implementations. Consumers who
// want a fully-functional Kensa instance call [Default]; consumers
// who want to compose their own implementations use [api.New]
// directly.
//
// The package lives outside internal/ because it imports both api/
// (for public types) and internal/ packages (for implementations);
// internal Go packages cannot be imported across module boundaries,
// so the wiring layer must be public-but-thin.
//
// Typical usage:
//
//	k, err := kensa.Default(ctx, "/var/lib/kensa/results.db")
//	if err != nil { /* ... */ }
//	defer k.Close()
//
//	res, err := k.Transact(ctx, host, txn)
package kensa

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/deadman"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/evidence"
	"github.com/Hanalyx/kensa-go/internal/store"
	"github.com/Hanalyx/kensa-go/internal/transport/ssh"
)

// Service wraps an [api.Kensa] together with the closable resources
// (the SQLite store) that the wiring owns. Callers should call
// [Service.Close] to release them on shutdown.
type Service struct {
	*api.Kensa
	store *store.SQLite
}

// Close releases owned resources. Safe to call multiple times.
func (s *Service) Close() error {
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}

// Default returns a fully-wired [Service]. The wiring opens a SQLite
// transaction log at storePath, constructs the standard transaction
// engine from internal/engine, and registers the SSH transport
// factory from internal/transport/ssh.
//
// All four [api.Config] backing fields — Engine, TransportFactory,
// Log, Verifier — are populated. The evidence signer is generated
// fresh on each call; production deployments should load a persisted
// key via [evidence.New] and wire it in via a custom [api.Config].
//
// An empty storePath defaults to ".kensa/results.db" in the current
// working directory.
func Default(ctx context.Context, storePath string) (*Service, error) {
	if storePath == "" {
		storePath = ".kensa/results.db"
	}
	s, err := store.OpenSQLite(ctx, storePath)
	if err != nil {
		return nil, fmt.Errorf("kensa: open store: %w", err)
	}
	signer, err := evidence.Generate()
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("kensa: generate signing key: %w", err)
	}
	cfg := api.Config{
		StorePath: storePath,
		Engine: engine.New(
			engine.WithStore(storeAdapter{s}),
			engine.WithDeadman(deadman.New(0, nil)),
			engine.WithSigner(signer),
		),
		TransportFactory: ssh.Factory{},
		Log:              s,
		Verifier:         signer,
	}
	k, err := api.New(cfg)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("kensa: new: %w", err)
	}
	return &Service{Kensa: k, store: s}, nil
}

// storeAdapter bridges the [store.SQLite] type to the
// [engine.Store] interface. Both interfaces are structurally
// equivalent for the methods engine.Store requires; the adapter
// exists only to satisfy Go's nominal interface check at the engine's
// package boundary.
type storeAdapter struct {
	*store.SQLite
}

// PersistPreStates forwards to the underlying SQLite store.
func (a storeAdapter) PersistPreStates(ctx context.Context, txnID uuid.UUID, preStates []api.PreState) error {
	return a.SQLite.PersistPreStates(ctx, txnID, preStates)
}

// PersistResult forwards to the underlying SQLite store.
func (a storeAdapter) PersistResult(ctx context.Context, result *api.TransactionResult) error {
	return a.SQLite.PersistResult(ctx, result)
}

// LoadPreStates forwards to the underlying SQLite store.
func (a storeAdapter) LoadPreStates(ctx context.Context, txnID uuid.UUID) ([]api.PreState, error) {
	return a.SQLite.LoadPreStates(ctx, txnID)
}
