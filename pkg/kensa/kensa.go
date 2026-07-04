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
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/engine/deadman"
	"github.com/Hanalyx/kensa/internal/evidence"
	"github.com/Hanalyx/kensa/internal/progress"
	"github.com/Hanalyx/kensa/internal/scan"
	"github.com/Hanalyx/kensa/internal/store"
	"github.com/Hanalyx/kensa/internal/transport/ssh"
)

// Service wraps an [api.Kensa] together with the closable resources
// (the SQLite store) that the wiring owns. Callers should call
// [Service.Close] to release them on shutdown.
type Service struct {
	*api.Kensa
	store    *store.SQLite
	eventBus *engine.InMemoryEventBus
	eng      api.Engine
}

// RemediateWithProgress runs a remediation exactly like
// [api.Kensa.Remediate] — connect a transport for host, then drive the
// scanner — but wires a per-rule [progress.Sink] into the scanner so a
// renderer can stream one result row per rule as each completes (covering
// every outcome: already-compliant, fixed, failed, errored). It lives in
// this assembly layer, building a sink-wired runner directly, so the frozen
// api/ ScannerBackend contract stays untouched. A nil sink is a no-op
// (byte-identical to Remediate).
func (s *Service) RemediateWithProgress(ctx context.Context, host api.HostConfig, rules []*api.Rule, sink progress.Sink) (*api.RemediationResult, error) {
	transport, err := ssh.Factory{}.Connect(ctx, host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = transport.Close() }()

	runner := scan.New(s.eng, scan.WithProgress(sink), scan.WithHostID(host.Hostname))
	result, err := runner.RemediateWithOverrides(ctx, transport, rules, host.Capabilities)
	if err != nil {
		return nil, err
	}
	result.HostID = host.Hostname
	return result, nil
}

// Subscribe returns a channel of events matching filter. The channel
// closes when ctx is done.
func (s *Service) Subscribe(ctx context.Context, filter api.EventFilter) (<-chan api.Event, error) {
	return s.eventBus.Subscribe(ctx, filter)
}

// RecordRemediateSession groups the transactions a remediation just committed
// under a new session, so the session-aware rollback workflow
// (`kensa list sessions`, `kensa rollback --start SESSION`) can find them. The
// engine persists each transaction with a NULL session_id during its commit
// phase; without this grouping a remediation's committed transactions are
// invisible to `list sessions` and reachable only by the legacy
// `rollback --txn UUID` path.
//
// It attaches through the SAME store handle the engine wrote the transactions
// with, so the just-committed rows are guaranteed visible (a second store
// connection would not see them until the engine's WAL is checkpointed).
// Sessions are a CLI-invocation grouping, so this is a CLI-driven step, not
// part of Remediate itself — an API embedder (e.g. OpenWatch) does its own
// run grouping.
//
// Best-effort by the caller's contract: the host is already changed, so the
// CLI treats any error here as a warning. Returns the new session ID, or
// uuid.Nil when there is no store (scan-only construction) or no transaction
// to group. If some transactions fail to attach, the session still groups the
// rest and an error names the count.
func (s *Service) RecordRemediateSession(ctx context.Context, host string, result *api.RemediationResult) (uuid.UUID, error) {
	if s.store == nil || result == nil || len(result.Transactions) == 0 {
		return uuid.Nil, nil
	}
	startedAt := result.Transactions[0].StartedAt
	for i := range result.Transactions {
		if t := result.Transactions[i].StartedAt; !t.IsZero() && t.Before(startedAt) {
			startedAt = t
		}
	}
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}

	sess := &store.Session{
		ID:          uuid.New(),
		StartedAt:   startedAt,
		Hostname:    host,
		Subcommand:  "remediate",
		ArgsSummary: fmt.Sprintf("%d rule(s)", len(result.Transactions)),
	}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		return uuid.Nil, fmt.Errorf("create session: %w", err)
	}
	var failed int
	for i := range result.Transactions {
		txnID := result.Transactions[i].TransactionID
		if txnID == uuid.Nil {
			continue
		}
		if err := s.store.AttachTransaction(ctx, txnID, sess.ID); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "warn: attach %s to session: %v\n", txnID, err)
		}
	}
	if err := s.store.FinishSession(ctx, sess.ID, time.Now().UTC()); err != nil {
		return sess.ID, fmt.Errorf("finish session: %w", err)
	}
	if failed > 0 {
		return sess.ID, fmt.Errorf("%d transaction(s) could not be attached to the rollback session", failed)
	}
	return sess.ID, nil
}

// GetSession returns the recorded session by ID. Exposed so session-aware CLI
// paths (notably `kensa rollback --start`) can read session metadata through
// the same store handle the service already owns, instead of opening a second
// SQLite handle on the same WAL database.
func (s *Service) GetSession(ctx context.Context, sessID uuid.UUID) (*store.Session, error) {
	if s.store == nil {
		return nil, fmt.Errorf("kensa: service has no store")
	}
	return s.store.GetSession(ctx, sessID)
}

// CommittedTxnIDs returns the committed transaction refs for a session,
// earliest-first — the set `rollback --start` reverts. Shares the service's
// store handle (see [Service.GetSession]).
func (s *Service) CommittedTxnIDs(ctx context.Context, sessID uuid.UUID) ([]store.TxnRef, error) {
	if s.store == nil {
		return nil, fmt.Errorf("kensa: service has no store")
	}
	return s.store.CommittedTxnIDs(ctx, sessID)
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
// Log, Verifier — are populated.
//
// Signing-key resolution (C-060):
//   - If KENSA_SIGNING_KEY env var is set, load the key at that
//     path via [evidence.LoadSigner]. The path points at a
//     PEM-encoded PKCS#8 Ed25519 .priv file, typically produced
//     by kensa-keygen.
//   - Otherwise, generate a fresh ephemeral keypair via
//     [evidence.Generate]. Useful for one-shot CLI runs and
//     tests; signatures from one run cannot be verified by
//     another because the private key isn't persisted.
//
// Production deployments wanting cross-invocation verifiability
// MUST set KENSA_SIGNING_KEY to a persistent kensa-keygen-
// produced .priv file.
//
// An empty storePath defaults to ".kensa/results.db" in the current
// working directory.
func Default(ctx context.Context, storePath string) (*Service, error) {
	return DefaultWithEngineOptions(ctx, storePath)
}

// DefaultWithEngineOptions is the option-aware variant of
// Default. Callers passing additional engine.Option values
// (e.g., engine.WithAgentClient for L-014b agent-mode
// dispatch) get an engine that composes those on top of the
// standard Store / Signer / Deadman / Events options.
//
// Default is preserved as a thin call into this function
// with no extra options so existing callers (OpenWatch,
// v1 consumers) work unchanged.
//
// L-014b deliverable per spec agent-cli-env-var C-01.
func DefaultWithEngineOptions(ctx context.Context, storePath string, engineOpts ...engine.Option) (*Service, error) {
	return defaultService(ctx, storePath, ssh.Factory{}, engineOpts...)
}

// DefaultWithTransportFactory is Default with the transport swapped:
// the standard engine / store / signer / scanner wiring, but every
// remote connection goes through the caller's tf instead of the
// bundled on-disk-key [ssh.Factory]. For embedders whose credential
// model the bundled factory cannot serve — e.g. an orchestrator
// (OpenWatch) that decrypts SSH credentials in memory only and
// implements [api.Transport] over its own SSH stack.
//
// Everything else matches [DefaultWithEngineOptions], including the
// KENSA_SIGNING_KEY handling and the engineOpts composition. A nil tf
// is rejected at construction.
//
// Embedders that only need the read-only scan path (no remediation,
// no transaction log) can avoid constructing the engine and store
// entirely: compose [api.New] directly with [NewScanner] and their
// TransportFactory.
func DefaultWithTransportFactory(ctx context.Context, storePath string, tf api.TransportFactory, engineOpts ...engine.Option) (*Service, error) {
	if tf == nil {
		return nil, fmt.Errorf("kensa: DefaultWithTransportFactory: nil TransportFactory")
	}
	return defaultService(ctx, storePath, tf, engineOpts...)
}

// defaultService is the shared builder behind Default,
// DefaultWithEngineOptions, and DefaultWithTransportFactory.
func defaultService(ctx context.Context, storePath string, tf api.TransportFactory, engineOpts ...engine.Option) (*Service, error) {
	if storePath == "" {
		storePath = ".kensa/results.db"
	}
	s, err := store.OpenSQLite(ctx, storePath)
	if err != nil {
		return nil, fmt.Errorf("kensa: open store: %w", err)
	}
	var signer *evidence.Signer
	if keyPath := os.Getenv("KENSA_SIGNING_KEY"); keyPath != "" {
		signer, err = evidence.LoadSigner(keyPath)
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("kensa: KENSA_SIGNING_KEY=%s: %w", keyPath, err)
		}
	} else {
		signer, err = evidence.Generate()
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("kensa: generate signing key: %w", err)
		}
	}
	bus := engine.NewInMemoryEventBus()

	// Standard option set; caller-supplied options appended
	// last so they can override (or compose with, e.g.,
	// WithAgentClient) the standard set.
	stdOpts := []engine.Option{
		engine.WithStore(storeAdapter{s}),
		// Fence live mutations against `kensa recover` on the same store: the
		// engine takes this lock SHARED while a recover takes it EXCLUSIVE
		// (security.md #14). Keyed on the store path this service just opened.
		engine.WithRecoverLock(store.RecoverLockPath(storePath)),
		engine.WithDeadman(deadman.New(0, nil)),
		engine.WithSigner(signer),
		engine.WithEvents(bus),
		// Emit a transaction-phase record into the host's auditd
		// at each phase boundary. Best-effort — NewEmitter degrades to a
		// no-op when the AUDIT netlink socket can't be opened (no
		// privilege), so this never affects a transaction.
		engine.WithAuditEmitter(auditnl.NewEmitter()),
	}
	allOpts := make([]engine.Option, 0, len(stdOpts)+len(engineOpts))
	allOpts = append(allOpts, stdOpts...)
	allOpts = append(allOpts, engineOpts...)
	eng := engine.New(allOpts...)

	cfg := api.Config{
		StorePath:        storePath,
		Engine:           eng,
		TransportFactory: tf,
		Log:              s,
		Verifier:         signer,
		Scanner:          scan.New(eng),
	}
	k, err := api.New(cfg)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("kensa: new: %w", err)
	}
	return &Service{Kensa: k, store: s, eventBus: bus, eng: eng}, nil
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
