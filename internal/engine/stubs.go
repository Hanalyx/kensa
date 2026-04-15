package engine

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// inMemoryStore is a non-durable [Store] used during Week 2 before the
// SQLite implementation lands in Week 3 (see KENSA_GO_DAY1_PLAN.md
// §11.1). Tests also use it when a real SQLite file would add
// unnecessary fixture cost. Production code wires the SQLite store via
// [Engine.WithStore].
type inMemoryStore struct {
	mu      sync.Mutex
	pre     map[uuid.UUID][]api.PreState
	results map[uuid.UUID]*api.TransactionResult
}

func newInMemoryStore() *inMemoryStore {
	return &inMemoryStore{
		pre:     make(map[uuid.UUID][]api.PreState),
		results: make(map[uuid.UUID]*api.TransactionResult),
	}
}

func (s *inMemoryStore) PersistPreStates(_ context.Context, txnID uuid.UUID, preStates []api.PreState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]api.PreState, len(preStates))
	copy(cp, preStates)
	s.pre[txnID] = cp
	return nil
}

func (s *inMemoryStore) PersistResult(_ context.Context, result *api.TransactionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[result.TransactionID] = result
	return nil
}

func (s *inMemoryStore) LoadPreStates(_ context.Context, txnID uuid.UUID) ([]api.PreState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pre[txnID], nil
}

// noopSigner is a [Signer] that records key ID but emits an empty
// signature. Replaced by a real Ed25519 signer in Week 25 per
// KENSA_GO_DAY1_PLAN.md §11.5. Until then envelope signatures verify
// only structurally; the engine still produces fully-shaped envelopes.
type noopSigner struct{}

func (noopSigner) Sign(_ *api.EvidenceEnvelope) ([]byte, string, error) {
	return []byte{}, "noop", nil
}

func (noopSigner) Verify(envelope *api.EvidenceEnvelope) (*api.VerifyResult, error) {
	return &api.VerifyResult{
		Valid:    envelope.SigningKeyID == "noop",
		KeyID:    envelope.SigningKeyID,
		SignedAt: envelope.FinishedAt,
	}, nil
}

// noopDeadman is a [DeadmanArmer] that records arm/cancel calls without
// scheduling anything on the host. Replaced by the at(1)/systemd-run
// implementation in Week 15-16 per KENSA_GO_DAY1_PLAN.md §11.4. Until
// then control-channel-sensitive changes appear armed but do not have
// a real out-of-band rollback path; rules that require true atomicity
// in the presence of control-channel risk should not be remediated
// against production hosts before Week 16.
type noopDeadman struct{}

func (noopDeadman) Arm(_ context.Context, _ api.Transport, _ uuid.UUID, _ []api.PreState) (string, int64, error) {
	return "/tmp/kensa-rollback-noop.sh", time.Now().Add(120 * time.Second).Unix(), nil
}

func (noopDeadman) Cancel(_ context.Context, _ api.Transport, _ uuid.UUID) error {
	return nil
}

// noopEventBus is a no-op [EventBus] used when the caller does not wire
// a real bus. Engine hooks publish to it freely; nothing is ever
// delivered to subscribers.
type noopEventBus struct{}

func (noopEventBus) Publish(_ context.Context, _ api.Event) error { return nil }

func (noopEventBus) Subscribe(ctx context.Context, _ api.EventFilter) (<-chan api.Event, error) {
	ch := make(chan api.Event)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}
