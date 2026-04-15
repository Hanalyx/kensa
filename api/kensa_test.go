package api_test

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

// fakeEngine satisfies [api.Engine] for wiring tests.
type fakeEngine struct {
	called   bool
	gotTxn   *api.Transaction
	wantStat api.TransactionStatus
}

func (f *fakeEngine) Run(_ context.Context, _ api.Transport, txn *api.Transaction, _ bool) (*api.TransactionResult, error) {
	f.called = true
	f.gotTxn = txn
	return &api.TransactionResult{
		TransactionID: txn.ID,
		Status:        f.wantStat,
	}, nil
}

// fakeFactory satisfies [api.TransportFactory] returning a no-op
// transport.
type fakeFactory struct{ closeCalled int }

func (f *fakeFactory) Connect(_ context.Context, _ api.HostConfig) (api.Transport, error) {
	return &fakeTransport{factory: f}, nil
}

type fakeTransport struct{ factory *fakeFactory }

func (t *fakeTransport) Run(_ context.Context, _ string) (*api.CommandResult, error) {
	return &api.CommandResult{ExitCode: 0}, nil
}
func (t *fakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (t *fakeTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (t *fakeTransport) ControlChannelSensitive() bool                           { return false }
func (t *fakeTransport) Close() error {
	t.factory.closeCalled++
	return nil
}

// fakeLog satisfies [api.LogQuery] for wiring tests.
type fakeLog struct{}

func (fakeLog) Query(_ context.Context, _ api.LogFilter, _ api.Page) (*api.QueryResult, error) {
	return &api.QueryResult{}, nil
}
func (fakeLog) Get(_ context.Context, _ uuid.UUID, _ ...api.GetOption) (*api.TransactionRecord, error) {
	return &api.TransactionRecord{}, nil
}
func (fakeLog) Aggregate(_ context.Context, _ api.LogFilter, _ api.AggregateKey, _ ...api.AggregateOption) (*api.AggregateResult, error) {
	return &api.AggregateResult{}, nil
}

// fakeVerifier satisfies [api.EnvelopeVerifier].
type fakeVerifier struct{ called bool }

func (v *fakeVerifier) VerifyEnvelope(_ *api.EvidenceEnvelope) (*api.VerifyResult, error) {
	v.called = true
	return &api.VerifyResult{Valid: true}, nil
}

// TestKensa_StubsReturnNotYetImplemented confirms the documented
// behavior: zero-value Config yields a Kensa whose execution methods
// return ErrNotYetImplemented.
func TestKensa_StubsReturnNotYetImplemented(t *testing.T) {
	k, err := api.New(api.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if _, err := k.Transact(ctx, api.HostConfig{Hostname: "x"}, &api.Transaction{}); !errors.Is(err, api.ErrNotYetImplemented) {
		t.Errorf("Transact err=%v, want ErrNotYetImplemented", err)
	}
	if _, err := k.Scan(ctx, api.HostConfig{}, nil); !errors.Is(err, api.ErrNotYetImplemented) {
		t.Errorf("Scan err=%v, want ErrNotYetImplemented", err)
	}
	if _, err := k.Remediate(ctx, api.HostConfig{}, nil); !errors.Is(err, api.ErrNotYetImplemented) {
		t.Errorf("Remediate err=%v, want ErrNotYetImplemented", err)
	}
	if _, err := k.Rollback(ctx, api.HostConfig{}, uuid.New()); !errors.Is(err, api.ErrNotYetImplemented) {
		t.Errorf("Rollback err=%v, want ErrNotYetImplemented", err)
	}
	if k.TransactionLog() != nil {
		t.Error("TransactionLog should return nil when Config.Log is nil")
	}
	if _, err := k.VerifyEnvelope(&api.EvidenceEnvelope{}); !errors.Is(err, api.ErrNotYetImplemented) {
		t.Errorf("VerifyEnvelope err=%v, want ErrNotYetImplemented", err)
	}
}

// TestKensa_TransactDelegatesToEngine confirms that wiring an Engine
// + TransportFactory via Config makes Transact functional end-to-end.
func TestKensa_TransactDelegatesToEngine(t *testing.T) {
	eng := &fakeEngine{wantStat: api.StatusCommitted}
	fac := &fakeFactory{}
	k, err := api.New(api.Config{Engine: eng, TransportFactory: fac})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	txn := &api.Transaction{ID: uuid.New(), RuleID: "test", Steps: []api.Step{{Mechanism: "noop"}}}
	res, err := k.Transact(context.Background(), api.HostConfig{Hostname: "h1"}, txn)
	if err != nil {
		t.Fatalf("Transact: %v", err)
	}
	if !eng.called {
		t.Fatal("expected engine.Run to be called")
	}
	if res.Status != api.StatusCommitted {
		t.Errorf("Status=%s, want Committed", res.Status)
	}
	// Transact should have populated HostID from HostConfig.
	if eng.gotTxn.HostID != "h1" {
		t.Errorf("Engine received HostID=%q, want %q", eng.gotTxn.HostID, "h1")
	}
	// Transport should have been closed via defer.
	if fac.closeCalled != 1 {
		t.Errorf("transport Close called %d times, want 1", fac.closeCalled)
	}
}

// TestKensa_TransactionLogReturnsConfigured confirms the LogQuery
// wired through Config.Log surfaces via TransactionLog().
func TestKensa_TransactionLogReturnsConfigured(t *testing.T) {
	log := fakeLog{}
	k, err := api.New(api.Config{Log: log})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := k.TransactionLog()
	if got == nil {
		t.Fatal("expected non-nil LogQuery when Config.Log is set")
	}
}

// TestKensa_VerifyEnvelopeDelegatesToVerifier confirms the
// EnvelopeVerifier wiring fires.
func TestKensa_VerifyEnvelopeDelegatesToVerifier(t *testing.T) {
	v := &fakeVerifier{}
	k, err := api.New(api.Config{Verifier: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := k.VerifyEnvelope(&api.EvidenceEnvelope{})
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if !v.called {
		t.Error("expected Verifier.VerifyEnvelope to be called")
	}
	if !res.Valid {
		t.Error("expected Valid=true")
	}
}
