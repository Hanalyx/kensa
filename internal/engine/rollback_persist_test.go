package engine_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// recordingRollbackStore implements engine.Store plus the optional
// engine.RollbackStore, capturing PersistRollback calls so a test can assert
// the engine records a rollback outcome after a successful revert.
type recordingRollbackStore struct {
	rolledBack map[uuid.UUID][]api.RollbackResult
}

func (r *recordingRollbackStore) PersistPreStates(context.Context, uuid.UUID, []api.PreState) error {
	return nil
}
func (r *recordingRollbackStore) PersistResult(context.Context, *api.TransactionResult) error {
	return nil
}
func (r *recordingRollbackStore) LoadPreStates(context.Context, uuid.UUID) ([]api.PreState, error) {
	return nil, nil
}
func (r *recordingRollbackStore) PersistRollback(_ context.Context, txnID uuid.UUID, results []api.RollbackResult, _ time.Time) error {
	if r.rolledBack == nil {
		r.rolledBack = map[uuid.UUID][]api.RollbackResult{}
	}
	r.rolledBack[txnID] = results
	return nil
}

func capturableRollbackRecord() *api.TransactionRecord {
	return &api.TransactionRecord{
		ID:     uuid.New(),
		RuleID: "fake-rule",
		Steps: []api.StepResult{
			{StepIndex: 0, Mechanism: "fake_cap", Capturable: true, Success: true},
		},
		PreStates: []api.PreState{
			{StepIndex: 0, Mechanism: "fake_cap", Capturable: true, Data: map[string]interface{}{"x": "y"}},
		},
	}
}

// TestRollbackTransaction_PersistsOutcome proves the engine records the
// rollback outcome (via the optional RollbackStore) after every step reverts.
//
// @spec cli-rollback-session-aware
// @ac AC-15
func TestRollbackTransaction_PersistsOutcome(t *testing.T) {
	t.Run("cli-rollback-session-aware/AC-15", func(t *testing.T) {})
	t.Log("// @spec cli-rollback-session-aware")
	t.Log("// @ac AC-15")

	r := handler.NewRegistry()
	r.Register(&engine.FakeHandler{HandlerName: "fake_cap", IsCapturable: true})
	store := &recordingRollbackStore{}
	e := engine.New(engine.WithRegistry(r), engine.WithStore(store))

	record := capturableRollbackRecord()
	res, err := e.RollbackTransaction(context.Background(), engine.NewFakeTransport(), record)
	if err != nil {
		t.Fatalf("RollbackTransaction: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected successful rollback, got %+v", res)
	}
	if _, ok := store.rolledBack[record.ID]; !ok {
		t.Error("engine did not persist the rollback outcome for the transaction")
	}
}

// TestRollbackTransaction_PartialFailureNotPersisted proves a rollback where a
// step fails is NOT recorded as rolled-back — the host is in a mixed state and
// the transaction must stay committed for the operator to inspect.
//
// @spec cli-rollback-session-aware
// @ac AC-15
func TestRollbackTransaction_PartialFailureNotPersisted(t *testing.T) {
	t.Run("cli-rollback-session-aware/AC-15", func(t *testing.T) {})
	t.Log("// @spec cli-rollback-session-aware")
	t.Log("// @ac AC-15")

	r := handler.NewRegistry()
	r.Register(&engine.FakeHandler{
		HandlerName:  "fake_cap",
		IsCapturable: true,
		RollbackErr:  errors.New("rollback failed on the host"),
	})
	store := &recordingRollbackStore{}
	e := engine.New(engine.WithRegistry(r), engine.WithStore(store))

	record := capturableRollbackRecord()
	res, _ := e.RollbackTransaction(context.Background(), engine.NewFakeTransport(), record)
	if res != nil && res.Success {
		t.Fatal("expected a failed rollback result when a step rollback errors")
	}
	if _, ok := store.rolledBack[record.ID]; ok {
		t.Error("a partial rollback must NOT be persisted as rolled-back")
	}
}
