package engine_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// recordingEmitter records the phase names the engine emits.
type recordingEmitter struct{ phases []string }

func (r *recordingEmitter) EmitPhase(_, phase string, _ bool) {
	r.phases = append(r.phases, phase)
}

func txnFor(mech string) *api.Transaction {
	return &api.Transaction{
		ID:            uuid.New(),
		HostID:        "test-host",
		Severity:      "medium",
		Steps:         []api.Step{{Index: 0, Mechanism: mech}},
		StartedAt:     time.Now().UTC(),
		Deadline:      time.Now().Add(time.Minute),
		Transactional: true,
	}
}

// A committed transaction emits started → capture → apply → validate →
// committed, in order.
//
// @spec engine-audit-emission
// @ac AC-01
func TestEmit_CommittedSequence(t *testing.T) {
	t.Run("engine-audit-emission/AC-01", func(t *testing.T) {})
	r := handler.NewRegistry()
	r.Register(&engine.FakeHandler{HandlerName: "fake_ok", IsCapturable: true})
	em := &recordingEmitter{}
	e := engine.New(engine.WithRegistry(r), engine.WithAuditEmitter(em))

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txnFor("fake_ok"), false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Fatalf("status = %s, want committed", res.Status)
	}
	want := []string{"started", "capture", "apply", "validate", "committed"}
	if !reflect.DeepEqual(em.phases, want) {
		t.Errorf("emitted phases = %v, want %v", em.phases, want)
	}
}

// A rolled-back transaction (apply fails) emits started → capture → apply
// → rolled_back, with no validate phase.
//
// @spec engine-audit-emission
// @ac AC-02
func TestEmit_RolledBackSequence(t *testing.T) {
	t.Run("engine-audit-emission/AC-02", func(t *testing.T) {})
	r := handler.NewRegistry()
	r.Register(&engine.FakeHandler{
		HandlerName:  "fake_fail",
		IsCapturable: true,
		ApplyErr:     errors.New("induced apply failure"),
	})
	em := &recordingEmitter{}
	e := engine.New(engine.WithRegistry(r), engine.WithAuditEmitter(em))

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txnFor("fake_fail"), false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != api.StatusRolledBack {
		t.Fatalf("status = %s, want rolled_back", res.Status)
	}
	want := []string{"started", "capture", "apply", "rolled_back"}
	if !reflect.DeepEqual(em.phases, want) {
		t.Errorf("emitted phases = %v, want %v", em.phases, want)
	}
}

// The default engine (no emitter wired) runs to completion without
// panicking — emission is off by default and never affects the outcome.
//
// @spec engine-audit-emission
// @ac AC-03
func TestEmit_NoopDefaultIsSafe(t *testing.T) {
	t.Run("engine-audit-emission/AC-03", func(t *testing.T) {})
	r := handler.NewRegistry()
	r.Register(&engine.FakeHandler{HandlerName: "fake_ok", IsCapturable: true})
	e := engine.New(engine.WithRegistry(r)) // no WithAuditEmitter

	res, err := e.Run(context.Background(), engine.NewFakeTransport(), txnFor("fake_ok"), false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != api.StatusCommitted {
		t.Errorf("status = %s, want committed", res.Status)
	}
}
