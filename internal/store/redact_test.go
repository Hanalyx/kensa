package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// TestPersistResult_RedactsEnvelopeBundle proves the store scrubs
// credential values from an unsigned (errored) envelope's captured-state
// bundle before writing the envelope record, so a Get round-trip returns
// "<redacted>".
//
// @spec store-redaction
// @ac AC-05
func TestPersistResult_RedactsEnvelopeBundle(t *testing.T) {
	t.Log("// @spec store-redaction")
	t.Log("// @ac AC-05")

	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.New()

	result := &api.TransactionResult{
		TransactionID: id,
		Status:        api.StatusErrored,
		StartedAt:     now,
		FinishedAt:    now.Add(time.Second),
		Envelope: &api.EvidenceEnvelope{
			SchemaVersion: "v1",
			TransactionID: id,
			RuleID:        "r",
			HostID:        "h",
			StartedAt:     now,
			FinishedAt:    now.Add(time.Second),
			Decision:      api.StatusErrored,
			Signature:     []byte{}, // unsigned errored path
			PreStateBundle: []api.PreState{
				{
					StepIndex:  0,
					Mechanism:  "config_set",
					Capturable: true,
					Data:       map[string]any{"path": "/etc/x", "api_key": "AKIA-secret"}, // pragma: allowlist secret
					CapturedAt: now,
				},
			},
		},
	}
	if err := s.PersistResult(ctx, result); err != nil {
		t.Fatalf("PersistResult: %v", err)
	}

	rec, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Envelope == nil || len(rec.Envelope.PreStateBundle) != 1 {
		t.Fatalf("envelope not round-tripped: %+v", rec.Envelope)
	}
	got := rec.Envelope.PreStateBundle[0].Data["api_key"] // pragma: allowlist secret
	if got != "<redacted>" {
		t.Errorf("api_key not redacted in stored envelope: %v", got)
	}
	if p := rec.Envelope.PreStateBundle[0].Data["path"]; p != "/etc/x" {
		t.Errorf("non-sensitive path altered: %v", p)
	}
}

// TestPersistPreStates_KeepsRollbackDataVerbatim proves the pre_states
// table (the rollback restoration source) is NOT redacted: a credential-
// named field round-trips unchanged, so rollback restores the real value.
//
// @spec store-redaction
// @ac AC-06
func TestPersistPreStates_KeepsRollbackDataVerbatim(t *testing.T) {
	t.Log("// @spec store-redaction")
	t.Log("// @ac AC-06")

	s := newTestStore(t)
	ctx := context.Background()
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)

	pre := []api.PreState{
		{
			StepIndex:  0,
			Mechanism:  "config_set",
			Capturable: true,
			Data:       map[string]any{"path": "/etc/x", "password": "keep-me-exact"}, // pragma: allowlist secret
			CapturedAt: now,
		},
	}
	if err := s.PersistPreStates(ctx, id, pre); err != nil {
		t.Fatalf("PersistPreStates: %v", err)
	}

	loaded, err := s.LoadPreStates(ctx, id)
	if err != nil {
		t.Fatalf("LoadPreStates: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 pre-state, got %d", len(loaded))
	}
	if got := loaded[0].Data["password"]; got != "keep-me-exact" { // pragma: allowlist secret
		t.Errorf("rollback pre-state must be verbatim, got %v — redacting it would corrupt restoration", got)
	}
}
