package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// finalize composes the [api.TransactionResult], generates and signs
// the evidence envelope, persists the result, publishes the terminal
// event, and returns the result to the caller. Used for both COMMIT
// and ROLLBACK terminal paths since the post-processing is identical
// modulo Status.
func (e *Engine) finalize(
	ctx context.Context,
	txn *api.Transaction,
	startedAt time.Time,
	status api.TransactionStatus,
	steps []api.StepResult,
	preStates []api.PreState,
	validators []api.ValidatorResult,
	rollbacks []api.RollbackResult,
) *api.TransactionResult {
	now := time.Now().UTC()
	result := &api.TransactionResult{
		TransactionID: txn.ID,
		Status:        status,
		Steps:         steps,
		PreStates:     preStates,
		StartedAt:     startedAt,
		FinishedAt:    now,
	}
	switch status {
	case api.StatusCommitted:
		t := now
		result.CommittedAt = &t
	case api.StatusRolledBack:
		t := now
		result.RolledBackAt = &t
	}

	// Build the evidence envelope per evidence-envelope spec.
	envelope := &api.EvidenceEnvelope{
		SchemaVersion:    "v1",
		TransactionID:    txn.ID,
		RuleID:           txn.RuleID,
		HostID:           txn.HostID,
		FleetID:          txn.FleetID,
		StartedAt:        startedAt,
		FinishedAt:       now,
		PreStateBundle:   preStates,
		ApplySteps:       steps,
		ValidatorResults: validators,
		Decision:         status,
		Severity:         txn.Severity,
		PostStateBundle:  nil, // populated by post-state recapture in a later milestone
		FrameworkRefs:    txn.FrameworkRefs,
	}
	// C-060 contract: every committed transaction MUST carry a real
	// Ed25519 signature. Silently swallowing Sign errors here would
	// produce a fully-committed audit record with empty signature
	// bytes — exactly the v1.0 disclaimer C-060 was supposed to
	// retire. If Sign fails, demote the transaction to StatusErrored
	// and surface the error so the caller sees the failure rather
	// than persisting an unsigned envelope as if all is well.
	sig, keyID, err := e.signer.Sign(envelope)
	if err != nil {
		result.Status = api.StatusErrored
		result.Error = fmt.Errorf("signer: %w", err)
		envelope.Decision = api.StatusErrored
		envelope.Signature = nil
		envelope.SigningKeyID = ""
	} else {
		envelope.Signature = sig
		envelope.SigningKeyID = keyID
	}
	result.Envelope = envelope

	// Mark stranded steps for transactional:false partial application.
	if status == api.StatusPartiallyApplied {
		for i := range result.Steps {
			if result.Steps[i].Success && !result.Steps[i].Capturable {
				result.Steps[i].Stranded = true
			}
		}
	}

	// Persist before returning so a caller that observes the
	// committed result can read it back from the store.
	_ = e.store.PersistResult(ctx, result)

	// Publish terminal event.
	switch status {
	case api.StatusCommitted:
		e.publish(ctx, api.Event{
			Kind:      api.Committed,
			TxnID:     &txn.ID,
			HostID:    txn.HostID,
			Timestamp: now,
		})
	case api.StatusRolledBack, api.StatusPartiallyApplied:
		source := "inline"
		if len(rollbacks) > 0 && rollbacks[0].Source != "" {
			source = rollbacks[0].Source
		}
		e.publish(ctx, api.Event{
			Kind:      api.RolledBack,
			TxnID:     &txn.ID,
			HostID:    txn.HostID,
			Timestamp: now,
			Data:      api.RolledBackData{Source: source, RuleID: txn.RuleID},
		})
	}

	return result
}

// errored constructs an [api.TransactionResult] for an
// [api.StatusErrored] outcome. The phase argument identifies which
// phase failed for diagnostics.
func (e *Engine) errored(ctx context.Context, txn *api.Transaction, startedAt time.Time, phase api.Phase, err error) *api.TransactionResult {
	now := time.Now().UTC()
	result := &api.TransactionResult{
		TransactionID: txn.ID,
		Status:        api.StatusErrored,
		StartedAt:     startedAt,
		FinishedAt:    now,
		Error:         err,
	}
	_ = e.store.PersistResult(ctx, result)
	e.publish(ctx, api.Event{
		Kind:      api.PhaseCompleted,
		TxnID:     &txn.ID,
		HostID:    txn.HostID,
		Timestamp: now,
		Data: api.PhaseCompletedData{
			Phase:    phase,
			Success:  false,
			Duration: time.Since(startedAt),
			RuleID:   txn.RuleID,
		},
	})
	return result
}
