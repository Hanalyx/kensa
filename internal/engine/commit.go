package engine

import (
	"context"
	"errors"
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
	transport api.Transport,
	txn *api.Transaction,
	startedAt time.Time,
	status api.TransactionStatus,
	steps []api.StepResult,
	preStates []api.PreState,
	validators []api.ValidatorResult,
	rollbacks []api.RollbackResult,
) *api.TransactionResult {
	// Terminal transaction-phase audit record (best-effort; never affects
	// the outcome). The status string is the phase name (committed /
	// rolled_back / partially_applied).
	e.emitter.EmitPhase(txn.ID.String(), string(status), status == api.StatusCommitted)

	now := time.Now().UTC()

	// Post-state recapture: re-read the host's end state so the signed
	// envelope proves a re-measurement, not just the attempted steps. Runs
	// before the envelope is built so the signature covers it; never fails
	// the transaction (a failed re-read is an "unobserved" entry).
	postStates := e.recapture(ctx, transport, txn)
	// For rollback outcomes, annotate each step with whether its recaptured
	// post-state byte-matches the captured pre-state — independent proof of
	// restoration beyond the handler's self-report. Recorded in the Detail
	// (audit-visible) without changing the verdict, which still derives from
	// the handler-reported Success/PartialRestore.
	if status == api.StatusRolledBack || status == api.StatusRollbackFailed || status == api.StatusPartiallyApplied || status == api.StatusRecovered {
		for i := range rollbacks {
			matched, observed := postMatchesPre(preStates, postStates, rollbacks[i].StepIndex)
			switch {
			case !observed:
				rollbacks[i].Detail += " [post-state: unobserved]"
			case matched:
				rollbacks[i].Detail += " [post-state: matches pre-state]"
			default:
				rollbacks[i].Detail += " [post-state: DIVERGES from pre-state]"
			}
		}
	}
	// HostUnchanged reflects the host state for THIS terminal status,
	// computed before any signer/persist demotion below: only a (verified)
	// rollback leaves the host provably in its pre-change state. A committed
	// or partially-applied outcome mutated the host. A later signer/persist
	// failure does not touch the host, so this value is preserved across the
	// demotion-to-errored paths.
	hostUnchanged := status == api.StatusRolledBack || status == api.StatusRecovered
	result := &api.TransactionResult{
		TransactionID:   txn.ID,
		Status:          status,
		Steps:           steps,
		PreStates:       preStates,
		RollbackResults: rollbacks,
		HostUnchanged:   hostUnchanged,
		StartedAt:       startedAt,
		FinishedAt:      now,
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
		RollbackResults:  rollbacks,
		Decision:         status,
		Severity:         txn.Severity,
		PostStateBundle:  postStates,
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
		// Signing failed after apply/rollback already completed on the host.
		// Demote to errored but PRESERVE HostUnchanged: the host is in
		// whatever state apply or rollback left it; the signing failure did
		// not touch it. Clear the committed/rolled-back timestamps so they
		// keep their "non-nil iff that status" invariant.
		result.Status = api.StatusErrored
		result.Error = fmt.Errorf("signer: %w", err)
		result.CommittedAt = nil
		result.RolledBackAt = nil
		envelope.Decision = api.StatusErrored
		// Empty (non-nil) signature, not nil: the demoted-errored row must
		// persist into the NOT-NULL envelope_sig column (see erroredEnvelope).
		envelope.Signature = []byte{}
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

	// Persist before returning. A terminal result we cannot durably record
	// is NOT a real committed/rolled_back outcome (C-08): demote so the
	// caller never observes an unrecorded success. "Evidence written to the
	// transaction log" must be a fact, not a claim.
	if perr := e.store.PersistResult(ctx, result); perr != nil {
		if result.Status == api.StatusCommitted || result.Status == api.StatusRolledBack {
			result.Status = api.StatusErrored
			result.CommittedAt = nil
			result.RolledBackAt = nil
			if result.Error == nil {
				result.Error = fmt.Errorf("persist terminal result: %w", perr)
			}
			if result.Envelope != nil {
				result.Envelope.Decision = api.StatusErrored
			}
		}
	} else if js, ok := e.store.(JournalStore); ok {
		// Terminal record is durable, so the crash-recovery journal entry is
		// no longer needed (the persisted transactions row already removes it
		// from the open-entry set; this is hygiene). If persisting FAILED
		// above, we deliberately leave the entry so recovery still sees an
		// in-flight transaction. Best-effort: a failed clear is harmless.
		_ = js.ClearJournalEntry(ctx, txn.ID)
	}

	// Publish the terminal event for the FINAL status (post-demotion), so a
	// demoted result never publishes a Committed event it did not earn.
	switch result.Status {
	case api.StatusCommitted:
		e.publish(ctx, api.Event{
			Kind:      api.Committed,
			TxnID:     &txn.ID,
			HostID:    txn.HostID,
			Timestamp: now,
		})
	case api.StatusRolledBack, api.StatusPartiallyApplied, api.StatusRollbackFailed, api.StatusRecovered:
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
	case api.StatusErrored:
		e.publish(ctx, api.Event{
			Kind:      api.PhaseCompleted,
			TxnID:     &txn.ID,
			HostID:    txn.HostID,
			Timestamp: now,
			Data: api.PhaseCompletedData{
				Phase:    api.PhaseCommit,
				Success:  false,
				Duration: time.Since(startedAt),
				RuleID:   txn.RuleID,
			},
		})
	}

	return result
}

// errored constructs an [api.TransactionResult] for an
// [api.StatusErrored] outcome. The phase argument identifies which
// phase failed for diagnostics.
func (e *Engine) errored(ctx context.Context, txn *api.Transaction, startedAt time.Time, phase api.Phase, err error) *api.TransactionResult {
	e.emitter.EmitPhase(txn.ID.String(), "errored", false)

	now := time.Now().UTC()
	result := &api.TransactionResult{
		TransactionID: txn.ID,
		Status:        api.StatusErrored,
		StartedAt:     startedAt,
		FinishedAt:    now,
		// Every errored() entry point is a pre-apply failure (preflight or
		// capture); the host is provably untouched. The post-apply signer/
		// persist failure path lives in finalize and preserves its own
		// HostUnchanged value.
		HostUnchanged: true,
		Error:         err,
	}
	// Record a durable, UNSIGNED evidence envelope so the errored outcome is
	// in the transaction log rather than vanishing (C-07). The store rejects
	// a nil envelope; C-06 permits an unsigned errored row, identified by the
	// errored decision + empty signature so verification tooling skips/flags
	// it rather than treating it as a valid signed record.
	result.Envelope = erroredEnvelope(txn, startedAt, now)
	if perr := e.store.PersistResult(ctx, result); perr != nil {
		// The outcome is already a failure the caller sees; surface the
		// persistence failure alongside it rather than silently dropping it.
		result.Error = errors.Join(result.Error, fmt.Errorf("persist errored result: %w", perr))
	}
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

// erroredEnvelope builds the durable, unsigned evidence envelope recorded
// for an errored transaction so the outcome is never silently unrecorded.
// It carries no apply/validator results (the transaction did not reach a
// successful apply) and no signature; the errored decision plus the empty
// signature is the marker verification tooling keys on.
func erroredEnvelope(txn *api.Transaction, startedAt, finishedAt time.Time) *api.EvidenceEnvelope {
	return &api.EvidenceEnvelope{
		SchemaVersion: "v1",
		TransactionID: txn.ID,
		RuleID:        txn.RuleID,
		HostID:        txn.HostID,
		FleetID:       txn.FleetID,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
		Decision:      api.StatusErrored,
		Severity:      txn.Severity,
		FrameworkRefs: txn.FrameworkRefs,
		// Empty (non-nil) signature is the unsigned-errored sentinel: it
		// persists into the NOT-NULL envelope_sig column (a nil would violate
		// it and drop the errored row from the audit log), and it tells
		// verification tooling this row was never signed.
		Signature: []byte{},
	}
}
