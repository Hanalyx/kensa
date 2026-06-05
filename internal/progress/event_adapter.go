package progress

import "github.com/Hanalyx/kensa/api"

// FromEvent translates one engine-emitted [api.Event] into the single
// source-agnostic [Update] the renderer consumes. It is the engine adapter's
// pure core: the remediate path subscribes to the lossy event bus and feeds
// each received event through FromEvent, rendering the resulting Update.
//
// FromEvent is pure — no I/O, no goroutines, no shared state — so every
// mapping is unit-testable without a live engine. It returns (Update, true)
// for the four transaction-scoped kinds the engine emits during a remediation,
// and (zero Update, false) for every other kind (the OpenWatch-owned
// heartbeat/drift kinds and the deadman kinds), which the renderer skips.
//
// The mapping uses the additive RuleID carried on the transaction payloads
// (api PR1):
//
//   - TransactionStarted -> [TxnStarted], RuleID from [api.TransactionStartedData].
//   - PhaseCompleted     -> [TxnPhase], RuleID + Phase + Success->OK from
//     [api.PhaseCompletedData].
//   - RolledBack         -> [TxnDone] with OK=false, RuleID from
//     [api.RolledBackData], Detail "rolled back".
//   - Committed          -> [TxnDone] with OK=true. Committed carries no Data
//     payload, so the Update's RuleID is empty — acceptable, because the
//     preceding TxnStarted/TxnPhase lines already named the rule.
//
// A type assertion on Event.Data uses the comma-ok form so a nil or
// mismatched Data never panics; the Update simply carries no RuleID in that
// (not-expected-in-practice) case. Display must never crash the run.
func FromEvent(ev api.Event) (Update, bool) {
	u := Update{Host: ev.HostID}
	switch ev.Kind {
	case api.TransactionStarted:
		u.Kind = TxnStarted
		if d, ok := ev.Data.(api.TransactionStartedData); ok {
			u.RuleID = d.RuleID
		}
		return u, true
	case api.PhaseCompleted:
		u.Kind = TxnPhase
		if d, ok := ev.Data.(api.PhaseCompletedData); ok {
			u.RuleID = d.RuleID
			u.Phase = d.Phase
			u.OK = d.Success
		}
		return u, true
	case api.RolledBack:
		u.Kind = TxnDone
		u.OK = false
		u.Detail = "rolled back"
		if d, ok := ev.Data.(api.RolledBackData); ok {
			u.RuleID = d.RuleID
		}
		return u, true
	case api.Committed:
		u.Kind = TxnDone
		u.OK = true
		return u, true
	default:
		// Heartbeat/drift (OpenWatch-owned) and deadman kinds are not part
		// of the remediate progress stream; skip them.
		return Update{}, false
	}
}
