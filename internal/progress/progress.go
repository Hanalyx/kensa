// Package progress defines the source-agnostic display model for the kensa
// CLI's live-progress streaming. Every progress source — the synchronous
// scan/detect path and the engine-backed remediate path that drains the api
// event bus — adapts into a single internal type, [Update], delivered to a
// [Sink]. The CLI renderer consumes only [Update], so it is decoupled from
// where the progress came from.
//
// This package is pure types: it defines the [Kind] enumeration, the [Update]
// struct, and the [Sink] interface. It has no behavior of its own (emission
// lives in the scan/detect/engine adapters; rendering lives in the renderer)
// and depends only on api for the reused [api.Phase] vocabulary — never on the
// lossy event bus.
package progress

import "github.com/Hanalyx/kensa/api"

// Kind classifies a progress [Update] by the milestone it reports. It is a
// display-only taxonomy distinct from api.EventKind: it spans the non-engine
// scan/detect milestones (ScanStart, RuleChecked, ProbeDone, ScanEnd) as well
// as the engine-backed transaction milestones (TxnStarted, TxnPhase, TxnDone).
type Kind int

// The progress milestones. The zero value is intentionally not a valid
// milestone so an unset Update.Kind is detectable.
const (
	// KindUnset is the zero value; not a valid milestone.
	KindUnset Kind = iota
	// ScanStart reports that a multi-rule scan is beginning.
	ScanStart
	// RuleChecked reports that one rule's check completed (Index/Total
	// give progress within the scan; OK is the check outcome).
	RuleChecked
	// ProbeDone reports that one capability probe completed.
	ProbeDone
	// TxnStarted reports that a transaction entered its capture phase.
	TxnStarted
	// TxnPhase reports that a transaction phase completed (Phase names it;
	// OK is the phase success flag).
	TxnPhase
	// TxnDone reports that a transaction reached a terminal status.
	TxnDone
	// ScanEnd reports that a multi-rule scan has finished.
	ScanEnd
)

// Update is the single source-agnostic unit the CLI renderer consumes. Each
// progress source fills the fields relevant to its [Kind]; unused fields stay
// at their zero value.
type Update struct {
	// Host is the host the update concerns (the SSH addr the CLI knows).
	Host string
	// Kind classifies the milestone; see [Kind].
	Kind Kind
	// RuleID is the canonical rule id when the update is per-rule
	// (RuleChecked, TxnStarted, TxnPhase, TxnDone); empty otherwise.
	RuleID string
	// Index is the 1-based position of this item within Total (e.g. the
	// nth rule of a scan, or the nth probe).
	Index int
	// Total is the total count the Index runs within.
	Total int
	// OK is the boolean outcome for milestones that have one (a passing
	// check, a successful phase).
	OK bool
	// Detail is an optional human-readable note (a refusal reason, a probe
	// name, an error summary).
	Detail string
	// Phase identifies the transaction phase for TxnPhase updates; the
	// zero value otherwise. Reuses the api phase vocabulary.
	Phase api.Phase
}

// Sink receives progress [Update]s. The non-engine scan/detect path calls
// Update synchronously per rule/probe (lossless); the engine adapter drains
// the api event bus and translates each event into an Update.
//
// A nil Sink is valid by convention and means "no progress wanted": callers
// route delivery through [Emit], which treats a nil Sink as a no-op.
type Sink interface {
	// Update delivers one progress update. Implementations MUST NOT block
	// the caller for long — progress is cosmetic and on the hot path.
	Update(Update)
}

// Emit delivers u to sink, treating a nil sink as a no-op. It is the
// nil-safe-by-convention path every source uses so each call site need not
// nil-check the Sink.
func Emit(sink Sink, u Update) {
	if sink == nil {
		return
	}
	sink.Update(u)
}
