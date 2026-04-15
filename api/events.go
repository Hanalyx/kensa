package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// EventKind enumerates every event type the engine emits. Subscribers
// filter by passing specific kinds in [EventFilter.Kinds].
type EventKind string

// The full set of [EventKind] values the engine emits.
const (
	// TransactionStarted fires when the engine enters [PhaseCapture]
	// for a new transaction. [Event.TxnID] is set.
	TransactionStarted EventKind = "transaction_started"

	// PhaseCompleted fires after each transaction phase finishes.
	// [Event.Data] is a [PhaseCompletedData] with the phase and
	// success flag.
	PhaseCompleted EventKind = "phase_completed"

	// Committed fires when a transaction reaches [StatusCommitted].
	Committed EventKind = "committed"

	// RolledBack fires when a transaction reaches [StatusRolledBack].
	// [Event.Data] is a [RolledBackData] identifying which rollback
	// path executed (inline, deadman, or manual).
	RolledBack EventKind = "rolled_back"

	// DriftDetected fires when a scheduled scan finds a rule's check
	// failing on a host where it previously passed.
	DriftDetected EventKind = "drift_detected"

	// HeartbeatPulse is the periodic "this host is reachable" signal.
	// Pulse rate is governed by [EventFilter.HeartbeatInterval].
	HeartbeatPulse EventKind = "heartbeat_pulse"

	// DeadmanTimerArmed fires when the engine schedules a rollback
	// script before applying a control-channel-affecting change.
	// [Event.Data] is a [DeadmanTimerData] with the fire time and
	// script path.
	DeadmanTimerArmed EventKind = "deadman_timer_armed"

	// DeadmanTimerFired fires when the scheduled deadman script runs
	// because validate did not complete within the timer window. The
	// transaction's terminal status (typically [StatusRolledBack])
	// follows.
	DeadmanTimerFired EventKind = "deadman_timer_fired"
)

// EventPublisher is the write side of the event stream. The engine
// publishes through it as transactions progress; consumers should not
// implement this interface directly.
type EventPublisher interface {
	// Publish delivers event to every matching subscriber. Returns
	// an error if the underlying transport rejected the event;
	// back-pressure is not surfaced here (see [EventSubscriber]).
	Publish(ctx context.Context, event Event) error
}

// EventSubscriber is the read side of the event stream. OpenWatch's
// Heartbeat (see docs/OPENWATCH_VISION.md §3.2) subscribes to drive
// real-time drift alerts, progress indicators, and the fleet-health
// view.
type EventSubscriber interface {
	// Subscribe returns a channel that receives events matching
	// filter. The channel closes when ctx is done.
	//
	// Back-pressure: when the consumer falls behind, non-pulse
	// events may be dropped and counted; [HeartbeatPulse] events
	// are coalesced rather than dropped, so subscribers always see
	// at least one pulse per host per [EventFilter.HeartbeatInterval]
	// while the host is alive.
	Subscribe(ctx context.Context, filter EventFilter) (<-chan Event, error)
}

// Event is one entry on the event stream.
type Event struct {
	// ID is the unique event identifier.
	ID uuid.UUID
	// Kind classifies the event; see [EventKind].
	Kind EventKind
	// TxnID is the source [Transaction.ID] for transaction-scoped
	// events; nil for fleet-level events such as [HeartbeatPulse].
	TxnID *uuid.UUID
	// HostID identifies the host the event concerns.
	HostID string
	// Timestamp is when the engine emitted the event.
	Timestamp time.Time
	// Data is a kind-specific payload. See the per-kind comments on
	// [EventKind] for the concrete type.
	Data interface{}
}

// EventFilter selects which events the subscriber receives. An empty
// [EventFilter.Kinds] list means "all kinds"; a non-empty list returns
// only those kinds. So a subscriber wanting only [DeadmanTimerFired]
// passes EventFilter{Kinds: []EventKind{DeadmanTimerFired}} and
// receives nothing else.
type EventFilter struct {
	Kinds    []EventKind
	HostIDs  []string
	FleetIDs []string
	// HeartbeatInterval caps the per-host pulse delivery rate. The
	// engine may emit pulses more frequently internally; the
	// subscription delivers at most one pulse per host per interval.
	// The zero value means 60 seconds.
	HeartbeatInterval time.Duration
}

// PhaseCompletedData is the [Event.Data] payload for a
// [PhaseCompleted] event.
type PhaseCompletedData struct {
	// Phase identifies which phase completed.
	Phase Phase
	// Success is true if the phase reached its normal terminal state.
	Success bool
	// Duration is the wall-clock time the phase took.
	Duration time.Duration
}

// RolledBackData is the [Event.Data] payload for a [RolledBack] event.
type RolledBackData struct {
	// Source identifies which rollback path executed: "inline",
	// "deadman", or "manual".
	Source string
	// Reason is a human-readable summary of why rollback fired.
	Reason string
}

// DeadmanTimerData is the [Event.Data] payload for both
// [DeadmanTimerArmed] and [DeadmanTimerFired].
type DeadmanTimerData struct {
	// FiresAt is the absolute time the scheduled script will (or did)
	// run on the host.
	FiresAt time.Time
	// ScriptPath is the path of the rollback script on the host.
	ScriptPath string
}
