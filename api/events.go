package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// EventKind enumerates every event type the engine emits. Consumers
// filter by passing specific kinds in EventFilter.Kinds.
type EventKind string

const (
	// TransactionStarted: engine enters CAPTURE phase for a transaction.
	TransactionStarted EventKind = "transaction_started"

	// PhaseCompleted: engine finished a phase. Event.Data is of type
	// PhaseCompletedData with Phase and Success fields.
	PhaseCompleted EventKind = "phase_completed"

	// Committed: transaction reached StatusCommitted.
	Committed EventKind = "committed"

	// RolledBack: transaction reached StatusRolledBack. Event.Data is
	// of type RolledBackData with RollbackSource ("inline"|"deadman"|"manual").
	RolledBack EventKind = "rolled_back"

	// DriftDetected: a scheduled scan found a rule's check failing on
	// a host where it previously passed.
	DriftDetected EventKind = "drift_detected"

	// HeartbeatPulse: periodic "this host is reachable" signal. Rate
	// controlled by EventFilter.HeartbeatInterval.
	HeartbeatPulse EventKind = "heartbeat_pulse"

	// DeadmanTimerArmed: engine armed a deadman timer before a
	// control-channel-affecting change. Event.Data is of type
	// DeadmanTimerData with FiresAt and ScriptPath fields.
	DeadmanTimerArmed EventKind = "deadman_timer_armed"

	// DeadmanTimerFired: the scheduled deadman script executed because
	// validate did not complete in time. Transaction outcome follows
	// via RolledBack or errored flows.
	DeadmanTimerFired EventKind = "deadman_timer_fired"
)

// EventPublisher is the write-side of the event stream. The engine
// publishes to it as transactions progress.
type EventPublisher interface {
	Publish(ctx context.Context, event Event) error
}

// EventSubscriber is the read-side. OpenWatch's Heartbeat
// (OPENWATCH_VISION.md §3.2) subscribes to drive real-time drift alerts,
// progress indicators, and fleet health views.
type EventSubscriber interface {
	// Subscribe returns a channel that receives events matching filter.
	// The channel closes when ctx is done. Back-pressure is handled by
	// the implementation: non-pulse events may be dropped and counted
	// when the consumer can't keep up; HeartbeatPulse is coalesced
	// (never dropped).
	Subscribe(ctx context.Context, filter EventFilter) (<-chan Event, error)
}

// Event is the unit of the event stream.
type Event struct {
	ID        uuid.UUID
	Kind      EventKind
	TxnID     *uuid.UUID // Nil for fleet-level events (HeartbeatPulse)
	HostID    string
	Timestamp time.Time
	Data      interface{} // Kind-specific payload
}

// EventFilter selects which events the subscriber receives. Empty Kinds
// means "all kinds"; a specific Kinds list returns ONLY those kinds — so
// a subscriber wanting only DeadmanTimerFired passes
// []EventKind{DeadmanTimerFired} and receives nothing else.
type EventFilter struct {
	Kinds    []EventKind
	HostIDs  []string
	FleetIDs []string

	// HeartbeatInterval caps the per-host pulse delivery rate. The engine
	// may emit pulses more frequently internally; the subscription
	// delivers at most one pulse per host per interval. Zero value means
	// 60 seconds.
	HeartbeatInterval time.Duration
}

// ─── Kind-specific Event.Data payloads ──────────────────────────────────

// PhaseCompletedData is the payload of a PhaseCompleted event.
type PhaseCompletedData struct {
	Phase    Phase
	Success  bool
	Duration time.Duration
}

// RolledBackData is the payload of a RolledBack event.
type RolledBackData struct {
	RollbackSource string // "inline" | "deadman" | "manual"
	Reason         string
}

// DeadmanTimerData is the payload of DeadmanTimerArmed / DeadmanTimerFired.
type DeadmanTimerData struct {
	FiresAt    time.Time
	ScriptPath string
}
