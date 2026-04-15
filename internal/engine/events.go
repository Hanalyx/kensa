package engine

import (
	"context"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// publish sends event to the configured [EventBus]. Errors are
// swallowed deliberately: the event stream must not stall the engine
// (engine-transaction priority over OPENWATCH_VISION.md heartbeat).
func (e *Engine) publish(ctx context.Context, event api.Event) {
	var publisher api.EventPublisher = e.events
	_ = publisher.Publish(ctx, event)
}

// publishStarted emits the [api.TransactionStarted] event at the top
// of the run loop.
func (e *Engine) publishStarted(ctx context.Context, txn *api.Transaction) {
	e.publish(ctx, api.Event{
		Kind:      api.TransactionStarted,
		TxnID:     &txn.ID,
		HostID:    txn.HostID,
		Timestamp: time.Now().UTC(),
	})
}

// publishPhaseCompleted emits the [api.PhaseCompleted] event at each
// phase boundary.
func (e *Engine) publishPhaseCompleted(ctx context.Context, txn *api.Transaction, phase api.Phase, success bool, sinceStart time.Duration) {
	e.publish(ctx, api.Event{
		Kind:      api.PhaseCompleted,
		TxnID:     &txn.ID,
		HostID:    txn.HostID,
		Timestamp: time.Now().UTC(),
		Data: api.PhaseCompletedData{
			Phase:    phase,
			Success:  success,
			Duration: sinceStart,
		},
	})
}
