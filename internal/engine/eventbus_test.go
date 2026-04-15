package engine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
)

func makeEvent(kind api.EventKind, hostID string) api.Event {
	return api.Event{
		ID:        uuid.New(),
		Kind:      kind,
		HostID:    hostID,
		Timestamp: time.Now().UTC(),
	}
}

// TestPublishDeliversToMatchingSubscriber verifies that a published event
// reaches a subscriber whose filter matches.
func TestPublishDeliversToMatchingSubscriber(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := NewInMemoryEventBus()
	ch, err := bus.Subscribe(ctx, api.EventFilter{
		HostIDs: []string{"host-a"},
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	ev := makeEvent(api.Committed, "host-a")
	if err := bus.Publish(ctx, ev); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-ch:
		if got.HostID != ev.HostID {
			t.Errorf("expected HostID %q, got %q", ev.HostID, got.HostID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for event")
	}
}

// TestPublishDoesNotDeliverToNonMatchingSubscriber verifies that an event
// for a different host is not delivered to a subscriber filtered on another
// host.
func TestPublishDoesNotDeliverToNonMatchingSubscriber(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := NewInMemoryEventBus()
	ch, err := bus.Subscribe(ctx, api.EventFilter{
		HostIDs: []string{"host-b"},
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	ev := makeEvent(api.Committed, "host-a")
	if err := bus.Publish(ctx, ev); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-ch:
		t.Errorf("received unexpected event: %v", got)
	case <-time.After(100 * time.Millisecond):
		// Correct: no event delivered.
	}
}

// TestFullChannelDropsEventsWithoutBlocking verifies that publishing to a
// subscriber with a full channel does not block.
func TestFullChannelDropsEventsWithoutBlocking(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	bus := NewInMemoryEventBus()
	ch, err := bus.Subscribe(ctx, api.EventFilter{})
	if err != nil {
		cancel()
		t.Fatalf("Subscribe: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Publish more events than the buffer can hold.
		for i := 0; i < subscriptionBufSize+10; i++ {
			ev := makeEvent(api.Committed, "host-x")
			if pubErr := bus.Publish(ctx, ev); pubErr != nil {
				return
			}
		}
	}()

	select {
	case <-done:
		// All publishes returned without blocking.
	case <-time.After(2 * time.Second):
		cancel()
		t.Error("Publish blocked — channel full events not being dropped")
		return
	}

	// Cancel to close the subscription channel, then drain.
	cancel()
	for range ch {
	}
}

// TestSubscriberChannelClosesOnContextCancel verifies that canceling the
// subscriber context causes the channel to close.
func TestSubscriberChannelClosesOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	bus := NewInMemoryEventBus()
	ch, err := bus.Subscribe(ctx, api.EventFilter{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to be closed, but received an event")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for channel to close after context cancellation")
	}
}

// TestMultipleSubscribersEachReceivePublishedEvent verifies fan-out: every
// active subscriber gets a copy of each published event.
func TestMultipleSubscribersEachReceivePublishedEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := NewInMemoryEventBus()
	const n = 5
	channels := make([]<-chan api.Event, n)
	for i := 0; i < n; i++ {
		ch, err := bus.Subscribe(ctx, api.EventFilter{})
		if err != nil {
			t.Fatalf("Subscribe %d: %v", i, err)
		}
		channels[i] = ch
	}

	ev := makeEvent(api.Committed, "host-z")
	if err := bus.Publish(ctx, ev); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	for i, ch := range channels {
		select {
		case got := <-ch:
			if got.ID != ev.ID {
				t.Errorf("subscriber %d: got event ID %v, want %v", i, got.ID, ev.ID)
			}
		case <-time.After(500 * time.Millisecond):
			t.Errorf("subscriber %d: timed out waiting for event", i)
		}
	}
}

// TestPublishAssignsUUIDWhenNil verifies that a nil event ID is replaced
// with a fresh uuid before delivery.
func TestPublishAssignsUUIDWhenNil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := NewInMemoryEventBus()
	ch, err := bus.Subscribe(ctx, api.EventFilter{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	ev := api.Event{
		Kind:      api.Committed,
		HostID:    "host-q",
		Timestamp: time.Now().UTC(),
		// ID is uuid.Nil intentionally.
	}
	if err := bus.Publish(ctx, ev); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-ch:
		if got.ID == uuid.Nil {
			t.Error("expected non-nil event ID after publish, got uuid.Nil")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for event")
	}
}

// TestKindFilterDelivers verifies that kind-filtered subscriptions only
// receive matching event kinds.
func TestKindFilterDelivers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bus := NewInMemoryEventBus()
	ch, err := bus.Subscribe(ctx, api.EventFilter{
		Kinds: []api.EventKind{api.Committed},
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Publish a non-matching event first.
	_ = bus.Publish(ctx, makeEvent(api.RolledBack, "host-r"))
	// Then a matching one.
	match := makeEvent(api.Committed, "host-r")
	_ = bus.Publish(ctx, match)

	select {
	case got := <-ch:
		if got.Kind != api.Committed {
			t.Errorf("expected kind %q, got %q", api.Committed, got.Kind)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for matching event")
	}

	// No second event should arrive.
	select {
	case got := <-ch:
		t.Errorf("unexpected second event: %v", got)
	case <-time.After(50 * time.Millisecond):
	}
}
