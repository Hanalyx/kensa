package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
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
//
// @spec engine-event-bus
// @ac AC-01
func TestPublishDeliversToMatchingSubscriber(t *testing.T) {
	t.Run("engine-event-bus/AC-01", func(t *testing.T) {})
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
//
// @spec engine-event-bus
// @ac AC-02
func TestPublishDoesNotDeliverToNonMatchingSubscriber(t *testing.T) {
	t.Run("engine-event-bus/AC-02", func(t *testing.T) {})
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
//
// @spec engine-event-bus
// @ac AC-03
func TestFullChannelDropsEventsWithoutBlocking(t *testing.T) {
	t.Run("engine-event-bus/AC-03", func(t *testing.T) {})
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
//
// @spec engine-event-bus
// @ac AC-04
func TestSubscriberChannelClosesOnContextCancel(t *testing.T) {
	t.Run("engine-event-bus/AC-04", func(t *testing.T) {})
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
//
// @spec engine-event-bus
// @ac AC-05
func TestMultipleSubscribersEachReceivePublishedEvent(t *testing.T) {
	t.Run("engine-event-bus/AC-05", func(t *testing.T) {})
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
//
// @spec engine-event-bus
// @ac AC-06
func TestPublishAssignsUUIDWhenNil(t *testing.T) {
	t.Run("engine-event-bus/AC-06", func(t *testing.T) {})
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
//
// @spec engine-event-bus
// @ac AC-02
func TestKindFilterDelivers(t *testing.T) {
	t.Run("engine-event-bus/AC-02", func(t *testing.T) {})
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

// TestPublishConcurrentWithCancelNeverPanics is the regression guard for the
// send-on-closed-channel race: Publish must never send to a subscriber whose
// channel was closed by a concurrent context cancellation. Before the fix,
// Publish snapshotted subscribers under the read lock, released it, then sent
// — so a cancel firing between the snapshot and the send closed the channel
// and the send panicked. This test publishes in a tight loop while a churn of
// short-lived subscriptions is repeatedly created and canceled; with the bug
// present it panics within a few iterations, with the fix it completes
// cleanly. Run under `-race` it also flags the underlying data race.
//
// @spec engine-event-bus
// @ac AC-07
func TestPublishConcurrentWithCancelNeverPanics(t *testing.T) {
	t.Run("engine-event-bus/AC-07", func(t *testing.T) {})

	bus := NewInMemoryEventBus()
	const iterations = 2000

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Publisher: hammer Publish for the whole test.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ev := makeEvent(api.Committed, "host-race")
		for {
			select {
			case <-stop:
				return
			default:
				// A panic here (send on closed channel) fails the test by
				// crashing the process — which is exactly the regression we
				// guard against.
				_ = bus.Publish(context.Background(), ev)
			}
		}
	}()

	// Churn: create and cancel subscriptions as fast as possible so a cancel
	// (which removes the sub and closes its channel) is constantly racing the
	// publisher's delivery loop.
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		ch, err := bus.Subscribe(ctx, api.EventFilter{HostIDs: []string{"host-race"}})
		if err != nil {
			cancel()
			t.Fatalf("Subscribe: %v", err)
		}
		// Drain whatever is buffered, then cancel to trigger the close that
		// races the in-flight Publish.
		select {
		case <-ch:
		default:
		}
		cancel()
	}

	close(stop)
	wg.Wait()
}
