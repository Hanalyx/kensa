package engine

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

const subscriptionBufSize = 64

// subscription is one active subscriber registered with [InMemoryEventBus].
type subscription struct {
	filter api.EventFilter
	ch     chan api.Event
}

// matches reports whether event passes the subscription's filter.
func (s *subscription) matches(event api.Event) bool {
	f := s.filter
	if len(f.Kinds) > 0 {
		found := false
		for _, k := range f.Kinds {
			if k == event.Kind {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(f.HostIDs) > 0 {
		found := false
		for _, h := range f.HostIDs {
			if h == event.HostID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(f.FleetIDs) > 0 && event.TxnID != nil {
		// FleetID filtering is best-effort: events do not carry a FleetID
		// directly, so we can only filter when the caller also sets HostIDs.
		// An empty FleetIDs slice means "all fleets", which is the common case.
		_ = f.FleetIDs // accept all when only FleetIDs is set.
	}
	return true
}

// InMemoryEventBus is a thread-safe fan-out event bus. Published events
// are delivered to all matching subscribers. When a subscriber's channel
// is full, the event is dropped rather than blocking the publisher
// (back-pressure per api.EventSubscriber contract).
type InMemoryEventBus struct {
	mu   sync.RWMutex
	subs []*subscription
}

// NewInMemoryEventBus returns a ready-to-use [InMemoryEventBus].
func NewInMemoryEventBus() *InMemoryEventBus {
	return &InMemoryEventBus{}
}

// Publish implements api.EventPublisher. It assigns a random UUID to
// event.ID when event.ID is uuid.Nil, then delivers the event to every
// matching subscriber. If a subscriber's buffer is full the event is
// dropped for that subscriber (non-blocking send).
func (b *InMemoryEventBus) Publish(ctx context.Context, event api.Event) error {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}

	b.mu.RLock()
	subs := make([]*subscription, len(b.subs))
	copy(subs, b.subs)
	b.mu.RUnlock()

	for _, s := range subs {
		if !s.matches(event) {
			continue
		}
		select {
		case s.ch <- event:
		default:
			// Drop — subscriber is full.
		}
	}
	return nil
}

// Subscribe implements api.EventSubscriber. It returns a buffered channel
// that receives events matching filter. The channel is closed when ctx is
// done.
func (b *InMemoryEventBus) Subscribe(ctx context.Context, filter api.EventFilter) (<-chan api.Event, error) {
	sub := &subscription{
		filter: filter,
		ch:     make(chan api.Event, subscriptionBufSize),
	}

	b.mu.Lock()
	b.subs = append(b.subs, sub)
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		for i, s := range b.subs {
			if s == sub {
				b.subs = append(b.subs[:i], b.subs[i+1:]...)
				break
			}
		}
		b.mu.Unlock()
		close(sub.ch)
	}()

	return sub.ch, nil
}

// WithInMemoryEvents returns an [Option] that wires a fresh
// [InMemoryEventBus] into the engine.
func WithInMemoryEvents() Option {
	return WithEvents(NewInMemoryEventBus())
}
