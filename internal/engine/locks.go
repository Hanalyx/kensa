package engine

import (
	"sync"

	"github.com/Hanalyx/kensa/api"
)

// hostLocks owns the per-host mutexes that satisfy engine-transaction
// spec C-05: concurrent invocations against the same host serialize;
// concurrent invocations against different hosts proceed in parallel.
type hostLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newHostLocks() *hostLocks {
	return &hostLocks{locks: make(map[string]*sync.Mutex)}
}

// acquire returns a release function for hostID's mutex. When
// nonBlocking is true and the mutex is held, acquire returns
// [api.ErrHostBusy] instead of waiting.
func (h *hostLocks) acquire(hostID string, nonBlocking bool) (release func(), err error) {
	mu := h.mutexFor(hostID)
	if nonBlocking {
		if !mu.TryLock() {
			return nil, api.ErrHostBusy
		}
	} else {
		mu.Lock()
	}
	return mu.Unlock, nil
}

// mutexFor returns the (possibly newly created) mutex for hostID.
func (h *hostLocks) mutexFor(hostID string) *sync.Mutex {
	h.mu.Lock()
	defer h.mu.Unlock()
	mu, ok := h.locks[hostID]
	if !ok {
		mu = &sync.Mutex{}
		h.locks[hostID] = mu
	}
	return mu
}
