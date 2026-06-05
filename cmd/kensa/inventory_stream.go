package main

import (
	"sync"

	"github.com/Hanalyx/kensa/internal/progress"
)

// hostStampSink wraps a progress.Sink and stamps a fixed host addr onto every
// Update before forwarding. The single-host scan runner emits Updates with an
// empty Host field; in inventory mode each per-host worker wraps the merge sink
// in a hostStampSink carrying that worker's inventory addr, so the merged stream
// is attributed without the runner ever knowing which host it serves (spec
// cli-inventory-stream C-01/C-02). The CLI knows the addr — it came from the
// parsed inventory entry — so attribution lives at the CLI seam, not the runner.
type hostStampSink struct {
	host string
	out  progress.Sink
}

// Update stamps s.host onto u (overriding whatever Host the upstream set) and
// forwards it. Delivery is nil-safe by convention: a nil downstream is a no-op
// via progress.Emit.
func (s hostStampSink) Update(u progress.Update) {
	u.Host = s.host
	progress.Emit(s.out, u)
}

// chanSink forwards every Update onto a channel. It is the producer side of the
// inventory fan-in: each per-host worker sends through one of these (wrapped in
// a hostStampSink) and never touches the stderr writer itself (spec
// cli-inventory-stream C-01). A send blocks only until the single renderer
// goroutine ranges the next value off, so the merge is lossless (unlike the
// lossy 64-slot engine bus) and naturally back-pressures a slow terminal.
type chanSink struct {
	ch chan<- progress.Update
}

// Update sends u onto the channel. The renderer goroutine ranges the channel to
// close, so this blocks only momentarily under normal operation.
func (s chanSink) Update(u progress.Update) {
	s.ch <- u
}

// inventoryMerge is the fan-in that turns N concurrent per-host progress streams
// into one host-prefixed render on a single stderr consumer. The topology is the
// textbook merge mandated by the streaming plan (spec cli-inventory-stream):
//
//   - ONE channel of progress.Update (ch) shared by all workers.
//   - A producer WaitGroup (wg) counting live workers; each worker calls
//     workerSink(addr) to get its own host-stamping sink and (when done)
//     workerDone() exactly once.
//   - ONE closer goroutine that wg.Wait()s then close(ch) — exactly once, after
//     the last worker's last send (C-03: no send-on-closed-channel panic).
//   - ONE renderer goroutine that ranges ch to close, delivering each Update to
//     the single text consumer on stderr (C-04: one renderer, one writer, no
//     per-write lock — the channel is the synchronization point).
//
// Workers NEVER write to the consumer directly; they only send Updates onto the
// channel through their host-stamping sink. wait() blocks until the merge has
// fully drained (workers done -> channel closed -> renderer finished), so the
// caller can render the canonical stdout result docs afterward with no
// interleave (C-05).
type inventoryMerge struct {
	ch       chan progress.Update
	wg       sync.WaitGroup
	consumer progress.Sink
	closed   chan struct{} // signaled when the renderer goroutine exits
}

// newInventoryMerge starts the closer and renderer goroutines and returns a
// running merge that fans per-worker Updates into consumer.
//
// The producer WaitGroup is seeded with ONE "dispatch guard" up front, before
// the closer goroutine starts. This is the correctness crux. Workers register
// lazily (each workerSink does wg.Add(1)), because the fan-out may dispatch
// FEWER than the host count if ctx is canceled mid-loop — pre-seeding by host
// count would then deadlock on workers that never spawn. But a purely lazy
// wg.Add risks the closer's wg.Wait() observing a transient zero between two
// registrations and closing the channel while a later worker still holds a
// chanSink (send-on-closed-channel panic). The dispatch guard prevents that: the
// WaitGroup cannot reach zero until the caller calls dispatchDone() AFTER the
// fan-out loop has registered every worker it is going to. So wg.Wait() blocks
// until (all spawned workers done) AND (dispatch finished) — closing the channel
// strictly after the last possible send (spec cli-inventory-stream C-03).
//
// consumer is the single text StreamConsumer the CLI points at stderr; it is
// touched only by the lone renderer goroutine (C-04). The buffered channel
// smooths bursts but does not change correctness — the merge is lossless
// regardless of buffer size.
func newInventoryMerge(consumer progress.Sink) *inventoryMerge {
	m := &inventoryMerge{
		ch:       make(chan progress.Update, 64),
		consumer: consumer,
		closed:   make(chan struct{}),
	}
	m.wg.Add(1) // dispatch guard; released by dispatchDone()
	// Renderer: the ONLY goroutine that touches consumer. Ranges to close.
	go func() {
		defer close(m.closed)
		for u := range m.ch {
			progress.Emit(m.consumer, u)
		}
	}()
	// Closer: the ONLY goroutine that closes ch, and only after every worker
	// has finished sending AND dispatch is done (wg.Wait()). This is what makes
	// the workers' sends safe — the channel is closed strictly after the last
	// send.
	go func() {
		m.wg.Wait()
		close(m.ch)
	}()
	return m
}

// workerSink registers one producer and returns its host-stamping sink: Updates
// it forwards are stamped with addr and sent on the merge channel. The caller
// MUST invoke the returned done func exactly once when that worker has sent its
// last Update — it decrements the producer WaitGroup. done is idempotent
// (sync.Once) so a defensive double-call from a cleanup path cannot drive the
// WaitGroup negative. workerSink MUST be called before dispatchDone() (the
// dispatch guard keeps wg.Wait() from completing until then).
func (m *inventoryMerge) workerSink(addr string) (progress.Sink, func()) {
	m.wg.Add(1)
	var once sync.Once
	done := func() { once.Do(m.wg.Done) }
	return hostStampSink{host: addr, out: chanSink{ch: m.ch}}, done
}

// dispatchDone releases the dispatch guard, signaling that the fan-out loop has
// registered every worker it will. It MUST be called exactly once, after the
// fan-out returns (every workerSink has been called). Until it is called the
// closer's wg.Wait() cannot complete, so the channel cannot close mid-dispatch.
func (m *inventoryMerge) dispatchDone() {
	m.wg.Done()
}

// wait blocks until the merge has fully drained: the closer has closed the
// channel (all workers done + dispatch done) and the renderer goroutine has
// finished delivering every buffered Update. After wait returns it is safe to
// render the canonical stdout result docs — the progress stream has fully
// flushed (spec cli-inventory-stream C-04/C-05).
func (m *inventoryMerge) wait() {
	<-m.closed
}
