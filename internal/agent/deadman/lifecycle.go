package deadman

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/Hanalyx/kensa/internal/agent/ownedexec"
)

// ErrShuttingDown is returned before a losing admission/cancellation changes work.
var ErrShuttingDown = errors.New("agent: shutting_down")

// ErrRecovering refuses mutation while a recovery claim owns the agent.
var ErrRecovering = errors.New("agent: recovery already owns mutation admission")

// ErrHandlerBusy refuses a native Capture/mutation wait-ownership conflict.
var ErrHandlerBusy = errors.New("agent: native Capture/mutation execution is busy")

type capture struct {
	once   sync.Once
	native *ownedexec.NativeStatus
}

type mutation struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// Default is the same Armer used by the existing wire entrypoints.
func Default() *Armer { return defaultArmer }

func (a *Armer) notifyLocked() { close(a.changed); a.changed = make(chan struct{}) }

// Admitting reports whether the dispatcher can accept a new request.
func (a *Armer) Admitting() bool { a.mu.Lock(); defer a.mu.Unlock(); return !a.closed }

// Handling reports an admitted handler that can keep the frame loop busy.
func (a *Armer) Handling() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.mutations) > 0 || len(a.captures) > 0
}

// BeginCapture retains native command waits with the existing Capture caller.
// Its natural context is not canceled by recovery/shutdown. Completion does not
// call the process-wide reaper: the handler's synchronous native waits own it.
func (a *Armer) BeginCapture() (context.Context, func(error), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, nil, ErrShuttingDown
	}
	if a.recovering > 0 {
		return nil, nil, ErrRecovering
	}
	if len(a.mutations) > 0 {
		return nil, nil, ErrHandlerBusy
	}
	ctx, native := ownedexec.NativeContext(context.Background())
	operation := &capture{native: native}
	a.captures[operation] = struct{}{}
	a.notifyLocked()
	return ctx, func(outcome error) {
		operation.once.Do(func() {
			uncertainty := errors.Join(operation.native.Err(), ownedexec.NativeUncertainty(outcome))
			a.mu.Lock()
			if uncertainty != nil {
				a.failures = append(a.failures, uncertainty)
				a.notifyLocked()
				a.mu.Unlock()
				fmt.Fprintln(os.Stderr, "kensa agent: Capture native wait UNRESOLVED; retaining ownership")
				return
			}
			delete(a.captures, operation)
			a.notifyLocked()
			a.mu.Unlock()
		})
	}, nil
}

// BeginMutation owns the handler and its work until its returned join is called.
func (a *Armer) BeginMutation() (context.Context, func(), error) {
	if err := ownedexec.Prepare(); err != nil {
		return nil, nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, nil, ErrShuttingDown
	}
	if a.recovering > 0 {
		return nil, nil, ErrRecovering
	}
	if len(a.captures) > 0 {
		return nil, nil, ErrHandlerBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	operation := &mutation{cancel: cancel, done: make(chan struct{})}
	a.mutations[operation] = struct{}{}
	a.notifyLocked()
	join := func() {
		operation.once.Do(func() {
			// The handler has returned, but an adopted mutating child can still live.
			err := ownedexec.Quiesce()
			cancel()
			a.mu.Lock()
			if err != nil {
				a.failures = append(a.failures, fmt.Errorf("agent: mutation join: %w", err))
			}
			delete(a.mutations, operation)
			close(operation.done)
			a.notifyLocked()
			a.mu.Unlock()
		})
	}
	return ownedexec.Context(ctx), join, nil
}

// Cancel preserves a pre-frontier explicit cancellation and joins its teardown.
// A cancellation after the frontier cannot suppress drain-owned recovery.
func (a *Armer) Cancel(txnID string) (bool, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return false, ErrShuttingDown
	}
	job, exists := a.active[txnID]
	if !exists {
		a.mu.Unlock()
		return false, nil
	}
	job.canceled = true
	a.notifyLocked()
	job.cancel()
	job.wake()
	a.mu.Unlock()
	<-job.done
	return true, nil
}

// StartShutdown closes admission once, preserving every reserved/initializing
// job and admitted handler. Capture finishes naturally; only mutating operation
// contexts are canceled. Neither is the recovery context.
func (a *Armer) StartShutdown(cause error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cause != nil {
		a.failures = append(a.failures, cause)
	}
	a.closed = true
	for operation := range a.mutations {
		operation.cancel()
	}
	for _, job := range a.active {
		job.wake()
	}
	a.notifyLocked()
}

// RecordError retains a terminal protocol/I/O error alongside recovery failures.
func (a *Armer) RecordError(cause error) {
	if cause == nil {
		return
	}
	a.mu.Lock()
	a.failures = append(a.failures, cause)
	a.notifyLocked()
	a.mu.Unlock()
}

// Drain joins actual work and teardown. It deliberately has no abort timer:
// an unconfirmed stop remains an owned unresolved obligation, never exit-0 idle.
func (a *Armer) Drain() error {
	reportedCapture := false
	for {
		a.mu.Lock()
		if !a.closed {
			a.mu.Unlock()
			return errors.New("deadman: drain requires closed admission")
		}
		if len(a.active) == 0 && len(a.mutations) == 0 && len(a.captures) == 0 {
			result := errors.Join(a.failures...)
			a.mu.Unlock()
			return result
		}
		changed := a.changed
		pendingCapture := len(a.captures) > 0
		a.mu.Unlock()
		if pendingCapture && !reportedCapture {
			fmt.Fprintln(os.Stderr, "kensa agent: shutdown waiting for natural Capture completion; UNRESOLVED until joined")
			reportedCapture = true
		}
		<-changed
	}
}
