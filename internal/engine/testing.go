package engine

import (
	"context"
	"io/fs"
	"sync"

	"github.com/Hanalyx/kensa-go/api"
)

// FakeTransport is an in-memory [api.Transport] for engine tests.
// It records commands and returns programmable results so tests can
// drive the engine through every code path without a real host.
type FakeTransport struct {
	mu      sync.Mutex
	Runs    []string
	Results map[string]*api.CommandResult // command → result
	// CCSensitive is returned by [FakeTransport.ControlChannelSensitive].
	CCSensitive bool
	closed      bool
}

// NewFakeTransport returns a transport whose [api.CommandResult] for
// any unmatched command is exit-0 with empty stdout/stderr.
func NewFakeTransport() *FakeTransport {
	return &FakeTransport{Results: make(map[string]*api.CommandResult)}
}

// Run records cmd and returns the programmed result, or a default
// success result if no programming exists for cmd.
func (f *FakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Runs = append(f.Runs, cmd)
	if r, ok := f.Results[cmd]; ok {
		return r, nil
	}
	return &api.CommandResult{ExitCode: 0}, nil
}

// Put is a no-op for tests; returns nil.
func (f *FakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }

// Get is a no-op for tests; returns nil.
func (f *FakeTransport) Get(_ context.Context, _, _ string) error { return nil }

// ControlChannelSensitive returns f.CCSensitive.
func (f *FakeTransport) ControlChannelSensitive() bool { return f.CCSensitive }

// Close marks the transport closed; subsequent Run calls succeed
// (tests may need to inspect Runs after Close).
func (f *FakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// IsClosed reports whether [FakeTransport.Close] was called.
func (f *FakeTransport) IsClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// FakeHandler is a programmable [api.Handler] for engine tests. Every
// behavior — capturable flag, apply outcome, capture outcome, rollback
// outcome — is independently controllable so tests can drive the
// engine through every branch.
type FakeHandler struct {
	HandlerName     string
	IsCapturable    bool
	ApplyErr        error
	ApplyResult     *api.StepResult
	CaptureErr      error
	CapturePreState *api.PreState
	RollbackErr     error
	RollbackResult  *api.RollbackResult

	mu            sync.Mutex
	ApplyCalls    int
	CaptureCalls  int
	RollbackCalls int
}

// Name returns the configured handler name.
func (f *FakeHandler) Name() string { return f.HandlerName }

// Capturable returns the configured capturable flag.
func (f *FakeHandler) Capturable() bool { return f.IsCapturable }

// Apply records the call and returns the configured outcome.
func (f *FakeHandler) Apply(_ context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	f.mu.Lock()
	f.ApplyCalls++
	f.mu.Unlock()
	if f.ApplyErr != nil {
		return nil, f.ApplyErr
	}
	if f.ApplyResult != nil {
		return f.ApplyResult, nil
	}
	return &api.StepResult{Success: true}, nil
}

// Capture records the call and returns the configured outcome. Only
// invoked when IsCapturable is true.
func (f *FakeHandler) Capture(_ context.Context, _ api.Transport, _ api.Params) (*api.PreState, error) {
	f.mu.Lock()
	f.CaptureCalls++
	f.mu.Unlock()
	if f.CaptureErr != nil {
		return nil, f.CaptureErr
	}
	if f.CapturePreState != nil {
		return f.CapturePreState, nil
	}
	return &api.PreState{Data: map[string]interface{}{"fake": true}}, nil
}

// Rollback records the call and returns the configured outcome. Only
// invoked when IsCapturable is true and Apply succeeded.
func (f *FakeHandler) Rollback(_ context.Context, _ api.Transport, _ *api.PreState) (*api.RollbackResult, error) {
	f.mu.Lock()
	f.RollbackCalls++
	f.mu.Unlock()
	if f.RollbackErr != nil {
		return nil, f.RollbackErr
	}
	if f.RollbackResult != nil {
		return f.RollbackResult, nil
	}
	return &api.RollbackResult{Success: true}, nil
}
