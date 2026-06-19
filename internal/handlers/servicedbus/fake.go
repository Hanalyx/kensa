package servicedbus

import (
	"context"
	"io/fs"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/systemd"
)

// FakeTransport is a test double implementing BOTH api.Transport and
// systemd.Transport, for exercising the service handlers' D-Bus path
// (and its shell fallback) without a real helper or systemd. Tests stuff
// canned per-op responses/errors into Resp/Err (keyed by op name:
// "enable", "disable", "mask", "unmask", "start", "stop", "unit-state")
// and assert on the ordered Calls log. An op with no entry succeeds with
// an empty Response. Lives in the production package (a normal file, not
// _test.go) so all three handler test packages can share it, mirroring
// engine.NewFakeTransport.
type FakeTransport struct {
	Resp  map[string]*systemd.Response
	Err   map[string]error
	Calls []string

	// Shell side (api.Transport). Populated only when a test exercises
	// the fallback path; the D-Bus path never calls Run.
	RunResults map[string]*api.CommandResult
	Runs       []string
}

// NewFake returns a FakeTransport with initialized maps.
func NewFake() *FakeTransport {
	return &FakeTransport{
		Resp:       map[string]*systemd.Response{},
		Err:        map[string]error{},
		RunResults: map[string]*api.CommandResult{},
	}
}

func (f *FakeTransport) op(name string) (*systemd.Response, error) {
	f.Calls = append(f.Calls, name)
	if err, ok := f.Err[name]; ok {
		// Return the canned response alongside the error so HelperError
		// cases mirror Client.invoke (which returns resp + *HelperError).
		return f.Resp[name], err
	}
	if r, ok := f.Resp[name]; ok {
		return r, nil
	}
	return &systemd.Response{Success: true, Op: name}, nil
}

// systemd.Transport methods.

func (f *FakeTransport) Enable(_ context.Context, _ string) (*systemd.Response, error) {
	return f.op("enable")
}
func (f *FakeTransport) Disable(_ context.Context, _ string) (*systemd.Response, error) {
	return f.op("disable")
}
func (f *FakeTransport) Mask(_ context.Context, _ string) (*systemd.Response, error) {
	return f.op("mask")
}
func (f *FakeTransport) Unmask(_ context.Context, _ string) (*systemd.Response, error) {
	return f.op("unmask")
}
func (f *FakeTransport) Start(_ context.Context, _ string) (*systemd.Response, error) {
	return f.op("start")
}
func (f *FakeTransport) Stop(_ context.Context, _ string) (*systemd.Response, error) {
	return f.op("stop")
}
func (f *FakeTransport) UnitState(_ context.Context, _ string) (*systemd.Response, error) {
	return f.op("unit-state")
}

// api.Transport methods (shell-fallback side).

func (f *FakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	f.Runs = append(f.Runs, cmd)
	if r, ok := f.RunResults[cmd]; ok {
		return r, nil
	}
	return &api.CommandResult{ExitCode: 0}, nil
}
func (f *FakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (f *FakeTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (f *FakeTransport) ControlChannelSensitive() bool                           { return false }
func (f *FakeTransport) Close() error                                            { return nil }

// Compile-time assertions that the fake satisfies both interfaces.
var (
	_ api.Transport     = (*FakeTransport)(nil)
	_ systemd.Transport = (*FakeTransport)(nil)
)
