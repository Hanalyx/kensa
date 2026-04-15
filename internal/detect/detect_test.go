package detect

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// fakeTransport is a test double for [api.Transport] that maps exact
// command strings to [api.CommandResult] values. Commands not present
// in the map return exit code 1 by default.
type fakeTransport struct {
	// results maps a command string to the exit code to return.
	results map[string]int
	// errOn maps a command string to a transport-level error.
	errOn map[string]error
}

func (f *fakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	if err, ok := f.errOn[cmd]; ok {
		return nil, err
	}
	code := 1
	if c, ok := f.results[cmd]; ok {
		code = c
	}
	return &api.CommandResult{
		ExitCode: code,
		Duration: time.Millisecond,
	}, nil
}

func (f *fakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (f *fakeTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (f *fakeTransport) ControlChannelSensitive() bool                           { return false }
func (f *fakeTransport) Close() error                                            { return nil }

// allZeroResults builds a results map with exit code 0 for every
// known probe command.
func allZeroResults() map[string]int {
	m := make(map[string]int, len(probes))
	for _, p := range probes {
		m[p.cmd] = 0
	}
	return m
}

// TestDetect_AllPresent verifies that a host returning exit 0 for
// every probe produces a full capability set with all values true.
func TestDetect_AllPresent(t *testing.T) {
	ft := &fakeTransport{results: allZeroResults()}
	caps, err := Detect(context.Background(), ft)
	if err != nil {
		t.Fatalf("Detect returned unexpected error: %v", err)
	}
	for _, p := range probes {
		if !caps[p.name] {
			t.Errorf("expected capability %q to be true, got false", p.name)
		}
	}
}

// TestDetect_OneFalse verifies that a host returning exit 1 for one
// probe has exactly that capability set to false while all others
// remain true.
func TestDetect_OneFalse(t *testing.T) {
	target := probes[0] // sshd_config_d
	results := allZeroResults()
	results[target.cmd] = 1

	ft := &fakeTransport{results: results}
	caps, err := Detect(context.Background(), ft)
	if err != nil {
		t.Fatalf("Detect returned unexpected error: %v", err)
	}
	if caps[target.name] {
		t.Errorf("expected capability %q to be false after exit 1, got true", target.name)
	}
	// All others must still be true.
	for _, p := range probes[1:] {
		if !caps[p.name] {
			t.Errorf("expected capability %q to be true, got false", p.name)
		}
	}
}

// TestDetect_ErrorsAreSuppressed verifies that a transport-level error
// on a single probe does not abort the full detection run. The
// erroring capability is marked false; others are still evaluated.
func TestDetect_ErrorsAreSuppressed(t *testing.T) {
	target := probes[1]    // authselect
	errTarget := probes[2] // crypto_policies — will return a transport error

	results := allZeroResults()
	results[target.cmd] = 1 // explicit false via exit code

	ft := &fakeTransport{
		results: results,
		errOn: map[string]error{
			errTarget.cmd: context.DeadlineExceeded,
		},
	}

	caps, err := Detect(context.Background(), ft)
	if err != nil {
		t.Fatalf("Detect returned unexpected error even though probe errors should be suppressed: %v", err)
	}
	if caps[target.name] {
		t.Errorf("expected capability %q to be false, got true", target.name)
	}
	if caps[errTarget.name] {
		t.Errorf("expected capability %q to be false after transport error, got true", errTarget.name)
	}
	// Verify that the remaining probes are still evaluated.
	evaluated := 0
	for _, p := range probes {
		if p.name == target.name || p.name == errTarget.name {
			continue
		}
		evaluated++
		if !caps[p.name] {
			t.Errorf("expected capability %q to remain true, got false", p.name)
		}
	}
	if evaluated == 0 {
		t.Error("no remaining probes were checked")
	}
}

// TestDetect_AllAbsent verifies that a host returning exit 1 for
// every probe produces a full capability set with all values false.
func TestDetect_AllAbsent(t *testing.T) {
	ft := &fakeTransport{results: map[string]int{}} // all default to 1
	caps, err := Detect(context.Background(), ft)
	if err != nil {
		t.Fatalf("Detect returned unexpected error: %v", err)
	}
	for _, p := range probes {
		if caps[p.name] {
			t.Errorf("expected capability %q to be false, got true", p.name)
		}
	}
}

// TestDetect_CapabilitySetLength verifies the returned set contains
// exactly one entry per known probe.
func TestDetect_CapabilitySetLength(t *testing.T) {
	ft := &fakeTransport{results: allZeroResults()}
	caps, err := Detect(context.Background(), ft)
	if err != nil {
		t.Fatalf("Detect returned unexpected error: %v", err)
	}
	if len(caps) != len(probes) {
		t.Errorf("expected %d capabilities, got %d", len(probes), len(caps))
	}
}
