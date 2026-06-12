package kensa

import (
	"context"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// fakeTransport satisfies api.Transport from a command → result map;
// unmapped commands succeed with empty output (probes pass cleanly).
type fakeTransport struct {
	results map[string]api.CommandResult
}

func (f *fakeTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	if r, ok := f.results[cmd]; ok {
		return &r, nil
	}
	return &api.CommandResult{ExitCode: 0}, nil
}
func (f *fakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (f *fakeTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (f *fakeTransport) Close() error                                            { return nil }
func (f *fakeTransport) ControlChannelSensitive() bool                           { return false }

// fakeFactory is a recording api.TransportFactory — the stand-in for
// an embedder's in-memory-credentials SSH stack.
type fakeFactory struct {
	connects atomic.Int64
	results  map[string]api.CommandResult
}

func (f *fakeFactory) Connect(_ context.Context, _ api.HostConfig) (api.Transport, error) {
	f.connects.Add(1)
	return &fakeTransport{results: f.results}, nil
}

// passingSysctl maps the plainRule check to a passing result.
func passingSysctl() map[string]api.CommandResult {
	return map[string]api.CommandResult{
		"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
	}
}

// TestPublicConstruction covers the two public construction paths for
// a caller-supplied TransportFactory.
//
// @spec scan-public-construction
func TestPublicConstruction(t *testing.T) {
	// AC-01: the full public chain — LoadRules → api.New{NewScanner,
	// caller factory} → Scan → Outcomes. No internal/ imports, no
	// engine/store/signer.
	t.Run("scan-public-construction/AC-01", func(t *testing.T) {
		// @spec scan-public-construction
		// @ac AC-01
		rulePath := writeRule(t, t.TempDir(), "r.yml", plainRule)
		rules, err := LoadRules("", []string{rulePath}, nil)
		if err != nil {
			t.Fatalf("LoadRules: %v", err)
		}

		tf := &fakeFactory{results: passingSysctl()}
		k, err := api.New(api.Config{Scanner: NewScanner(), TransportFactory: tf})
		if err != nil {
			t.Fatalf("api.New: %v", err)
		}
		res, err := k.Scan(context.Background(), api.HostConfig{Hostname: "h1"}, rules)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if tf.connects.Load() != 1 {
			t.Errorf("caller factory Connect calls: want 1, got %d", tf.connects.Load())
		}
		if len(res.Outcomes) != 1 || res.Outcomes[0].Status != api.CompliancePass {
			t.Fatalf("want one pass outcome, got %+v", res.Outcomes)
		}
	})

	// AC-02: scan-only — Remediate errors without mutation; concurrent
	// Scans from many goroutines share one backend safely (-race).
	t.Run("scan-public-construction/AC-02", func(t *testing.T) {
		// @spec scan-public-construction
		// @ac AC-02
		rulePath := writeRule(t, t.TempDir(), "r.yml", plainRule)
		rules, err := LoadRules("", []string{rulePath}, nil)
		if err != nil {
			t.Fatalf("LoadRules: %v", err)
		}
		tf := &fakeFactory{results: passingSysctl()}
		k, err := api.New(api.Config{Scanner: NewScanner(), TransportFactory: tf})
		if err != nil {
			t.Fatalf("api.New: %v", err)
		}

		// Remediate dials the transport (api.Kensa connects before
		// delegating) and then errors in the backend's nil-engine
		// guard — before any detect/check/apply command runs. So it
		// contributes one Connect with zero remote commands.
		if _, err := k.Remediate(context.Background(), api.HostConfig{Hostname: "h1"}, rules); err == nil {
			t.Error("Remediate on a scan-only construction must error (engine not wired)")
		}
		remediateConnects := tf.connects.Load()

		const workers = 8
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := k.Scan(context.Background(), api.HostConfig{Hostname: "h"}, rules)
				if err != nil {
					errs <- err
					return
				}
				if len(res.Outcomes) != 1 || res.Outcomes[0].Status != api.CompliancePass {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("concurrent scan: %v", err)
		}
		if got := tf.connects.Load() - remediateConnects; got != workers {
			t.Errorf("want %d Connect calls from the scans, got %d", workers, got)
		}
	})

	// AC-03: DefaultWithTransportFactory routes connections through the
	// supplied factory; nil factory is a construction error.
	t.Run("scan-public-construction/AC-03", func(t *testing.T) {
		// @spec scan-public-construction
		// @ac AC-03
		if _, err := DefaultWithTransportFactory(context.Background(), t.TempDir()+"/r.db", nil); err == nil {
			t.Fatal("nil factory must be rejected at construction")
		}

		tf := &fakeFactory{results: passingSysctl()}
		svc, err := DefaultWithTransportFactory(context.Background(), t.TempDir()+"/r.db", tf)
		if err != nil {
			t.Fatalf("DefaultWithTransportFactory: %v", err)
		}
		defer func() { _ = svc.Close() }()

		rulePath := writeRule(t, t.TempDir(), "r.yml", plainRule)
		rules, err := LoadRules("", []string{rulePath}, nil)
		if err != nil {
			t.Fatalf("LoadRules: %v", err)
		}
		res, err := svc.Scan(context.Background(), api.HostConfig{Hostname: "h1"}, rules)
		if err != nil {
			t.Fatalf("Scan via custom factory: %v", err)
		}
		if tf.connects.Load() == 0 {
			t.Error("Scan did not go through the supplied factory")
		}
		if len(res.Outcomes) != 1 || res.Outcomes[0].Status != api.CompliancePass {
			t.Errorf("want one pass outcome, got %+v", res.Outcomes)
		}
	})

	// AC-04: existing constructors unchanged — DefaultWithEngineOptions
	// still builds with its bundled defaults and closes cleanly.
	t.Run("scan-public-construction/AC-04", func(t *testing.T) {
		// @spec scan-public-construction
		// @ac AC-04
		svc, err := DefaultWithEngineOptions(context.Background(), t.TempDir()+"/r.db")
		if err != nil {
			t.Fatalf("DefaultWithEngineOptions: %v", err)
		}
		if err := svc.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
			t.Errorf("Close: %v", err)
		}
	})
}
