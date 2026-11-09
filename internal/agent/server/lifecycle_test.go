package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/deadman"
	"github.com/Hanalyx/kensa/internal/agent/wirev1"
	"github.com/Hanalyx/kensa/internal/handler"
)

type admittedWriter struct {
	name, target               string
	started, canceled, release chan struct{}
}

func (h *admittedWriter) Name() string     { return h.name }
func (h *admittedWriter) Capturable() bool { return true }
func (h *admittedWriter) write(ctx context.Context) error {
	if err := os.WriteFile(h.target, []byte("applied"), 0o600); err != nil {
		return err
	}
	close(h.started)
	<-ctx.Done()
	close(h.canceled)
	<-h.release
	return os.WriteFile(h.target, []byte("last admitted write"), 0o600)
}
func (h *admittedWriter) Apply(ctx context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	err := h.write(ctx)
	return &api.StepResult{Success: err == nil}, err
}
func (h *admittedWriter) Rollback(ctx context.Context, _ api.Transport, _ *api.PreState) (*api.RollbackResult, error) {
	err := h.write(ctx)
	return &api.RollbackResult{Success: err == nil}, err
}

// @spec agent-stdio-subcommand
// @ac AC-09
func TestDispatcherJoinsAdmittedMutationsBeforeRestoration(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-09")
	for _, operation := range []string{"apply", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "state")
			h := &admittedWriter{name: "lifecycle_" + operation, target: target, started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
			handler.Register(h)
			a := deadman.New()
			dispatch := HandlerFor(a)
			if _, err := a.ArmDeadman("admitted", time.Minute, []string{fmt.Sprintf("printf captured > %q", target)}); err != nil {
				t.Fatal(err)
			}
			req := &wirev1.Request{SchemaVersion: 1, CorrelationId: 1}
			if operation == "apply" {
				req.Payload = &wirev1.Request_Apply{Apply: &wirev1.ApplyRequest{Mechanism: h.name}}
			} else {
				pre, err := wirev1.APIPreStateToWire(api.PreState{Mechanism: h.name, Capturable: true, Data: map[string]any{}})
				if err != nil {
					t.Fatal(err)
				}
				req.Payload = &wirev1.Request_Rollback{Rollback: &wirev1.RollbackRequest{PreState: pre}}
			}
			done := make(chan *wirev1.Response, 1)
			go func() { done <- dispatch(req) }()
			select {
			case <-h.started:
			case result := <-done:
				t.Fatalf("mutation was not admitted: %v", result)
			case <-time.After(5 * time.Second):
				t.Fatal("mutation admission timed out")
			}
			a.StartShutdown(nil)
			select {
			case <-h.canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("dispatcher failed to propagate mutation cancellation")
			}
			drain := make(chan error, 1)
			go func() { drain <- a.Drain() }()
			select {
			case err := <-drain:
				t.Fatalf("shutdown declared idle before admitted mutation joined: %v", err)
			case <-time.After(200 * time.Millisecond):
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "applied" {
				t.Fatalf("recovery overtook running mutation: %q %v", data, err)
			}
			close(h.release)
			select {
			case result := <-done:
				if result.GetError() != nil {
					t.Fatal(result.GetError())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("mutation did not join")
			}
			select {
			case err := <-drain:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("recovery failed to join")
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "captured" {
				t.Fatalf("late mutation overwrote restored state: %q %v", data, err)
			}
		})
	}
}
