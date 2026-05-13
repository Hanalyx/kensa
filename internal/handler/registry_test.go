package handler_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

// stubHandler is a minimal capturable handler used to exercise the registry.
type stubHandler struct {
	name       string
	capturable bool
}

func (s *stubHandler) Name() string     { return s.name }
func (s *stubHandler) Capturable() bool { return s.capturable }
func (s *stubHandler) Apply(_ context.Context, _ api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	return nil, api.ErrNotYetImplemented
}

// @spec handler-interface
// @ac AC-07
func TestRegistry_AC07_DuplicateRegistrationPanics(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-07")
	r := handler.NewRegistry()
	r.Register(&stubHandler{name: "test_mechanism", capturable: true})

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r.Register(&stubHandler{name: "test_mechanism", capturable: true})
}

// @spec handler-interface
// @ac AC-01
func TestRegistry_GetReturnsRegisteredHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-01")
	r := handler.NewRegistry()
	want := &stubHandler{name: "config_set", capturable: true}
	r.Register(want)

	got, ok := r.Get("config_set")
	if !ok {
		t.Fatal("expected handler to be found")
	}
	if got.Name() != want.Name() {
		t.Errorf("got name=%q, want %q", got.Name(), want.Name())
	}
}

func TestRegistry_GetUnregisteredReturnsFalse(t *testing.T) {
	r := handler.NewRegistry()
	if _, ok := r.Get("nonexistent"); ok {
		t.Error("expected ok=false for unregistered handler")
	}
}

// @spec handler-interface
// @ac AC-05
func TestNonCapturableHandler_DoesNotImplementCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-05")
	var h api.Handler = &stubHandler{name: "noncap", capturable: false}
	if _, ok := h.(api.CombinedHandler); ok {
		t.Error("non-capturable handler should not satisfy CombinedHandler")
	}
}

func TestRegistry_NamesReturnsAllRegistered(t *testing.T) {
	r := handler.NewRegistry()
	r.Register(&stubHandler{name: "alpha", capturable: true})
	r.Register(&stubHandler{name: "beta", capturable: false})

	names := r.Names()
	if len(names) != 2 {
		t.Fatalf("got %d names, want 2", len(names))
	}
}
