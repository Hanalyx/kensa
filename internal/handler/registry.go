// Package handler hosts the global handler registry and the engine's
// view of the [api.Handler] interface. Concrete handlers live in
// internal/handlers/<mechanism>/ and register themselves at init time.
package handler

import (
	"fmt"
	"sync"

	"github.com/Hanalyx/kensa/api"
)

// Registry maps a mechanism name to its registered [api.Handler]. The
// global registry is populated by handler-package init functions; the
// engine looks up handlers by the [api.Step.Mechanism] string.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]api.Handler
}

// NewRegistry returns an empty [Registry]. Tests use a fresh registry
// to avoid cross-test pollution; production code uses [Default].
func NewRegistry() *Registry {
	return &Registry{handlers: make(map[string]api.Handler)}
}

// Register adds h to r under h.Name(). Panics if a handler with the
// same name is already registered (handler-interface spec AC-07).
func (r *Registry) Register(h api.Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := h.Name()
	if _, exists := r.handlers[name]; exists {
		panic(fmt.Sprintf("handler: %q already registered", name))
	}
	r.handlers[name] = h
}

// Get returns the handler registered under name, or false if no such
// handler is registered.
func (r *Registry) Get(name string) (api.Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[name]
	return h, ok
}

// MustGet returns the handler registered under name or panics. Used by
// the engine's pre-flight phase after the registered set has been
// validated.
func (r *Registry) MustGet(name string) api.Handler {
	h, ok := r.Get(name)
	if !ok {
		panic(fmt.Sprintf("handler: %q not registered", name))
	}
	return h
}

// Names returns a sorted list of registered mechanism names. Used by
// kensa-validate to verify rule YAML references against the registered
// handler set.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.handlers))
	for n := range r.handlers {
		names = append(names, n)
	}
	return names
}

// defaultRegistry is the process-global registry handler packages
// register themselves into.
var defaultRegistry = NewRegistry()

// Default returns the process-global registry.
func Default() *Registry { return defaultRegistry }

// Register adds h to the global registry. Convenience for handler
// init functions: `handler.Register(&Handler{})`.
func Register(h api.Handler) { defaultRegistry.Register(h) }
