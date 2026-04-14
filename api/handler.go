package api

import "context"

// Handler is the contract every mechanism handler implements.
//
// Satisfies the handler-interface spec (specs/handler/interface.spec.yaml):
//   - AC-01: Name/Capturable/Apply signatures
//   - AC-05: Non-capturable handlers implement only Handler, not CombinedHandler
//   - AC-06: Apply receives nil PreState iff Capturable() returns false
//   - AC-07: Duplicate Name() registration panics at init
type Handler interface {
	// Name returns the mechanism identifier used in rule YAML
	// (e.g. "config_set", "service_enabled", "command_exec").
	Name() string

	// Capturable reports whether this mechanism has capture and rollback
	// handlers. Returns false for command_exec, manual, grub_parameter_set,
	// and grub_parameter_remove; true for every other built-in mechanism.
	//
	// Per handler-interface spec C-02: the return value is a static property
	// of the mechanism, not a runtime condition.
	Capturable() bool

	// Apply executes the mechanism against the target host. For capturable
	// mechanisms, pre is the PreState the engine captured; for non-capturable
	// mechanisms, pre is nil (handler-interface spec AC-06).
	Apply(ctx context.Context, transport Transport, params Params, pre *PreState) (*StepResult, error)
}

// CaptureHandler records pre-state for a capturable mechanism.
// Only implemented by handlers where Capturable() returns true
// (handler-interface spec AC-02).
type CaptureHandler interface {
	// Capture records the system's pre-state for this mechanism's
	// parameters. The returned PreState is persisted to the transaction
	// log before any apply runs (engine-transaction spec AC-04) and used
	// by Rollback.
	//
	// Returns ErrCaptureIncomplete if pre-state cannot be reliably
	// recorded; the engine aborts the transaction before apply.
	Capture(ctx context.Context, transport Transport, params Params) (*PreState, error)
}

// RollbackHandler reverses an applied change using captured pre-state.
// Only implemented by handlers where Capturable() returns true
// (handler-interface spec AC-03).
type RollbackHandler interface {
	// Rollback restores the system to the captured pre-state. Must be
	// idempotent — a second invocation against already-restored state
	// is a no-op (file_permissions spec AC-06, generalized).
	Rollback(ctx context.Context, transport Transport, pre *PreState) (*RollbackResult, error)
}

// CombinedHandler is the interface union every capturable mechanism
// satisfies. Non-capturable mechanisms implement only Handler and thus
// fail type-assertion to CombinedHandler at runtime — this is the
// compile-time and runtime enforcement of handler-interface spec AC-04
// and C-03.
type CombinedHandler interface {
	Handler
	CaptureHandler
	RollbackHandler
}

// Params is the opaque parameters container a handler decodes into its
// mechanism-specific parameter struct. The engine passes the raw YAML
// mapping through; each handler's private decodeParams function
// validates shape and types.
type Params map[string]interface{}
