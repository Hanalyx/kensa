package api

import "context"

// Handler is the contract every mechanism handler implements.
//
// A Handler knows how to apply a single kind of system change — for
// example, setting a config key, enabling a service, or running a
// command. The engine selects a Handler at remediation time using
// [Handler.Name] and invokes [Handler.Apply] under the protection of
// the four-phase transaction.
//
// Capturable handlers also implement [CaptureHandler] and
// [RollbackHandler] (combined as [CombinedHandler]). Non-capturable
// handlers — those returning false from [Handler.Capturable] — implement
// only Handler. Type-asserting a non-capturable handler to
// [CombinedHandler] returns false; this is the runtime enforcement of
// the atomicity boundary.
//
// Spec: handler-interface (specs/handler/interface.spec.yaml).
type Handler interface {
	// Name returns the mechanism identifier used in rule YAML, such as
	// "config_set", "service_enabled", or "command_exec".
	Name() string

	// Capturable reports whether this mechanism participates in atomic
	// transactions. It returns false for command_exec, manual,
	// grub_parameter_set, and grub_parameter_remove; true for every
	// other built-in mechanism. The value is a static property of the
	// mechanism, not a runtime condition.
	Capturable() bool

	// Apply executes the mechanism against the target host. For
	// capturable mechanisms, pre is the [PreState] the engine captured
	// before this step. For non-capturable mechanisms, pre is nil.
	// Apply returns a [StepResult] describing the outcome, or an
	// error if the step could not be attempted.
	Apply(ctx context.Context, transport Transport, params Params, pre *PreState) (*StepResult, error)
}

// CaptureHandler records pre-state for a capturable mechanism. Only
// handlers where [Handler.Capturable] returns true implement this
// interface.
//
// The engine invokes [CaptureHandler.Capture] before the apply phase
// and persists the returned [PreState] to the transaction log before
// any mutation runs. If the engine crashes between capture and apply,
// the persisted pre-state remains available for out-of-band rollback
// via `kensa rollback --start N`.
type CaptureHandler interface {
	// Capture records the system's pre-state for this mechanism's
	// parameters. It returns [ErrCaptureIncomplete] if pre-state cannot
	// be reliably recorded; the engine then aborts the transaction
	// before any apply step runs.
	Capture(ctx context.Context, transport Transport, params Params) (*PreState, error)
}

// RollbackHandler reverses an applied change using captured pre-state.
// Only handlers where [Handler.Capturable] returns true implement this
// interface.
//
// Rollback must be idempotent. A second invocation against
// already-restored state is a no-op — this is the property that makes
// the deadman-timer rollback path safe to combine with in-band
// rollback.
type RollbackHandler interface {
	// Rollback restores the system to the captured pre-state and
	// returns a [RollbackResult] describing what was restored. A
	// non-nil error indicates rollback could not complete; the
	// transaction is recorded with the partial-restore detail in the
	// returned result, not lost.
	Rollback(ctx context.Context, transport Transport, pre *PreState) (*RollbackResult, error)
}

// CombinedHandler is the interface union every capturable mechanism
// satisfies. Non-capturable mechanisms implement only [Handler], so
// type-asserting them to CombinedHandler at runtime returns false.
// This compiler-enforced split is how the atomicity boundary stays
// honest: a non-capturable handler cannot accidentally be treated as
// capturable, and a capturable handler cannot ship without all three
// methods.
type CombinedHandler interface {
	Handler
	CaptureHandler
	RollbackHandler
}

// Params is the opaque parameters container the engine passes from the
// rule YAML mapping to a handler. Each handler's private decoder
// validates shape and types against its mechanism-specific parameter
// struct. Decoding errors surface as [Handler.Apply] errors during
// pre-flight, not as runtime panics.
type Params map[string]interface{}
