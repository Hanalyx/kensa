package api

// RunOption is a functional option applied to Run / Scan / Remediate /
// Execute. Options let callers tune behavior (non-blocking semantics,
// deadlines, custom loggers) without expanding the method signature.
//
// Per engine-transaction spec C-05, the engine enforces per-host
// serialization INTERNALLY. Callers need not implement per-host locks;
// RunOption here exposes the small surface of knobs the engine permits.
type RunOption func(*runOptions)

// runOptions is the internal struct populated by RunOption functions.
// Every field has a zero-value default matching the most common call
// pattern (blocking on the per-host mutex, no custom deadline).
type runOptions struct {
	nonBlocking bool
}

// WithNonBlocking returns ErrHostBusy immediately if the host's per-host
// mutex is held, instead of blocking until it releases. Useful for
// OpenWatch's job queue workers that want to detect contention and
// requeue rather than stall.
func WithNonBlocking() RunOption {
	return func(o *runOptions) { o.nonBlocking = true }
}
