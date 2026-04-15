package api

// RunOption is a functional option for [Kensa.Transact], [Kensa.Scan],
// [Kensa.Remediate], and [Kensa.Execute]. Options let callers tune
// behavior — non-blocking semantics, deadlines, custom loggers —
// without expanding method signatures.
//
// The engine enforces per-host serialization internally (engine-
// transaction spec C-05), so callers do not need to implement
// per-host locks. RunOption exposes only the small surface of knobs
// the engine permits.
type RunOption func(*runOptions)

// runOptions is the internal struct populated by [RunOption] callbacks.
// Every field has a zero-value default matching the most common
// invocation: blocking on the per-host mutex, no caller-imposed
// deadline.
type runOptions struct {
	nonBlocking bool
}

// WithNonBlocking causes the engine to return [ErrHostBusy]
// immediately if the per-host mutex is held instead of blocking until
// release. Useful for OpenWatch's job-queue workers, which prefer to
// detect contention and requeue rather than stall a worker thread.
func WithNonBlocking() RunOption {
	return func(o *runOptions) { o.nonBlocking = true }
}
