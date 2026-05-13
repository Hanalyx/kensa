package output

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/Hanalyx/kensa-go/api"
)

// Fan-out is the multi-target dispatcher for `kensa <cmd> -o FORMAT:PATH
// [-o FORMAT:PATH...]`. Operators provide one or more output specs;
// the fan-out runs the registered writer for each spec in its own
// goroutine, opens (or reuses stdout for empty Path) the destination,
// writes, and aggregates errors.
//
// Concurrency model:
//   - One goroutine per Spec. The number of specs is operator-bounded
//     and small in practice (≤8: one per registered format) so the
//     goroutine count is bounded.
//   - Each goroutine has its own (writer, io.Writer) pair. Writers
//     registered in writer.go are stateless value types (per
//     specs/output/writer.spec.yaml C-01), so sharing a writer
//     instance across goroutines is safe.
//   - Errors are collected via per-index slice writes (each goroutine
//     owns errs[i]; no mutex needed because indexes don't overlap)
//     and synchronized to the main goroutine via sync.WaitGroup.
//     The first error in argv order is returned (specs[i] errors
//     before specs[j] when i < j) so the operator's diagnostic
//     matches left-to-right reading. Every spec is attempted
//     regardless of earlier failures — partial output is more useful
//     than all-or-nothing.
//   - The win is latency on slow filesystems (NFS, encrypted FUSE)
//     and on workloads with many specs. For ≤3 local-disk specs,
//     parallel dispatch is roughly equivalent to sequential — the
//     model is right for the worst case, neutral for the common one.
//
// File handling:
//   - Specs with non-empty Path use os.Create (O_CREATE|O_TRUNC|O_WRONLY)
//     and defer Close. There is no atomic-write protection in C-019;
//     a failed write leaves a partial file. Atomic-write semantics
//     (write-to-tempfile + rename) is a separate deliverable
//     (C-021 or post-1.0).
//   - Specs with empty Path use stdoutOverride (typically os.Stdout
//     from the cmd/kensa layer; io.Discard when --quiet is set).

// stdoutOverride allows callers to redirect Specs with empty Path
// without modifying os.Stdout globally. The cmd/kensa dispatcher
// passes os.Stdout (or io.Discard when --quiet is set) per-call.

// FanOutScanResult fans out a ScanResult across every spec.
//
// The stdoutOverride parameter is the io.Writer that specs with an
// empty Path will write to. The cmd/kensa dispatcher passes
// os.Stdout normally and io.Discard when --quiet is set. Passing
// nil panics (programmer error: every caller must decide what
// stdout means for them).
//
// Returns the first error encountered in argv order; every spec is
// attempted. A spec with an unregistered format produces
// ErrUnsupportedFormat for that spec; the rest of the fan-out
// continues.
func FanOutScanResult(specs []Spec, stdoutOverride io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult) error {
	if stdoutOverride == nil {
		panic("output: FanOutScanResult: stdoutOverride must not be nil")
	}
	return fanOut(specs, stdoutOverride, func(spec Spec, w io.Writer) error {
		writer, ok := ScanWriterFor(spec.Format)
		if !ok {
			return fmt.Errorf("%w: %q has no scan-result writer", ErrUnsupportedFormat, spec.Format)
		}
		return writer.WriteScanResult(w, hostID, rules, result)
	})
}

// FanOutRemediationResult fans out a RemediationResult across every spec.
func FanOutRemediationResult(specs []Spec, stdoutOverride io.Writer, hostID string, rules []*api.Rule, result *api.RemediationResult) error {
	if stdoutOverride == nil {
		panic("output: FanOutRemediationResult: stdoutOverride must not be nil")
	}
	return fanOut(specs, stdoutOverride, func(spec Spec, w io.Writer) error {
		writer, ok := RemediationWriterFor(spec.Format)
		if !ok {
			return fmt.Errorf("%w: %q has no remediation-result writer", ErrUnsupportedFormat, spec.Format)
		}
		return writer.WriteRemediationResult(w, hostID, rules, result)
	})
}

// FanOutCaps fans out a capability probe result across every spec.
func FanOutCaps(specs []Spec, stdoutOverride io.Writer, hostID string, caps api.CapabilitySet) error {
	if stdoutOverride == nil {
		panic("output: FanOutCaps: stdoutOverride must not be nil")
	}
	return fanOut(specs, stdoutOverride, func(spec Spec, w io.Writer) error {
		writer, ok := CapsWriterFor(spec.Format)
		if !ok {
			return fmt.Errorf("%w: %q has no caps writer", ErrUnsupportedFormat, spec.Format)
		}
		return writer.WriteCaps(w, hostID, caps)
	})
}

// ErrUnsupportedFormat is returned when a spec's format has no
// writer registered for the payload type. Distinguishable via
// errors.Is from generic write errors so cmd/kensa can render it
// as a usage-error (exit 2) instead of a runtime error (exit 1).
var ErrUnsupportedFormat = errors.New("output: unsupported format for this payload type")

// fanOut is the shared concurrent dispatcher. It opens a destination
// for each Spec, invokes writeFunc against that destination, and
// returns the first error in argv order.
//
// The writeFunc parameter is a closure carrying the payload-typed
// lookup + write (see FanOutScanResult etc.); fanOut is the
// concurrency + I/O scaffolding around it.
func fanOut(specs []Spec, stdoutOverride io.Writer, writeFunc func(Spec, io.Writer) error) error {
	if len(specs) == 0 {
		return nil
	}

	// errs[i] holds the error from specs[i]; nil means success.
	// We allocate once; goroutines write to their own slot without
	// locking (the slice is immutable except for per-index assignment
	// which is safe when each goroutine has a unique index).
	errs := make([]error, len(specs))
	var wg sync.WaitGroup
	wg.Add(len(specs))

	for i, spec := range specs {
		go func(i int, spec Spec) {
			defer wg.Done()
			errs[i] = runOneSpec(spec, stdoutOverride, writeFunc)
		}(i, spec)
	}
	wg.Wait()

	// Return the first error in argv order so the operator's
	// diagnostic matches left-to-right reading.
	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("output[%d] (%s): %w", i, specs[i].String(), err)
		}
	}
	return nil
}

// runOneSpec opens the destination for spec, invokes writeFunc, and
// closes the destination. File destinations are opened with
// O_CREATE|O_TRUNC|O_WRONLY (overwrite); stdout destinations use
// stdoutOverride.
//
// The path is shell-expanded by the shell, not by us — paths
// containing $HOME or ~ that didn't get expanded by the shell are
// passed through to os.Create literally, which on most shells means
// the operator gets a file named "~". Documented as a known caveat.
func runOneSpec(spec Spec, stdoutOverride io.Writer, writeFunc func(Spec, io.Writer) error) error {
	if spec.Path == "" {
		return writeFunc(spec, stdoutOverride)
	}
	// Reject path traversal that would clobber sensitive paths. The
	// operator-supplied path is trusted (kensa runs as the operator),
	// but a small amount of defense against typos is cheap.
	if strings.HasPrefix(spec.Path, "/dev/") || strings.HasPrefix(spec.Path, "/proc/") || strings.HasPrefix(spec.Path, "/sys/") {
		return fmt.Errorf("path %q rejected: writing under /dev, /proc, or /sys is unsupported", spec.Path)
	}
	f, err := os.Create(spec.Path)
	if err != nil {
		return fmt.Errorf("open %q: %w", spec.Path, err)
	}
	defer func() { _ = f.Close() }()
	return writeFunc(spec, f)
}
