package main

import (
	"fmt"

	"github.com/spf13/pflag"
)

// MaxWorkers is the upper bound on --workers. Above 50, kensa
// becomes a fork-bomb against its own bastion / local resources
// and fan-in to a shared sshd target trips MaxStartups
// throttling. Treat the limit as a guardrail against operator
// typos like `-w 500`, not a tunable knob.
const MaxWorkers = 50

// LargeFleetThreshold is the host count above which kensa emits
// a one-line stderr hint when --workers is at its default of 1.
// An operator with a 50-host inventory who didn't pass --workers
// is almost certainly going to want concurrency once they see
// how long sequential runs take; surface the knob.
const LargeFleetThreshold = 5

// registerWorkersFlag wires --workers / -w with default 1
// (sequential, matches Python kensa). Validation happens via
// validateWorkers up front, before any goroutine fan-out.
//
// The pflag library appends "(default 1)" automatically; we
// don't repeat it in the description.
func registerWorkersFlag(fs *pflag.FlagSet, dst *int) {
	fs.IntVarP(dst, "workers", ShortWorkers, 1,
		fmt.Sprintf("concurrent SSH connections for --inventory mode (1-%d; 1 = sequential)", MaxWorkers))
}

// validateWorkers returns a usage error when n is out of range.
// Used by runCheck (and any future inventory-mode subcommand) to
// reject a bad --workers value before SSH setup.
func validateWorkers(n int) error {
	if n < 1 {
		return fmt.Errorf("--workers must be >= 1; got %d", n)
	}
	if n > MaxWorkers {
		return fmt.Errorf("--workers must be <= %d; got %d (kensa caps the pool to keep itself from becoming a fork-bomb against the bastion / local resource limits; sshd MaxStartups also trips at this scale when fanning into a shared target)", MaxWorkers, n)
	}
	return nil
}
