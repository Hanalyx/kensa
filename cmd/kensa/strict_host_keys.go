package main

import (
	"github.com/spf13/pflag"
)

// registerStrictHostKeysFlag wires the boolean pair
// --strict-host-keys / --no-strict-host-keys onto fs. The two
// flags are deliberately separate so operators can both opt in
// (--strict-host-keys) and explicitly opt out
// (--no-strict-host-keys) — the latter matters once a future
// config-file deliverable lets sites set strict-on-by-default,
// at which point operators need a way to override back.
//
// Default is false (TOFU policy) to match Python kensa. Use
// resolveStrictHostKeys to read the resolved value back.
//
// Note: this is a flag pair rather than a single string with
// NoOptDefVal (the C-026 password pattern) because there's no
// value to prompt for, and the inverse name needs to be
// targetable by a future config-file or env-var deliverable.
func registerStrictHostKeysFlag(fs *pflag.FlagSet) {
	fs.Bool("strict-host-keys", false,
		"verify SSH host keys; reject unknown (overrides --no-strict-host-keys)")
	fs.Bool("no-strict-host-keys", false,
		"trust on first use (default today; explicit form for future config-file override)")
}

// resolveStrictHostKeys reads --strict-host-keys and
// --no-strict-host-keys from fs and returns the effective policy.
// Both flags set is a usage error.
func resolveStrictHostKeys(fs *pflag.FlagSet) (bool, error) {
	strict := fs.Changed("strict-host-keys")
	noStrict := fs.Changed("no-strict-host-keys")
	if strict && noStrict {
		return false, NewUsageError("--strict-host-keys and --no-strict-host-keys are mutually exclusive")
	}
	if strict {
		return true, nil
	}
	// --no-strict-host-keys is the documented default; passing it
	// explicitly is a no-op but accepted (matches Python).
	return false, nil
}
