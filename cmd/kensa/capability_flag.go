package main

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/detect"
)

// registerCapabilityFlag wires --capability / -C as a repeatable
// KEY=VALUE flag. Operators pass `-C apparmor=true -C selinux=false`
// to override the detected capability set per-key. KEY is validated
// against the canonical vocabulary in detect.KnownCapabilities();
// VALUE is parsed by parseCapabilityValue (true|false, plus the
// usual yes/no/1/0 aliases).
//
// Uses StringArrayVarP rather than StringSliceVarP: the latter
// comma-splits a single argument, which would surprise operators
// once a future capability VALUE grammar gets richer than booleans.
func registerCapabilityFlag(fs *pflag.FlagSet, dst *[]string) {
	fs.StringArrayVarP(dst, "capability", ShortCapability, nil,
		"override a detected capability KEY=VALUE; repeatable (e.g. -C apparmor=true -C selinux=false). Duplicate KEYs: last value wins.")
}

// resolveCapabilityOverrides parses raw -C KEY=VALUE entries into a
// CapabilitySet, validating KEY against the known vocabulary and
// VALUE against the truth-value parser. The first malformed entry
// surfaces as a usage error.
//
// Duplicate KEYs across multiple -C flags are resolved last-write-
// wins via map assignment (no error, no warning) — matches the
// principle of least surprise for repeatable flags.
func resolveCapabilityOverrides(raw []string) (api.CapabilitySet, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	known := capabilityVocabulary()
	out := make(api.CapabilitySet, len(raw))
	for _, entry := range raw {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("--capability %q: missing '='; use KEY=VALUE form", entry)
		}
		if key == "" {
			return nil, fmt.Errorf("--capability %q: empty KEY (use KEY=VALUE form)", entry)
		}
		if _, in := known[key]; !in {
			return nil, fmt.Errorf("--capability %q: unknown capability key %q; valid keys: %s", entry, key, strings.Join(detect.KnownCapabilities(), ", "))
		}
		v, err := parseCapabilityValue(value)
		if err != nil {
			return nil, fmt.Errorf("--capability %q: %w", entry, err)
		}
		out[key] = v
	}
	return out, nil
}

// parseCapabilityValue turns the operator-supplied side of a
// KEY=VALUE pair into a bool. Accepts the obvious truthy/falsy
// spellings; rejects anything else with a clear error so a
// typo doesn't silently flip the policy.
func parseCapabilityValue(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "y", "on", "1":
		return true, nil
	case "false", "no", "n", "off", "0":
		return false, nil
	}
	return false, fmt.Errorf("expected true|false, got %q", s)
}

// capabilityVocabulary returns the set of known capability names
// as a lookup map. Wraps detect.KnownCapabilities so the CLI layer
// doesn't have to repeat it inline.
func capabilityVocabulary() map[string]struct{} {
	names := detect.KnownCapabilities()
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}

