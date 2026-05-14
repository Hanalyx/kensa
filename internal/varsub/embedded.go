package varsub

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

// embeddedDefaultsYAML is the kensa built-in defaults file.
// Vendored from kensa/config/defaults.yml (Python sister repo);
// see internal/varsub/embedded/defaults.yml for the source.
//
// Embedded at build time so a fresh `kensa check` against the
// production rule corpus doesn't silently skip the ~30 templated
// rules. Operators override via --config-dir's higher-priority
// tiers (defaults.yml / conf.d / groups / hosts / CLI --var).
//
//go:embed embedded/defaults.yml
var embeddedDefaultsYAML []byte

// builtInDefaultsCache memoizes the parsed result so repeated
// BuiltInDefaults calls (per-host inventory fan-out) don't re-
// parse the same bytes. The embedded YAML is immutable so a
// single parse is correct for the lifetime of the process.
var builtInDefaultsCache Variables

// BuiltInDefaults returns the variables defined in the
// embedded defaults.yml. It is the lowest-priority tier in
// ResolveTiers — every other source overrides it.
//
// Returns an error only if the embedded YAML fails to parse,
// which would indicate a build-time corruption (the file is
// validated at test time via TestBuiltInDefaults_Parses).
func BuiltInDefaults() (Variables, error) {
	if builtInDefaultsCache != nil {
		return builtInDefaultsCache, nil
	}
	var doc defaultsDoc
	if err := yaml.Unmarshal(embeddedDefaultsYAML, &doc); err != nil {
		return nil, fmt.Errorf("embedded defaults: parse: %w", err)
	}
	out := make(Variables, len(doc.Variables))
	for k, v := range doc.Variables {
		if !validVarName(k) {
			return nil, fmt.Errorf("embedded defaults: variables.%s: KEY must match [A-Za-z][A-Za-z0-9_]*", k)
		}
		s, err := stringify(v)
		if err != nil {
			return nil, fmt.Errorf("embedded defaults: variables.%s: %w", k, err)
		}
		out[k] = s
	}
	builtInDefaultsCache = out
	return out, nil
}
