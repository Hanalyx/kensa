package varsub

import (
	"fmt"
	"path/filepath"
)

// defaultsDoc is the on-disk shape of <config-dir>/defaults.yml.
// Matches the Python kensa convention of a top-level `variables:`
// map. We're forward-compatible: future Phase 3.6 may add a
// `frameworks:` overlay block; the loader returns only the
// `variables:` content for now.
type defaultsDoc struct {
	Variables map[string]any `yaml:"variables"`
}

// LoadDefaults reads <configDir>/defaults.yml and returns its
// `variables:` block as a Variables map. Returns (nil, nil) when
// configDir is empty (no --config-dir supplied) or when the
// file does not exist (operators may run without a defaults
// file). Returns an error only when the file exists but is
// malformed.
//
// Values from YAML are coerced to strings — the rule corpus
// embeds them as strings (`"{{ var }}"`), and the substitution
// is textual. Numeric YAML values like `pam_faillock_deny: 3`
// are converted to "3" via fmt.Sprint; bool values to "true"/
// "false"; nil is rejected as a usage error so operators don't
// accidentally substitute a literal "<nil>" into a rule.
func LoadDefaults(configDir string) (Variables, error) {
	if configDir == "" {
		return nil, nil
	}
	return loadVariablesFile(filepath.Join(configDir, "defaults.yml"))
}

// validVarName mirrors the Substitute templateRe vocabulary:
// the leading char must be a letter, the rest letters / digits /
// underscore. Used by LoadDefaults to reject defaults.yml keys
// that the substitution engine could never reach.
func validVarName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		first := i == 0
		isAlpha := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
		isDigit := r >= '0' && r <= '9'
		isUnder := r == '_'
		if first {
			if !isAlpha {
				return false
			}
		} else if !(isAlpha || isDigit || isUnder) {
			return false
		}
	}
	return true
}

// stringify converts a YAML scalar (bool / int / string /
// float / nil) to a string. Non-scalar values (maps, slices)
// are rejected — variable values must be flat. The nil case
// is rejected to surface accidental empty entries.
func stringify(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "", fmt.Errorf("nil/empty value not allowed; remove the entry or set an explicit value")
	case string:
		return t, nil
	case bool, int, int64, float64, uint, uint64:
		return fmt.Sprint(t), nil
	case map[string]any:
		return "", fmt.Errorf("nested map values not allowed; variable values must be a string, number, or boolean")
	case []any:
		return "", fmt.Errorf("list values not allowed; variable values must be a string, number, or boolean")
	default:
		return "", fmt.Errorf("non-scalar value of type %T not allowed; use a string, number, or boolean", t)
	}
}
