package varsub

import (
	"fmt"
	"path/filepath"
	"strings"
)

// defaultsDoc is the on-disk shape of <config-dir>/defaults.yml.
// Matches the Python kensa convention of a top-level `variables:`
// map. We're forward-compatible: future work may add a
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
		return stringifyList(t)
	default:
		return "", fmt.Errorf("non-scalar value of type %T not allowed; use a string, number, or boolean", t)
	}
}

// ListSeparator joins the elements of a list-valued variable.
//
// Substitution is TEXTUAL and happens before the YAML is decoded, so a list has
// to render as something that is still valid YAML wherever the author wrote
// `{{ name }}`, quoted or not. A flow sequence would only survive unquoted, and
// a newline-joined value would break the line it lands on. A single-line
// delimited scalar survives both, which is why a list is carried as text and
// split again by the check that consumes it.
const ListSeparator = ","

// stringifyList renders a YAML list as a single-line delimited scalar.
//
// Elements are validated rather than escaped. A value containing the separator
// or whitespace would split into members the operator never wrote, and a set
// comparison would then be answered against a set nobody declared, which is the
// false-result class this whole area exists to avoid. Rejecting is loud;
// escaping would be silent and would have to be undone identically by every
// consumer.
func stringifyList(items []any) (string, error) {
	if len(items) == 0 {
		// An empty list is legal and renders as the empty string.
		//
		// An earlier version of this rejected it, on the reasoning that an
		// empty set must never quietly become a pass. That reasoning was right
		// and the place for it was wrong: refusing here also refuses the only
		// honest way to ship a variable whose value only the operator can know.
		// `authorized_local_accounts: []` is exactly that, and it is how the
		// built-in defaults declare "this is a list, and nobody has said what
		// belongs in it yet".
		//
		// The guarantee moved to the consumer, where it belongs. set_compare
		// reports itself not assessable on an empty set, so an empty set still
		// cannot become a pass, and now it also cannot become a load failure on
		// a fleet that has simply not been configured.
		return "", nil
	}
	out := make([]string, 0, len(items))
	for i, it := range items {
		switch it.(type) {
		case nil:
			return "", fmt.Errorf("element %d is empty; every member must be a value", i+1)
		case []any, map[string]any:
			return "", fmt.Errorf("element %d is not a scalar; a list variable holds a flat list of strings, numbers or booleans", i+1)
		}
		e := fmt.Sprint(it)
		if e == "" {
			return "", fmt.Errorf("element %d is an empty string; every member must be a value", i+1)
		}
		if strings.ContainsAny(e, ListSeparator) {
			return "", fmt.Errorf("element %d (%q) contains %q, which separates members; a member cannot contain it", i+1, e, ListSeparator)
		}
		if strings.ContainsAny(e, " \t\n\r") {
			return "", fmt.Errorf("element %d (%q) contains whitespace; a member cannot contain it", i+1, e)
		}
		out = append(out, e)
	}
	return strings.Join(out, ListSeparator), nil
}
