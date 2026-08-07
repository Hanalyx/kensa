package varsub

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// VarType is the kind of value a variable holds.
type VarType string

const (
	// TypeInt is a whole number. Negative values are valid: several pwquality
	// credit variables ship as -1.
	TypeInt VarType = "integer"
	// TypeString is text. Values that merely look numeric live here when the
	// leading zero matters, which is why the umask variables are strings.
	TypeString VarType = "string"
	// TypeList is a list of members, written as a YAML list in a file and as
	// comma-separated members on the command line.
	TypeList VarType = "list"
)

// BuiltInTypes reports the declared type of every variable Kensa ships a
// default for.
//
// The embedded defaults file IS the declaration. There is no second schema to
// keep in step with it, because a second one would drift: the type of
// `root_umask` is already visible in that file as a quoted string, and writing
// it down again somewhere else only creates a chance for the two to disagree.
//
// A variable with no built-in default is untyped and is not checked. Sites
// author their own rules with their own variables, and Kensa has no basis to
// police a name it has never heard of.
func BuiltInTypes() (map[string]VarType, error) {
	builtInTypesOnce.Do(func() {
		var doc defaultsDoc
		if err := yaml.Unmarshal(embeddedDefaultsYAML, &doc); err != nil {
			builtInTypesErr = fmt.Errorf("embedded defaults: parse: %w", err)
			return
		}
		out := make(map[string]VarType, len(doc.Variables))
		for k, v := range doc.Variables {
			out[k] = typeOf(v)
		}
		builtInTypes = out
	})
	return builtInTypes, builtInTypesErr
}

var (
	builtInTypesOnce sync.Once
	builtInTypes     map[string]VarType
	builtInTypesErr  error
)

// typeOf classifies a value as decoded from YAML.
func typeOf(v any) VarType {
	switch v.(type) {
	case int, int64, uint, uint64:
		return TypeInt
	case []any:
		return TypeList
	default:
		return TypeString
	}
}

// CheckFileValue validates a value read from a YAML tier against the type the
// built-in defaults declare for that name.
//
// File tiers are checked STRICTLY, against the YAML type rather than against
// what the text could be parsed into, because in a file the author controls the
// quoting and the quoting carries meaning. `root_umask: 027` is the case this
// exists for: unquoted, YAML reads the leading zero as octal and hands back the
// number 23, which is not the 027 anybody intended and is not even 27. Written
// as `'027'` it is a string and correct. Only
// the type tells those apart, so accepting a number for a string variable would
// throw away the one signal that distinguishes them.
func CheckFileValue(name string, raw any, types map[string]VarType) error {
	want, known := types[name]
	if !known {
		return nil
	}
	got := typeOf(raw)
	if got == want {
		return nil
	}
	switch {
	case want == TypeInt && got == TypeString:
		return fmt.Errorf("%s expects %s, got the string %q. Remove the quotes if it is a number",
			name, want, fmt.Sprint(raw))
	case want == TypeString && got == TypeInt:
		// Deliberately does NOT suggest quoting the number shown. YAML reads a
		// leading zero as octal, so an author who wrote 027 sees 23 here, and
		// telling them to write '23' would hand back a different value than the
		// one they meant. The fix is to quote what they originally typed.
		return fmt.Errorf("%s expects %s, got the number %v. Quote the value in the file so YAML keeps "+
			"your text exactly as written. Note a bare 027 is read as the number 23, so quote the "+
			"digits you intended rather than the number shown here",
			name, want, raw)
	case want == TypeList:
		return fmt.Errorf("%s expects a %s, got %s. Write it as a YAML list of members", name, want, got)
	case got == TypeList:
		return fmt.Errorf("%s expects %s, got a list", name, want)
	default:
		return fmt.Errorf("%s expects %s, got %s", name, want, got)
	}
}

// CheckCLIValue validates a value supplied through --var against the declared
// type.
//
// The command line is checked by PARSE, not by type, and the difference is
// forced rather than chosen: every --var value arrives as text, so
// `--var pam_faillock_deny=3` is the string "3" no matter what the variable
// holds. Checking its Go type would reject every numeric override ever written.
// What can still be caught is text that is not the thing it claims to be, which
// is the actual mistake: a typo, a unit left on the end, a decimal where a whole
// number belongs.
func CheckCLIValue(name, raw string, types map[string]VarType) error {
	want, known := types[name]
	if !known {
		return nil
	}
	switch want {
	case TypeInt:
		if _, err := strconv.Atoi(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("%s expects an %s, got %q", name, want, raw)
		}
	case TypeList:
		for _, m := range strings.Split(raw, ListSeparator) {
			if strings.TrimSpace(m) != m {
				return fmt.Errorf("%s is a %s; the member %q has surrounding whitespace", name, want, m)
			}
		}
	case TypeString:
		// Any text is a valid string.
	}
	return nil
}
