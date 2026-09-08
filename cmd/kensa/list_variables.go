package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/internal/output"
	"github.com/Hanalyx/kensa/internal/varsub"
	"github.com/Hanalyx/kensa/pkg/kensa"
)

// Default-state values for a listed variable. The three are distinct because
// "ships empty on purpose" and "Kensa has never heard of this name" are
// different situations for an operator, and a bare empty value cannot tell
// them apart.
const (
	// defaultStateValue is an explicit, non-empty built-in default.
	defaultStateValue = "value"
	// defaultStateEmpty is an explicit built-in that is an empty string or an
	// empty list. Some variables ship empty deliberately, because only a site
	// can say what its own authorized set contains.
	defaultStateEmpty = "empty"
	// defaultStateAbsent means Kensa ships no default. A site authored the
	// variable in its own rules, so Kensa knows neither its type nor a value.
	defaultStateAbsent = "absent"
)

// variableRow is one row of `kensa list variables`.
//
// Type and Default are `any` rather than strings so the document can keep the
// declared shape: an integer stays a JSON number, a list stays a JSON array,
// and a variable Kensa does not ship stays null. Collapsing them all to text
// would make `3`, `"3"` and `["3"]` indistinguishable to a consumer.
type variableRow struct {
	Default      any      `json:"default"`
	DefaultState string   `json:"default_state"`
	Name         string   `json:"name"`
	Rules        []string `json:"rules"`
	Type         *string  `json:"type"`
}

// listVariablesDoc is the JSON document. One key, so a consumer never has to
// guess which of several top-level fields carries the payload.
type listVariablesDoc struct {
	Variables []variableRow `json:"variables"`
}

// buildVariableRows joins the variables the corpus references to the metadata
// Kensa embeds.
//
// Membership comes from the corpus, never from the embedded file. A built-in
// no rule mentions is not operator work and would read as though it were; a
// site variable Kensa has never heard of IS operator work and has to appear,
// even though Kensa can say nothing about its type or default.
func buildVariableRows(used map[string][]string, defaults map[string]string, types map[string]varsub.VarType) ([]variableRow, error) {
	names := make([]string, 0, len(used))
	for n := range used {
		names = append(names, n)
	}
	sort.Strings(names)

	rows := make([]variableRow, 0, len(names))
	for _, name := range names {
		raw, hasDefault := defaults[name]
		declared, hasType := types[name]

		// Metadata that disagrees with itself is a fault in the embedded
		// artifact, not something to paper over: guessing here would publish a
		// value nobody declared.
		if hasType != hasDefault {
			return nil, fmt.Errorf(
				"variable %s: embedded metadata is inconsistent (default present: %v, type present: %v)",
				name, hasDefault, hasType)
		}

		row := variableRow{Name: name, Rules: sortedUnique(used[name])}
		if !hasDefault {
			row.Type = nil
			row.Default = nil
			row.DefaultState = defaultStateAbsent
			rows = append(rows, row)
			continue
		}

		value, state, err := typedDefault(name, declared, raw)
		if err != nil {
			return nil, err
		}
		t := string(declared)
		row.Type = &t
		row.Default = value
		row.DefaultState = state
		rows = append(rows, row)
	}
	return rows, nil
}

// typedDefault converts one stored default back to its declared shape.
//
// Every default is stored as text, so the declared type is the only thing that
// says what the text meant. Splitting on a comma by looking at the value would
// be wrong: `ssh_approved_ciphers` is a declared string whose value contains
// commas, and turning it into an array would invent a list the author did not
// write.
func typedDefault(name string, declared varsub.VarType, raw string) (any, string, error) {
	switch declared {
	case varsub.TypeInt:
		// ParseInt over Atoi so the answer does not depend on the host's int
		// width; a 64-bit value must not silently change on a 32-bit build.
		n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, "", fmt.Errorf("variable %s is declared %s but its default %q is not one", name, declared, raw)
		}
		return n, defaultStateValue, nil

	case varsub.TypeList:
		// An empty declaration is an empty list, not a list holding one empty
		// member: strings.Split("", ",") returns [""], which would publish a
		// member no author wrote.
		if raw == "" {
			return []string{}, defaultStateEmpty, nil
		}
		members := strings.Split(raw, varsub.ListSeparator)
		for i, m := range members {
			if strings.TrimSpace(m) != m {
				return nil, "", fmt.Errorf(
					"variable %s is declared %s but member %d (%q) carries surrounding whitespace",
					name, declared, i+1, m)
			}
		}
		return members, defaultStateValue, nil

	case varsub.TypeString:
		if raw == "" {
			return "", defaultStateEmpty, nil
		}
		return raw, defaultStateValue, nil

	default:
		return nil, "", fmt.Errorf("variable %s has unsupported declared type %q", name, declared)
	}
}

// sortedUnique returns the rule IDs sorted with duplicates removed, so a rule
// naming one variable twice is still one entry and the order does not depend
// on directory traversal.
func sortedUnique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// writeVariablesText renders the human table.
//
// Defaults render as JSON literals so the text and JSON forms cannot disagree
// about whether a value was a number, a quoted string or a list. Nothing is
// truncated: an operator reading this is deciding what to configure, and a
// clipped list of rules or ciphers is the part they needed.
func writeVariablesText(w io.Writer, rows []variableRow) error {
	fmt.Fprintln(w, "kensa list variables")
	fmt.Fprintf(w, "  %d variable(s)\n\n", len(rows))
	if len(rows) == 0 {
		fmt.Fprintln(w, "  no variables referenced by the loaded corpus")
		return nil
	}

	type line struct{ name, typ, def, state, rules string }
	lines := make([]line, 0, len(rows))
	for _, r := range rows {
		typ := "untyped"
		if r.Type != nil {
			typ = *r.Type
		}
		enc, err := json.Marshal(r.Default)
		if err != nil {
			return fmt.Errorf("render default for %s: %w", r.Name, err)
		}
		lines = append(lines, line{r.Name, typ, string(enc), r.DefaultState, strings.Join(r.Rules, ",")})
	}

	// Column widths come from the values, but padding is capped. One default
	// in the shipped corpus is ~300 characters, and padding every other row
	// out to match it makes the table unreadable. A value wider than its cap
	// overflows its column and pushes the rest of its own row right; it is
	// never shortened, because an operator reading this is deciding what to
	// configure and the clipped tail is the part they needed.
	const maxDefaultPad = 40
	wName, wType, wDef, wState := len("variable"), len("type"), len("default"), len("state")
	for _, l := range lines {
		wName = maxInt(wName, len(l.name))
		wType = maxInt(wType, len(l.typ))
		if len(l.def) <= maxDefaultPad {
			wDef = maxInt(wDef, len(l.def))
		}
		wState = maxInt(wState, len(l.state))
	}
	fmt.Fprintf(w, "  %-*s  %-*s  %-*s  %-*s  %s\n", wName, "variable", wType, "type", wDef, "default", wState, "state", "rules")
	fmt.Fprintf(w, "  %s  %s  %s  %s  %s\n",
		strings.Repeat("-", wName), strings.Repeat("-", wType),
		strings.Repeat("-", wDef), strings.Repeat("-", wState), strings.Repeat("-", len("rules")))
	for _, l := range lines {
		fmt.Fprintf(w, "  %-*s  %-*s  %-*s  %-*s  %s\n", wName, l.name, wType, l.typ, wDef, l.def, wState, l.state, l.rules)
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// runListVariables implements `kensa list variables`.
//
// This describes a corpus, not a host, so it reads only the embedded defaults.
// It takes no --config-dir, no --var and no host: an operator's own values are
// theirs, and a command that printed them would turn a corpus description into
// a disclosure of local configuration.
func runListVariables(args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"rules-dir": true, "format": true,
	})

	fs := pflag.NewFlagSet("list variables", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		rulesDir string
		format   string
		quiet    bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory of rule YAMLs to scan (required)")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text or json")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printListVariablesUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa list variables --help'", err)
	}
	if showHelp {
		printListVariablesUsage(os.Stdout, fs)
		return nil
	}

	if rulesDir == "" {
		return NewUsageError("--rules-dir DIR is required to scan a rule corpus")
	}
	switch format {
	case "text", "json":
	default:
		return NewUsageError(fmt.Sprintf("--format %q: must be 'text' or 'json'", format))
	}

	used, err := kensa.RuleVariables(rulesDir)
	if err != nil {
		return err
	}
	defaults, err := kensa.BuiltInVars()
	if err != nil {
		return err
	}
	types, err := varsub.BuiltInTypes()
	if err != nil {
		return err
	}

	// Build every row before writing anything. A conversion failure must not
	// leave a half-written document on stdout that a consumer would parse as
	// complete.
	rows, err := buildVariableRows(used, defaults, types)
	if err != nil {
		return err
	}

	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		return jw.WriteJSONValue(out, listVariablesDoc{Variables: rows})
	}
	return writeVariablesText(out, rows)
}

func printListVariablesUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprint(w, `Usage: kensa list variables --rules-dir DIR [flags]

List every rule variable the corpus references, with the type and default
Kensa ships for it and the rules that use it.

This describes a corpus, not a host: it reads Kensa's built-in defaults only
and never your own configuration, so the same corpus reports the same values
on any machine.

Flags:
`)
	fmt.Fprint(w, fs.FlagUsages())
}
