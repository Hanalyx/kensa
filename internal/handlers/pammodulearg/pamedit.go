package pammodulearg

import (
	"fmt"
	"regexp"
	"strings"
)

// transformFile applies the handler's action to a PAM file's content in Go —
// the agent-path counterpart of the sed program the shell path runs. It
// returns the new content and whether anything changed. It mirrors the shell
// semantics exactly:
//
//   - ensure: if ANY matching module line already carries the arg the whole
//     file is a no-op (the coarse file-level idempotency the check command
//     enforces); otherwise " arg" is appended to the end of every matching
//     line (sed: /match/s/$/ arg/).
//   - remove: every occurrence of " arg" is stripped from each matching line
//     (sed: /match/s/ arg//g), with arg taken as an extended regex when
//     ArgRegex is set (sed -E). Go's RE2 matches ERE for the corpus patterns.
//
// A line "matches" when it contains the module and, when Type is set, begins
// (after leading whitespace) with that PAM type column — i.e. ^\s*type\s.*module.
func transformFile(p *Params, content string) (string, bool, error) {
	lines := strings.Split(content, "\n")
	changed := false

	switch p.Action {
	case "ensure":
		present, err := anyMatchingLineHasArg(p, lines)
		if err != nil {
			return "", false, err
		}
		if present {
			return content, false, nil
		}
		for i, line := range lines {
			if matchesLine(p, line) {
				lines[i] = line + " " + p.Arg
				changed = true
			}
		}
	case "remove":
		stripper, err := argStripper(p)
		if err != nil {
			return "", false, err
		}
		for i, line := range lines {
			if !matchesLine(p, line) {
				continue
			}
			if nl := stripper(line); nl != line {
				lines[i] = nl
				changed = true
			}
		}
	default:
		return "", false, fmt.Errorf("pam_module_arg: unknown action %q", p.Action)
	}

	if !changed {
		return content, false, nil
	}
	return strings.Join(lines, "\n"), true, nil
}

// matchesLine reports whether line is a target module line, mirroring the
// shell match pattern (module substring, plus the anchored type column when
// Type is set).
func matchesLine(p *Params, line string) bool {
	if !strings.Contains(line, p.Module) {
		return false
	}
	if p.Type == "" {
		return true
	}
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, p.Type) {
		return false
	}
	rest := trimmed[len(p.Type):]
	return rest != "" && (rest[0] == ' ' || rest[0] == '\t')
}

// anyMatchingLineHasArg reports whether some matching module line already
// carries the arg (literal substring, or regex match when ArgRegex is set) —
// the file-level idempotency the ensure check enforces.
func anyMatchingLineHasArg(p *Params, lines []string) (bool, error) {
	var re *regexp.Regexp
	if p.ArgRegex {
		var err error
		re, err = regexp.Compile(p.Arg)
		if err != nil {
			return false, fmt.Errorf("pam_module_arg: invalid arg regex %q: %w", p.Arg, err)
		}
	}
	for _, line := range lines {
		if !matchesLine(p, line) {
			continue
		}
		if re != nil {
			if re.MatchString(line) {
				return true, nil
			}
			continue
		}
		if strings.Contains(line, p.Arg) {
			return true, nil
		}
	}
	return false, nil
}

// argStripper returns a function that removes " arg" occurrences from a line,
// mirroring sed 's/ arg//g' (literal) or sed -E 's/ arg//g' (regex).
func argStripper(p *Params) (func(string) string, error) {
	if p.ArgRegex {
		re, err := regexp.Compile(" " + p.Arg)
		if err != nil {
			return nil, fmt.Errorf("pam_module_arg: invalid arg regex %q: %w", p.Arg, err)
		}
		return func(line string) string { return re.ReplaceAllString(line, "") }, nil
	}
	needle := " " + p.Arg
	return func(line string) string { return strings.ReplaceAll(line, needle, "") }, nil
}
