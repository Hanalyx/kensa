// Package filepermissions implements the file_permissions handler:
// set owner, group, mode, and (optionally) SELinux context on a file
// or directory. First capturable handler shipped per
// docs/KENSA_GO_DAY1_PLAN.md §5.4.
//
// Spec: handler-file-permissions
// (specs/handlers/file_permissions.spec.yaml).
package filepermissions

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// Params is the decoded parameter struct for the file_permissions
// mechanism. Decoded from rule YAML's mechanism params block by
// [decodeParams].
type Params struct {
	// Path is the absolute filesystem path on the target host. Required.
	Path string
	// Owner is the desired owner (username). Optional; omitted means
	// leave unchanged.
	Owner string
	// Group is the desired group (group name). Optional.
	Group string
	// Mode is the desired permission mode as a 4-digit octal string
	// (for example, "0644", "0600"). Optional.
	Mode string
	// SELinuxContext is the desired SELinux context as
	// user:role:type:range. Optional; omitted means leave unchanged.
	// SELinux context restoration uses chcon with the captured value
	// verbatim per handler-file-permissions spec C-04 / AC-08.
	SELinuxContext string

	// Find-based selection, mutually exclusive with Path. When FindPaths
	// is non-empty the handler resolves a SET of targets by running find,
	// then applies owner/group/mode to each and captures each one's prior
	// state for byte-perfect rollback. SELinux is not set/restored on the
	// find-based path (none of the find-based rules set a context).
	FindPaths []string
	// FindType limits the find to files ("f") or directories ("d"); empty
	// means no -type predicate.
	FindType string
	// FindName is an optional -name glob (e.g. "*.so*").
	FindName string
	// FindArgs is extra find TEST predicates appended to the search (e.g.
	// "! -user root", "-perm /o+r"). Validated to exclude action predicates
	// (see validateFindArgs) so rule content can never inject a command.
	FindArgs string
}

// FindBased reports whether these params select a set of targets via find
// rather than a single Path.
func (p *Params) FindBased() bool { return len(p.FindPaths) > 0 }

// errMissingPath is returned when params lacks the required path field.
var errMissingPath = errors.New("file_permissions: params requires either 'path' or 'find_paths'")

// findActionPredicates are find primaries that EXECUTE a command or WRITE a
// file. They must never appear in caller-supplied find_args — otherwise rule
// content could turn a permissions search into arbitrary command execution.
// Test predicates (-perm, -user, -group, -type, -name, -newer, ...) are safe
// and not listed.
var findActionPredicates = []string{
	"-exec", "-execdir", "-ok", "-okdir", "-delete",
	"-fls", "-fprint", "-fprint0", "-fprintf",
}

// validateFindArgs guards the find_args fragment, which is spliced verbatim
// into the find command line (the corpus uses shell-level syntax like escaped
// parens \( \) and quoted globs '*.conf', so it cannot be flattened to a quoted
// token list without rewriting every rule). Two defense layers:
//
//  1. No find ACTION predicate (-exec/-delete/-fprint/...) — those run commands
//     or write files; find_args may carry TEST predicates only.
//  2. No shell command-injection vector — the metacharacters that chain,
//     substitute, redirect, or background a command, plus UNESCAPED parens
//     (subshell). find's own grouping must be written escaped: \( \).
//
// This is defense-in-depth: rules are curated/reviewed, but the engine treats
// rule content as untrusted on the apply path (cf. the sed/mount injection
// fixes in the v0.6.0 release prep).
func validateFindArgs(args string) error {
	for _, tok := range strings.Fields(args) {
		for _, bad := range findActionPredicates {
			if tok == bad {
				return fmt.Errorf("file_permissions: find_args may not contain the action predicate %q (test predicates only)", bad)
			}
		}
	}
	for _, meta := range []string{";", "|", "&", "$", "`", "<", ">", "\n"} {
		if strings.Contains(args, meta) {
			return fmt.Errorf("file_permissions: find_args may not contain the shell metacharacter %q", meta)
		}
	}
	// find's grouping parens must be escaped (\( \)); a bare ( starts a subshell.
	if stripped := strings.NewReplacer(`\(`, "", `\)`, "").Replace(args); strings.ContainsAny(stripped, "()") {
		return errors.New(`file_permissions: find_args parentheses must be escaped as \( \)`)
	}
	return nil
}

// decodeParams converts the engine's opaque [api.Params] map into the typed
// Params struct. It accepts EITHER a single 'path' OR find-based selection via
// 'find_paths' (+ optional find_type / find_name / find_args). Returns an error
// if neither is present, if find_args contains an action predicate, or if any
// value has an unexpected type.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingPath
	}
	out := &Params{}

	if v, ok := p["find_paths"]; ok {
		paths, err := decodeStringList("find_paths", v)
		if err != nil {
			return nil, err
		}
		if len(paths) == 0 {
			return nil, errMissingPath
		}
		out.FindPaths = paths
		if v, ok := p["find_type"]; ok {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("file_permissions: 'find_type' must be a string, got %T", v)
			}
			if s != "" && s != "f" && s != "d" {
				return nil, fmt.Errorf("file_permissions: 'find_type' must be 'f' or 'd', got %q", s)
			}
			out.FindType = s
		}
		if v, ok := p["find_name"]; ok {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("file_permissions: 'find_name' must be a string, got %T", v)
			}
			out.FindName = s
		}
		if v, ok := p["find_args"]; ok {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("file_permissions: 'find_args' must be a string, got %T", v)
			}
			if err := validateFindArgs(s); err != nil {
				return nil, err
			}
			out.FindArgs = s
		}
	} else {
		pathRaw, ok := p["path"]
		if !ok {
			return nil, errMissingPath
		}
		path, ok := pathRaw.(string)
		if !ok || path == "" {
			return nil, errMissingPath
		}
		out.Path = path
	}

	if v, ok := p["owner"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("file_permissions: 'owner' must be a string, got %T", v)
		}
		out.Owner = s
	}
	if v, ok := p["group"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("file_permissions: 'group' must be a string, got %T", v)
		}
		out.Group = s
	}
	if v, ok := p["mode"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("file_permissions: 'mode' must be a string, got %T", v)
		}
		out.Mode = s
	}
	if v, ok := p["selinux_context"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("file_permissions: 'selinux_context' must be a string, got %T", v)
		}
		out.SELinuxContext = s
	}
	// Find-based selection does not capture or restore SELinux context (the
	// find-based rules never set one). Reject the combination loudly rather
	// than silently ignoring a requested relabel that rollback couldn't undo.
	if out.FindBased() && out.SELinuxContext != "" {
		return nil, errors.New("file_permissions: 'selinux_context' is not supported with 'find_paths'")
	}
	return out, nil
}

// decodeStringList converts a YAML list param (decoded as []interface{} of
// strings, or a single string) into []string.
func decodeStringList(key string, v interface{}) ([]string, error) {
	switch t := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("file_permissions: %q entries must be non-empty strings, got %T", key, e)
			}
			out = append(out, s)
		}
		return out, nil
	case []string:
		return t, nil
	case string:
		if t == "" {
			return nil, fmt.Errorf("file_permissions: %q must be non-empty", key)
		}
		return []string{t}, nil
	default:
		return nil, fmt.Errorf("file_permissions: %q must be a list of strings, got %T", key, v)
	}
}
