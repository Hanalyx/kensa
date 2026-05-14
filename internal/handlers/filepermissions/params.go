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
}

// errMissingPath is returned when params lacks the required path field.
var errMissingPath = errors.New("file_permissions: params missing required 'path'")

// decodeParams converts the engine's opaque [api.Params] map into the
// typed Params struct. Returns an error if path is missing or if any
// value has an unexpected type.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingPath
	}
	pathRaw, ok := p["path"]
	if !ok {
		return nil, errMissingPath
	}
	path, ok := pathRaw.(string)
	if !ok || path == "" {
		return nil, errMissingPath
	}
	out := &Params{Path: path}

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
	return out, nil
}
