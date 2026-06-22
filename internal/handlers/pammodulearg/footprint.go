package pammodulearg

import (
	"fmt"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
)

// CapturedFootprint opts pam_module_arg into the agent-mode pre-commit gate.
// It declares every PAM file the apply may rewrite — the keys of the
// whole-file capture (pre.Data["files_content"]). The agent path edits each
// file in place via the kernelio funnel, so the observed footprint (one
// rewrite per changed file) must be a subset of this declaration. A legacy
// pre-state (files_snapshot) declares the same files from that map so an
// in-flight transaction still gates.
func (h *Handler) CapturedFootprint(pre *api.PreState) (*footprint.Footprint, error) {
	if pre == nil || pre.Data == nil {
		return nil, fmt.Errorf("pam_module_arg: nil pre-state")
	}
	files := fileKeys(pre.Data["files_content"])
	if len(files) == 0 {
		files = fileKeys(pre.Data["files_snapshot"])
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("pam_module_arg: pre-state declares no files")
	}
	f := footprint.New()
	for _, file := range files {
		// PAM files exist before the edit, so the op is modify; the gate
		// compares paths, not ops.
		f.Add(footprint.Entry{Path: file, Op: footprint.OpModify})
	}
	return f, nil
}

// fileKeys returns the file-path keys of a captured map[file]value, or nil.
func fileKeys(v interface{}) []string {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	files := make([]string, 0, len(m))
	for file := range m {
		files = append(files, file)
	}
	return files
}
