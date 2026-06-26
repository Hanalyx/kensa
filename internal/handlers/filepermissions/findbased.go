package filepermissions

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// maxFindFiles caps how many files a single find-based file_permissions step
// may touch. Above this the handler REFUSES at capture (ErrCaptureIncomplete)
// rather than capture a partial pre-state it could not fully roll back — the
// atomicity contract favors a loud refusal over an un-revertable change. The
// find_args filter normally bounds the set to the VIOLATIONS (e.g. only the
// world-readable files), so a real hardened host stays far below this.
const maxFindFiles = 4096

// fileState is one captured target's prior ownership and mode.
type fileState struct {
	Path  string
	Mode  string // 4-digit octal
	Owner string
	UID   string
	Group string
	GID   string
}

// captureFindBased resolves the find selection, records each matched file's
// prior owner/group/mode, and returns a PreState carrying the whole list so
// Apply touches exactly this set and Rollback restores each one. SELinux is
// not captured: the find-based rules set owner/group/mode only, so Apply never
// relabels and there is nothing to restore.
func (h *Handler) captureFindBased(ctx context.Context, transport api.Transport, p *Params) (*api.PreState, error) {
	// `-exec stat … {} +` batches the stat into one (or few) invocations.
	cmd := h.findCommand(p, `-exec stat -c '%n|%a|%U|%u|%G|%g' {} +`)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("file_permissions: capture (find) transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("file_permissions: capture (find) failed for %v: %w (stderr: %s)",
			p.FindPaths, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}

	files, err := parseFindStat(res.Stdout)
	if err != nil {
		return nil, fmt.Errorf("file_permissions: capture (find) parse failed: %w (%v)", api.ErrCaptureIncomplete, err)
	}
	if len(files) > maxFindFiles {
		return nil, fmt.Errorf("file_permissions: find matched %d files, exceeding the %d cap: refusing to capture a pre-state that could not be fully rolled back: %w",
			len(files), maxFindFiles, api.ErrCaptureIncomplete)
	}

	records := make([]interface{}, 0, len(files))
	for _, f := range files {
		records = append(records, map[string]interface{}{
			"path": f.Path, "mode": f.Mode, "owner": f.Owner,
			"uid": f.UID, "group": f.Group, "gid": f.GID,
		})
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"find_based": true,
			"files":      records,
		},
	}, nil
}

// applyFindBased sets the target owner/group/mode on every file the matching
// Capture recorded. Acting on the CAPTURED set (not a fresh find) keeps
// capture, apply, and rollback over exactly the same files — so rollback is
// complete even though find_args (e.g. -perm /o+r) no longer matches the files
// after they are fixed.
func (h *Handler) applyFindBased(ctx context.Context, transport api.Transport, p *Params, pre *api.PreState) (*api.StepResult, error) {
	paths := capturedPaths(pre)
	if len(paths) == 0 {
		return &api.StepResult{Success: true, Detail: "file_permissions: find matched no files; nothing to apply"}, nil
	}

	quoted := quoteAll(paths)
	var cmds []string
	if p.Owner != "" || p.Group != "" {
		spec := p.Owner
		if p.Group != "" {
			spec += ":" + p.Group
		}
		cmds = append(cmds, fmt.Sprintf("chown %s %s", spec, quoted))
	}
	if p.Mode != "" {
		// Mode may be absolute octal or symbolic (e.g. "o-r"); chmod accepts both.
		cmds = append(cmds, fmt.Sprintf("chmod %s %s", p.Mode, quoted))
	}
	if len(cmds) == 0 {
		return &api.StepResult{Success: true, Detail: "file_permissions: no owner/group/mode to set"}, nil
	}

	res, err := transport.Run(ctx, strings.Join(cmds, " && "))
	if err != nil {
		return nil, fmt.Errorf("file_permissions: apply (find) transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("file_permissions: apply (find) failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("file_permissions: applied to %d file(s) under %v", len(paths), p.FindPaths),
	}, nil
}

// rollbackFindBased restores each captured file's own prior owner/group/mode.
// Per-file (modes differ across the set), order-independent because the files
// are independent.
func (h *Handler) rollbackFindBased(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	files := capturedFiles(pre)
	if len(files) == 0 {
		return &api.RollbackResult{Success: true, Detail: "file_permissions: nothing to rollback (no captured files)", ExecutedAt: time.Now().UTC()}, nil
	}
	var cmds []string
	for _, f := range files {
		// Owner/group always present from a stat capture; mode always present.
		spec := f.Owner + ":" + f.Group
		cmds = append(cmds, fmt.Sprintf("chown %s %s", spec, shellQuote(f.Path)))
		cmds = append(cmds, fmt.Sprintf("chmod %s %s", f.Mode, shellQuote(f.Path)))
	}
	res, err := transport.Run(ctx, strings.Join(cmds, " && "))
	if err != nil {
		return nil, fmt.Errorf("file_permissions: rollback (find) transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("file_permissions: rollback (find) failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("file_permissions: restored %d file(s) to captured pre-state", len(files)),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// findCommand builds `find <paths> [-type T] [-name N] <find_args> <suffix>`.
// Paths and -name are shell-quoted; find_args is spliced verbatim (it is
// shell-level find syntax, validated by validateFindArgs at decode).
func (h *Handler) findCommand(p *Params, suffix string) string {
	var b strings.Builder
	b.WriteString("find")
	for _, fp := range p.FindPaths {
		b.WriteString(" ")
		b.WriteString(shellQuote(fp))
	}
	if p.FindType != "" {
		b.WriteString(" -type ")
		b.WriteString(p.FindType)
	}
	if p.FindName != "" {
		b.WriteString(" -name ")
		b.WriteString(shellQuote(p.FindName))
	}
	if p.FindArgs != "" {
		b.WriteString(" ")
		b.WriteString(p.FindArgs)
	}
	b.WriteString(" ")
	b.WriteString(suffix)
	return b.String()
}

// parseFindStat parses lines of "path|mode|owner|uid|group|gid". A path
// containing '|' or a newline would defeat this; system paths under the
// hardening targets do not, and a malformed line is surfaced as an error so
// capture refuses rather than mis-records.
func parseFindStat(stdout string) ([]fileState, error) {
	out := []fileState{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 6 {
			return nil, fmt.Errorf("expected 6 stat fields, got %d (line=%q)", len(fields), line)
		}
		mode := fields[1]
		if len(mode) < 4 {
			mode = strings.Repeat("0", 4-len(mode)) + mode
		}
		out = append(out, fileState{
			Path: fields[0], Mode: mode, Owner: fields[2],
			UID: fields[3], Group: fields[4], GID: fields[5],
		})
	}
	return out, nil
}

// capturedFiles extracts the captured file states from a find-based PreState,
// tolerating both the in-memory shape (Apply, same run) and the JSON-reloaded
// shape (Rollback from `kensa rollback`).
func capturedFiles(pre *api.PreState) []fileState {
	if pre == nil || pre.Data == nil {
		return nil
	}
	raw, ok := pre.Data["files"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]fileState, 0, len(raw))
	for _, e := range raw {
		m, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		str := func(k string) string { s, _ := m[k].(string); return s }
		out = append(out, fileState{
			Path: str("path"), Mode: str("mode"), Owner: str("owner"),
			UID: str("uid"), Group: str("group"), GID: str("gid"),
		})
	}
	return out
}

// capturedPaths returns just the paths from a find-based PreState.
func capturedPaths(pre *api.PreState) []string {
	files := capturedFiles(pre)
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	return paths
}

// isFindBasedPreState reports whether pre carries a find-based capture.
func isFindBasedPreState(pre *api.PreState) bool {
	if pre == nil || pre.Data == nil {
		return false
	}
	b, _ := pre.Data["find_based"].(bool)
	return b
}

// quoteAll shell-quotes each path and joins them with spaces, for a single
// chown/chmod over the whole set.
func quoteAll(paths []string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = shellQuote(p)
	}
	return strings.Join(q, " ")
}
