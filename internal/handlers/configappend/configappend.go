// Package configappend implements the config_append handler:
// append a line to a file if it is not already present, with
// capture and rollback support.
// Spec: specs/handlers/config_append.spec.yaml.
package configappend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/fsatomic"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// configFileMode is the fallback mode for a config file config_append must
// create (rare — append targets normally exist). An existing file's mode is
// preserved.
const configFileMode = 0o644

// lineExists reports whether content contains line as an exact full line —
// the Go equivalent of `grep -qxF`.
func lineExists(content, line string) bool {
	for _, l := range strings.Split(content, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

// appendLine returns content with line appended as a distinct final line,
// inserting a separating newline when content does not already end in one
// (so the appended line is grep -xF-matchable, matching `echo >>` intent).
func appendLine(content, line string) string {
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n"
}

// existingMode returns path's current mode bits, or configFileMode if it does
// not exist — so a replace preserves a tightened file's permissions rather
// than widening them.
func existingMode(path string) os.FileMode {
	if info, err := os.Stat(path); err == nil {
		return fsatomic.FileModeBits(info.Mode())
	}
	return configFileMode
}

// mechanism is the canonical handler name.
const mechanism = "config_append"

// Params is the decoded parameter struct for the config_append
// mechanism.
type Params struct {
	// Path is the file to append to. Required.
	Path string
	// Line is the line to append if not already present. Required.
	Line string
}

// errMissingPath is returned when params lacks the required path.
var errMissingPath = errors.New("config_append: params missing required 'path'")

// errMissingLine is returned when params lacks the required line.
var errMissingLine = errors.New("config_append: params missing required 'line'")

// decodeParams converts api.Params into the typed Params struct.
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
	lineRaw, ok := p["line"]
	if !ok {
		return nil, errMissingLine
	}
	line, ok := lineRaw.(string)
	if !ok {
		return nil, errMissingLine
	}
	return &Params{Path: path, Line: line}, nil
}

// Handler implements the config_append mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "config_append".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply checks if line already exists in the file (grep -qxF). If not,
// it appends the line. Idempotent when line is already present.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.applyKernel(ctx, ft, p)
	}
	return h.applyShell(ctx, transport, p)
}

// applyKernel reads the file, and — if the line is not already an exact line —
// appends it and rewrites the file atomically through the funnel (so the
// footprint recorder observes the one file this apply touches). Idempotent.
func (h *Handler) applyKernel(ctx context.Context, ft kernelio.FileTransport, p *Params) (*api.StepResult, error) {
	content, _, err := ft.ReadFileIfExists(p.Path)
	if err != nil {
		return nil, fmt.Errorf("config_append: read %s: %w", p.Path, err)
	}
	if lineExists(content, p.Line) {
		return &api.StepResult{
			Success: true,
			Detail:  fmt.Sprintf("config_append: line already present in %s (no-op, kernel-io)", p.Path),
		}, nil
	}
	if werr := kernelio.WriteFile(ctx, ft, p.Path, existingMode(p.Path), []byte(appendLine(content, p.Line))); werr != nil {
		return nil, fmt.Errorf("config_append: append to %s: %w", p.Path, werr)
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("config_append: appended line to %s (kernel-io)", p.Path),
	}, nil
}

// applyShell is the direct-SSH fallback: grep check + echo append.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
	// Check if line already exists (exact line match, no regex).
	checkCmd := fmt.Sprintf("grep -qxF %s %s", shellEscape(p.Line), shellEscape(p.Path))
	res, err := transport.Run(ctx, checkCmd)
	if err != nil {
		return nil, fmt.Errorf("config_append: apply check transport error: %w", err)
	}
	if res.ExitCode == 0 {
		// Line already present — idempotent no-op.
		return &api.StepResult{
			Success: true,
			Detail:  fmt.Sprintf("config_append: line already present in %s (no-op)", p.Path),
		}, nil
	}

	// Append the line.
	appendCmd := fmt.Sprintf("echo %s >> %s", shellEscape(p.Line), shellEscape(p.Path))
	res, err = transport.Run(ctx, appendCmd)
	if err != nil {
		return nil, fmt.Errorf("config_append: apply append transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("config_append: append to %s failed (exit %d): %s", p.Path, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("config_append: appended line to %s", p.Path),
	}, nil
}

// Capture records whether the line was already present in the file
// before Apply runs. Rollback uses was_present to decide whether to
// remove the line.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	content, existed, err := h.readFile(ctx, transport, p.Path)
	if err != nil {
		return nil, err
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"path":          p.Path,
			"line":          p.Line,
			"was_present":   lineExists(content, p.Line),
			"prior_content": content,
			"file_existed":  existed,
		},
	}, nil
}

// readFile returns path's content and existence, via the kernel-IO read
// (agent) or a shell cat with an absent sentinel.
func (h *Handler) readFile(ctx context.Context, transport api.Transport, path string) (string, bool, error) {
	if ft, ok := transport.(kernelio.FileTransport); ok {
		c, existed, err := ft.ReadFileIfExists(path)
		if err != nil {
			return "", false, fmt.Errorf("config_append: capture read %s: %w (%v)", path, api.ErrCaptureIncomplete, err)
		}
		return c, existed, nil
	}
	cmd := fmt.Sprintf("test -e %[1]s && cat %[1]s || printf '__KENSA_ABSENT__'", shellEscape(path))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return "", false, fmt.Errorf("config_append: capture transport error: %w", err)
	}
	if !res.OK() {
		return "", false, fmt.Errorf("config_append: capture failed for %s: %w (stderr: %s)", path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	if res.Stdout == "__KENSA_ABSENT__" {
		return "", false, nil
	}
	return res.Stdout, true, nil
}

// Rollback removes the appended line if it was not present before Apply
// ran (was_present=false). Idempotent.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("config_append: rollback called with nil pre-state")
	}
	path, _ := pre.Data["path"].(string)
	line, _ := pre.Data["line"].(string)
	wasPresent, _ := pre.Data["was_present"].(bool)

	if path == "" || line == "" {
		return nil, errors.New("config_append: pre-state missing 'path' or 'line'")
	}

	if wasPresent {
		// Line existed before we ran — leave it in place.
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("config_append: line was pre-existing in %s, nothing to rollback", path),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	priorContent, hasContent := pre.Data["prior_content"].(string)
	_, hasFileExisted := pre.Data["file_existed"]
	if !hasContent || !hasFileExisted {
		// Pre-state captured before the kernel-IO migration: no prior_content
		// was recorded. Fall back to the original sed line-removal so rolling
		// back an in-flight pre-migration transaction never deletes the file.
		return h.rollbackLegacySed(ctx, transport, path, line)
	}
	fileExisted, _ := pre.Data["file_existed"].(bool)

	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.rollbackKernel(ctx, ft, path, priorContent, fileExisted)
	}
	return h.rollbackShellRestore(ctx, transport, path, priorContent, fileExisted)
}

// rollbackKernel restores the captured prior content atomically (or removes
// the file if it did not exist before Apply) — byte-perfect.
func (h *Handler) rollbackKernel(ctx context.Context, ft kernelio.FileTransport, path, priorContent string, fileExisted bool) (*api.RollbackResult, error) {
	if fileExisted {
		if err := kernelio.WriteFile(ctx, ft, path, existingMode(path), []byte(priorContent)); err != nil {
			return nil, fmt.Errorf("config_append: rollback restore %s: %w", path, err)
		}
	} else if err := kernelio.RemoveFile(ctx, ft, path); err != nil {
		return nil, fmt.Errorf("config_append: rollback remove %s: %w", path, err)
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("config_append: restored %s (file_existed=%v) (kernel-io)", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShellRestore restores prior content via the shell (direct-SSH).
func (h *Handler) rollbackShellRestore(ctx context.Context, transport api.Transport, path, priorContent string, fileExisted bool) (*api.RollbackResult, error) {
	var cmd string
	if fileExisted {
		cmd = fmt.Sprintf("printf '%%s' %s > %s", shellEscape(priorContent), shellEscape(path))
	} else {
		cmd = fmt.Sprintf("rm -f %s", shellEscape(path))
	}
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("config_append: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("config_append: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("config_append: restored %s (file_existed=%v)", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackLegacySed removes the appended exact-match line via sed — the
// pre-migration behavior, used only for pre-states that predate prior_content
// capture.
func (h *Handler) rollbackLegacySed(ctx context.Context, transport api.Transport, path, line string) (*api.RollbackResult, error) {
	removeCmd := fmt.Sprintf("sed -i '/^%s$/d' %s", sedEscape(line), shellEscape(path))
	res, err := transport.Run(ctx, removeCmd)
	if err != nil {
		return nil, fmt.Errorf("config_append: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("config_append: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("config_append: removed appended line from %s (legacy pre-state)", path),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sedEscape escapes characters that have special meaning in a basic
// sed BRE address pattern (used between /^...$/). The characters
// \.[]^$*/ need escaping.
func sedEscape(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`.`, `\.`,
		`[`, `\[`,
		`]`, `\]`,
		`^`, `\^`,
		`$`, `\$`,
		`*`, `\*`,
		`/`, `\/`,
	)
	return r.Replace(s)
}
