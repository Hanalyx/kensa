// Package configappend implements the config_append handler:
// append a line to a file if it is not already present, with
// capture and rollback support.
// Spec: specs/handlers/config_append.spec.yaml.
package configappend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

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

	// Count exact matches; fall back to 0 if file does not exist.
	countCmd := fmt.Sprintf("grep -cxF %s %s 2>/dev/null || echo 0", shellEscape(p.Line), shellEscape(p.Path))
	res, err := transport.Run(ctx, countCmd)
	if err != nil {
		return nil, fmt.Errorf("config_append: capture transport error: %w", err)
	}

	wasPresent := strings.TrimSpace(res.Stdout) != "0"
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"path":        p.Path,
			"line":        p.Line,
			"was_present": wasPresent,
		},
	}, nil
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

	// Remove all exact-match lines added by Apply.
	// sed regex: anchor to full line so partial matches are safe.
	sedPattern := sedEscape(line)
	removeCmd := fmt.Sprintf("sed -i '/^%s$/d' %s", sedPattern, shellEscape(path))
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
		Detail:     fmt.Sprintf("config_append: removed appended line from %s", path),
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
