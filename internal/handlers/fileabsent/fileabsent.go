// Package fileabsent implements the file_absent handler: ensure a file
// does not exist on the target host. Capture records the full prior
// file state so rollback can recreate it exactly.
// Spec: specs/handlers/file_absent.spec.yaml.
package fileabsent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "file_absent"

// Params is the decoded parameter struct for the file_absent mechanism.
type Params struct {
	// Path is the absolute target path on the host. Required.
	Path string
}

// errMissingPath is returned when params lacks the required path field.
var errMissingPath = errors.New("file_absent: params missing required 'path'")

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingPath
	}
	v, ok := p["path"]
	if !ok {
		return nil, errMissingPath
	}
	path, ok := v.(string)
	if !ok || path == "" {
		return nil, errMissingPath
	}
	return &Params{Path: path}, nil
}

// Handler implements the file_absent mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "file_absent".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply removes the target file via `rm -f`. Idempotent: an already-
// absent file is not an error (rm -f exit 0 for absent paths).
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	res, err := transport.Run(ctx, fmt.Sprintf("rm -f %s", shellEscape(p.Path)))
	if err != nil {
		return nil, fmt.Errorf("file_absent: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("file_absent: rm -f %s failed (exit %d): %s", p.Path, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("file_absent: removed %s", p.Path),
	}, nil
}

// Capture records whether the file exists and, if so, its full content
// and attributes. An absent file is a valid capture (file_existed=false)
// and is NOT an error per spec C-04.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	cmd := fmt.Sprintf(
		`if [ -e %[1]s ]; then `+
			`printf 'EXISTS\n'; `+
			`stat -c '%%a|%%U|%%G' %[1]s; `+
			`ls -Zd %[1]s 2>/dev/null | awk '{print $1}'; `+
			`cat %[1]s; `+
			`else printf 'ABSENT\n'; fi`,
		shellEscape(p.Path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("file_absent: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("file_absent: capture failed for %s: %w (stderr: %s)",
			p.Path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}

	if strings.HasPrefix(res.Stdout, "ABSENT\n") {
		return &api.PreState{
			Mechanism:  mechanism,
			Capturable: true,
			CapturedAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"path":         p.Path,
				"file_existed": false,
				"content":      "",
				"mode":         "",
				"owner":        "",
				"group":        "",
				"selinux":      "",
			},
		}, nil
	}

	rest := strings.TrimPrefix(res.Stdout, "EXISTS\n")
	mode, owner, group, selinux, content, parseErr := parseCaptureOutput(rest)
	if parseErr != nil {
		return nil, fmt.Errorf("file_absent: capture parse failed for %s: %w", p.Path, parseErr)
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"path":         p.Path,
			"file_existed": true,
			"content":      content,
			"mode":         mode,
			"owner":        owner,
			"group":        group,
			"selinux":      selinux,
		},
	}, nil
}

// parseCaptureOutput parses: stat-line, SELinux-line, then file content.
func parseCaptureOutput(s string) (mode, owner, group, selinux, content string, err error) {
	idx := strings.Index(s, "\n")
	if idx < 0 {
		return "", "", "", "", "", fmt.Errorf("expected stat line in capture output")
	}
	statLine := s[:idx]
	rest := s[idx+1:]

	fields := strings.SplitN(statLine, "|", 3)
	if len(fields) != 3 {
		return "", "", "", "", "", fmt.Errorf("expected 3 stat fields, got %d (line=%q)", len(fields), statLine)
	}
	mode, owner, group = fields[0], fields[1], fields[2]
	if len(mode) < 4 {
		mode = strings.Repeat("0", 4-len(mode)) + mode
	}

	idx = strings.Index(rest, "\n")
	if idx < 0 {
		selinux = strings.TrimSpace(rest)
		if selinux == "?" {
			selinux = ""
		}
		return mode, owner, group, selinux, "", nil
	}
	selinux = strings.TrimSpace(rest[:idx])
	if selinux == "?" {
		selinux = ""
	}
	content = rest[idx+1:]
	return mode, owner, group, selinux, content, nil
}

// Rollback recreates the file when file_existed=true. When
// file_existed=false, rollback is a no-op (file was already absent).
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("file_absent: rollback called with nil pre-state")
	}
	path, _ := pre.Data["path"].(string)
	if path == "" {
		return nil, errors.New("file_absent: pre-state missing 'path'")
	}
	fileExisted, _ := pre.Data["file_existed"].(bool)

	if !fileExisted {
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("file_absent: no-op rollback for %s (was absent at capture)", path),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	content, _ := pre.Data["content"].(string)
	mode, _ := pre.Data["mode"].(string)
	owner, _ := pre.Data["owner"].(string)
	group, _ := pre.Data["group"].(string)
	selinux, _ := pre.Data["selinux"].(string)

	cmds := []string{fmt.Sprintf("printf '%%s' %s > %s", shellEscape(content), shellEscape(path))}
	if mode != "" {
		cmds = append(cmds, fmt.Sprintf("chmod %s %s", mode, shellEscape(path)))
	}
	if owner != "" || group != "" {
		spec := owner
		if group != "" {
			spec += ":" + group
		}
		cmds = append(cmds, fmt.Sprintf("chown %s %s", spec, shellEscape(path)))
	}
	if selinux != "" {
		cmds = append(cmds, fmt.Sprintf("chcon --no-dereference %s %s", shellEscape(selinux), shellEscape(path)))
	}

	res, err := transport.Run(ctx, strings.Join(cmds, " && "))
	if err != nil {
		return nil, fmt.Errorf("file_absent: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("file_absent: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("file_absent: recreated %s from captured pre-state", path),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
