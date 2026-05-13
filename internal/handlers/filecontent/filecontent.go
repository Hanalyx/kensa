// Package filecontent implements the file_content handler: write a
// complete file body to a target path. Capture records the prior
// content and attributes for rollback. If the file was absent, rollback
// removes it. Spec: specs/handlers/file_content.spec.yaml.
package filecontent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent/fsatomic"
)

// mechanism is the canonical handler name.
const mechanism = "file_content"

// Params is the decoded parameter struct for the file_content
// mechanism.
type Params struct {
	// Path is the absolute target path on the host. Required.
	Path string
	// Content is the complete file body to write. May contain newlines.
	// Required.
	Content string
	// Mode is the desired permission mode as a 4-digit octal string
	// (e.g. "0644"). Optional. When omitted: existing files retain
	// their current mode bits (matches `printf > file` shell
	// semantics); new files default to 0o644 (umask-default under
	// root). To force-normalize an existing file's mode, set the
	// rule's `mode:` field explicitly.
	Mode string
	// Owner is the desired owner username. Optional.
	Owner string
	// Group is the desired group name. Optional.
	Group string
}

var (
	errMissingPath    = errors.New("file_content: params missing required 'path'")
	errMissingContent = errors.New("file_content: params missing required 'content'")
)

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
	contentRaw, ok := p["content"]
	if !ok {
		return nil, errMissingContent
	}
	content, ok := contentRaw.(string)
	if !ok {
		return nil, fmt.Errorf("file_content: 'content' must be a string, got %T", contentRaw)
	}

	out := &Params{Path: path, Content: content}
	if v, ok := p["mode"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("file_content: 'mode' must be a string, got %T", v)
		}
		out.Mode = s
	}
	if v, ok := p["owner"]; ok {
		s, _ := v.(string)
		out.Owner = s
	}
	if v, ok := p["group"]; ok {
		s, _ := v.(string)
		out.Group = s
	}
	return out, nil
}

// Handler implements the file_content mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "file_content".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply writes the content to the target path using printf piped to
// tee (so it works without heredoc support), then applies mode and
// optional ownership. The pipeline is chained with `&&` so a failure
// in any step aborts the rest.
//
// Per spec C-01, apply is idempotent: writing the same content twice
// produces the same file.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if vErr := fsatomic.ValidatePath(p.Path); vErr != nil {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("file_content: %v", vErr),
		}, nil
	}

	// Phase 2 P-002: agent-mode uses fsatomic for the write
	// path (AtomicReplace for existing, AtomicWrite for new).
	// chmod is single-syscall atomic — passed via mode arg
	// to fsatomic. chown stays shell because there's no
	// equivalent atomic primitive AND a chown failure after
	// successful write needs to be reported as partial
	// success (FMA Q1.b).
	if afs, ok := transport.(fsatomic.Transport); ok {
		fileMode, modeSpecified, modeErr := fsatomic.ParseMode(p.Mode)
		if modeErr != nil {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("file_content: parse mode %q: %v", p.Mode, modeErr),
			}, nil
		}
		// Existence check for write vs replace branch.
		exists, statErr := fsatomic.FileExists(p.Path)
		if statErr != nil {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("file_content: stat %s: %v", p.Path, statErr),
			}, nil
		}
		// When the rule omits `mode`: preserve the target's
		// existing mode (re-Apply against a tightened file
		// must not silently widen); for a new file, fall back
		// to the umask-default 0o644. Matches the shell
		// `printf > file` semantics — existing file's mode is
		// untouched, new file's mode is umask-shaped.
		if !modeSpecified {
			if exists {
				info, infoErr := os.Stat(p.Path)
				if infoErr != nil {
					return &api.StepResult{
						Success: false,
						Detail:  fmt.Sprintf("file_content: stat for mode preservation %s: %v", p.Path, infoErr),
					}, nil
				}
				fileMode = fsatomic.FileModeBits(info.Mode())
			} else {
				fileMode = 0o644
			}
		}
		var writeErr error
		if exists {
			writeErr = afs.AtomicReplace(ctx, p.Path, fileMode, []byte(p.Content))
		} else {
			writeErr = afs.AtomicWrite(ctx, filepath.Dir(p.Path), filepath.Base(p.Path), fileMode, []byte(p.Content))
		}
		if writeErr != nil {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("file_content: atomic write %s: %v", p.Path, writeErr),
			}, nil
		}
		// chown via shell — single-syscall ops, no atomicity
		// advantage from rewriting in Go.
		if p.Owner != "" || p.Group != "" {
			spec := p.Owner
			if p.Group != "" {
				spec += ":" + p.Group
			}
			chownCmd := fmt.Sprintf("chown %s %s", spec, shellEscape(p.Path))
			res, runErr := transport.Run(ctx, chownCmd)
			if runErr != nil {
				return nil, fmt.Errorf("file_content: apply chown transport error: %w", runErr)
			}
			if !res.OK() {
				// FMA Q1.b: chown-after-write semi-failure.
				// Bytes are on disk; ownership is wrong.
				// Mark partial — operator can re-Apply.
				return &api.StepResult{
					Success: false,
					Detail: fmt.Sprintf("file_content: atomically wrote %d bytes but chown failed (exit %d): %s; file content is correct but ownership is unchanged",
						len(p.Content), res.ExitCode, strings.TrimSpace(res.Stderr)),
				}, nil
			}
		}
		return &api.StepResult{
			Success: true,
			Detail:  fmt.Sprintf("file_content: atomically wrote %d bytes to %s", len(p.Content), p.Path),
		}, nil
	}

	// Direct-SSH fallback: shell pipeline.
	writeCmd := fmt.Sprintf(
		"printf '%%s' %s > %s",
		shellEscape(p.Content),
		shellEscape(p.Path),
	)
	cmds := []string{writeCmd}

	if p.Mode != "" {
		cmds = append(cmds, fmt.Sprintf("chmod %s %s", p.Mode, shellEscape(p.Path)))
	}
	if p.Owner != "" || p.Group != "" {
		spec := p.Owner
		if p.Group != "" {
			spec += ":" + p.Group
		}
		cmds = append(cmds, fmt.Sprintf("chown %s %s", spec, shellEscape(p.Path)))
	}

	res, err := transport.Run(ctx, strings.Join(cmds, " && "))
	if err != nil {
		return nil, fmt.Errorf("file_content: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("file_content: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("file_content: wrote %d bytes to %s", len(p.Content), p.Path),
	}, nil
}

// parseFileMode and fileExists moved to
// internal/agent/fsatomic/mode.go for reuse across handlers.

// Capture records file_existed, content, mode, owner, group, and
// selinux_context. An absent file is valid (file_existed=false, all
// other fields empty) — it is NOT an error per spec C-04.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	// Check existence and capture attrs in one round trip.
	// If the file exists: emit "EXISTS" then stat line then SELinux
	// context then file content. If absent: emit "ABSENT".
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
		return nil, fmt.Errorf("file_content: capture transport error: %w", err)
	}
	if !res.OK() {
		// stat or cat failed due to permissions — not just absence.
		return nil, fmt.Errorf("file_content: capture failed for %s: %w (stderr: %s)",
			p.Path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}

	stdout := res.Stdout
	if strings.HasPrefix(stdout, "ABSENT\n") {
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

	// EXISTS\n<mode|owner|group>\n<selinux_line>\n<content...>
	rest := strings.TrimPrefix(stdout, "EXISTS\n")
	mode, owner, group, selinux, content, parseErr := parseCaptureOutput(rest)
	if parseErr != nil {
		return nil, fmt.Errorf("file_content: capture parse failed for %s: %w", p.Path, parseErr)
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

// parseCaptureOutput parses the EXISTS block: stat line, SELinux line,
// then all remaining lines as file content.
func parseCaptureOutput(s string) (mode, owner, group, selinux, content string, err error) {
	// First line: mode|owner|group
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

	// Second line: SELinux context (or "?" when SELinux absent)
	idx = strings.Index(rest, "\n")
	if idx < 0 {
		// No content; SELinux line was last.
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

// Rollback restores the prior file state per spec C-03.
//
// When file_existed=false: remove the file (it should not be there).
// When file_existed=true: rewrite content then restore attrs.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("file_content: rollback called with nil pre-state")
	}
	path, _ := pre.Data["path"].(string)
	if path == "" {
		return nil, errors.New("file_content: pre-state missing 'path'")
	}
	fileExisted, _ := pre.Data["file_existed"].(bool)

	// Phase 2 P-002 migration: agent-mode uses fsatomic;
	// direct-SSH falls back to shell. Symmetric with Apply.
	if afs, ok := transport.(fsatomic.Transport); ok {
		if !fileExisted {
			// Was absent — Apply created the file, Rollback removes it.
			rmErr := afs.AtomicRemove(ctx, path)
			if rmErr != nil && !errors.Is(rmErr, fsatomic.ErrNotExist) {
				return &api.RollbackResult{
					Success:    false,
					Detail:     fmt.Sprintf("file_content: rollback AtomicRemove %s: %v", path, rmErr),
					ExecutedAt: time.Now().UTC(),
				}, nil
			}
			return &api.RollbackResult{
				Success:    true,
				Detail:     fmt.Sprintf("file_content: atomically removed %s (was absent at capture)", path),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		// Was present — AtomicReplace with captured bytes.
		content, _ := pre.Data["content"].(string)
		mode, _ := pre.Data["mode"].(string)
		owner, _ := pre.Data["owner"].(string)
		group, _ := pre.Data["group"].(string)
		selinux, _ := pre.Data["selinux"].(string)

		fileMode, modeSpecified, modeErr := fsatomic.ParseMode(mode)
		if modeErr != nil {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("file_content: rollback parse mode %q: %v", mode, modeErr),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		if !modeSpecified {
			// Captured mode empty for a present-at-capture
			// file — Capture failed to record it. Refuse to
			// default; that would silently widen perms on a
			// tightened-mode file at rollback time.
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("file_content: rollback %s: captured mode missing; refusing to default (state is bad — re-issue the rule via `kensa remediate` to regenerate capture, or `kensa rollback --info <txn>` to inspect)", path),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		// Apply may have removed the file or the file may
		// already exist depending on Apply outcome. Try
		// AtomicReplace; on ErrNotExist fall back to
		// AtomicWrite (handle the Apply-removed case).
		writeErr := afs.AtomicReplace(ctx, path, fileMode, []byte(content))
		if writeErr != nil && errors.Is(writeErr, fsatomic.ErrNotExist) {
			writeErr = afs.AtomicWrite(ctx, filepath.Dir(path), filepath.Base(path), fileMode, []byte(content))
		}
		if writeErr != nil {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("file_content: rollback atomic write %s: %v", path, writeErr),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		// chown / chcon via shell.
		var attrCmds []string
		if owner != "" || group != "" {
			spec := owner
			if group != "" {
				spec += ":" + group
			}
			attrCmds = append(attrCmds, fmt.Sprintf("chown %s %s", spec, shellEscape(path)))
		}
		if selinux != "" {
			attrCmds = append(attrCmds, fmt.Sprintf("chcon --no-dereference %s %s", shellEscape(selinux), shellEscape(path)))
		}
		if len(attrCmds) > 0 {
			res, err := transport.Run(ctx, strings.Join(attrCmds, " && "))
			if err != nil {
				return nil, fmt.Errorf("file_content: rollback attr-restore transport error: %w", err)
			}
			if !res.OK() {
				return &api.RollbackResult{
					Success:        false,
					Detail:         fmt.Sprintf("file_content: rollback wrote bytes but attr-restore failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
					PartialRestore: true,
					ExecutedAt:     time.Now().UTC(),
				}, nil
			}
		}
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("file_content: atomically restored %s from captured pre-state", path),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	// Direct-SSH fallback: shell pipeline.
	if !fileExisted {
		// File was absent before apply — remove it.
		res, err := transport.Run(ctx, fmt.Sprintf("rm -f %s", shellEscape(path)))
		if err != nil {
			return nil, fmt.Errorf("file_content: rollback transport error: %w", err)
		}
		if !res.OK() {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("file_content: rollback remove failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
				ExecutedAt: time.Now().UTC(),
			}, nil
		}
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("file_content: removed %s (was absent at capture)", path),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	// Restore prior content and attributes.
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
		return nil, fmt.Errorf("file_content: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("file_content: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("file_content: restored %s to prior content and attributes", path),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
