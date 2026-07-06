// Package cronjob implements the cron_job handler: write a cron job
// entry to /etc/cron.d/. Capture records whether the file existed and
// its prior content for rollback.
// Spec: specs/handlers/cron_job.spec.yaml.
package cronjob

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
	"github.com/Hanalyx/kensa/internal/shellcapture"
	"github.com/Hanalyx/kensa/internal/valueguard"
)

// mechanism is the canonical handler name.
const mechanism = "cron_job"

// cronFileMode is the fallback mode for a cron.d file Kensa creates (root-owned,
// world-readable). When the file already exists the agent path preserves its
// actual mode via existingMode rather than forcing this value.
const cronFileMode = 0o644

// existingMode returns path's current mode bits, or cronFileMode when the file
// does not exist. The agent runs on the target host, so os.Stat is a local
// read — this preserves a pre-existing cron file's mode on apply and rollback.
func existingMode(path string) os.FileMode {
	if info, err := os.Stat(path); err == nil {
		return fsatomic.FileModeBits(info.Mode())
	}
	return cronFileMode
}

// Params is the decoded parameter struct for cron_job.
//
// Input key naming follows CANONICAL_RULE_SCHEMA_V1.md §3.5.4: the
// schema/corpus contract is {schedule, command, user} required, plus
// {name, file} optional. Neither "name" nor "file" is required — when
// both are absent the handler derives a stable, rollback-identifiable
// cron file name (see deriveName) so Apply/Capture/Rollback still
// operate on a deterministic path. The internal struct field names and
// the pre.Data map keys are unchanged, so the capture/rollback
// round-trip stays byte-identical.
type Params struct {
	// Name is the cron file name in /etc/cron.d/ (e.g. "kensa-audit").
	// Optional in the schema; derived when absent.
	Name string
	// Schedule is the cron schedule expression
	// (e.g. "0 2 * * *"). Required.
	Schedule string
	// User is the user to run the command as (e.g. "root"). Required.
	User string
	// Command is the command to execute. Required.
	Command string
	// Path is the resolved /etc/cron.d/ file path. Derived from the
	// optional "file" param (full path) if given, else from Name.
	Path string
}

var (
	errMissingSchedule = errors.New("cron_job: params missing required 'schedule'")
	errMissingUser     = errors.New("cron_job: params missing required 'user'")
	errMissingCommand  = errors.New("cron_job: params missing required 'command'")
)

// decodeParams converts api.Params into the typed Params struct.
//
// Input keys follow CANONICAL_RULE_SCHEMA_V1.md §3.5.4: {schedule,
// command, user} are required; {name, file} are optional. "file" is a
// full path (e.g. "/etc/cron.d/aide"); "name" is a basename under
// /etc/cron.d/. When both are absent a stable name is derived so the
// written file is deterministic and rollback-identifiable.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingSchedule
	}
	schedule, _ := p["schedule"].(string)
	if schedule == "" {
		return nil, errMissingSchedule
	}
	user, _ := p["user"].(string)
	if user == "" {
		return nil, errMissingUser
	}
	command, _ := p["command"].(string)
	if command == "" {
		return nil, errMissingCommand
	}
	name, _ := p["name"].(string)
	file, _ := p["file"].(string)

	// Resolve the on-disk cron file path. Precedence: explicit "file"
	// full path > "name" basename > derived stable name. This keeps
	// behavior identical when "name" is provided and lets the real
	// corpus (which sends "file" + no "name") decode.
	var path string
	switch {
	case file != "":
		path = file
	case name != "":
		path = cronPath(name)
	default:
		name = deriveName(command)
		path = cronPath(name)
	}

	// schedule/user/command are written into a "schedule user command" cron
	// line; a newline in any injects extra cron entries (security.md #13 class).
	if err := valueguard.NoControlCharsIn(map[string]string{
		"cron_job schedule": schedule, "cron_job user": user, "cron_job command": command,
	}); err != nil {
		return nil, err
	}
	return &Params{Name: name, Schedule: schedule, User: user, Command: command, Path: path}, nil
}

// cronPath returns the /etc/cron.d/ path for the cron job.
func cronPath(name string) string {
	return "/etc/cron.d/" + name
}

// deriveName produces a stable, filesystem-safe cron file name from the
// command when neither "name" nor "file" is supplied. The result is
// deterministic for a given command, so Capture and Rollback operate on
// the same path Apply wrote. The "kensa-" prefix marks it as managed.
func deriveName(command string) string {
	var b strings.Builder
	b.WriteString("kensa-")
	wrote := false
	for _, r := range command {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			wrote = true
		case (r == '-' || r == '_') && wrote:
			b.WriteRune(r)
		}
		if b.Len() >= 48 {
			break
		}
	}
	if !wrote {
		return "kensa-job"
	}
	return b.String()
}

// Handler implements the cron_job mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "cron_job".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// cronContent renders the /etc/cron.d/ file body: a Kensa header plus the
// "<schedule> <user> <command>" line.
func cronContent(p *Params) string {
	return fmt.Sprintf("# Managed by Kensa.\n%s %s %s\n", p.Schedule, p.User, p.Command)
}

// Apply writes the cron job file to /etc/cron.d/. Idempotent.
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

// applyKernel writes the cron file atomically through the funnel (so the
// footprint recorder observes the one file it touches), at the canonical
// 0644 mode.
func (h *Handler) applyKernel(ctx context.Context, ft kernelio.FileTransport, p *Params) (*api.StepResult, error) {
	if err := kernelio.WriteFile(ctx, ft, p.Path, existingMode(p.Path), []byte(cronContent(p))); err != nil {
		return nil, fmt.Errorf("cron_job: write %s: %w", p.Path, err)
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("cron_job: wrote %s (kernel-io)", p.Path),
	}, nil
}

// applyShell is the direct-SSH fallback: printf + chmod.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
	path := p.Path
	cmd := fmt.Sprintf(
		"printf '%%s' %s > %s && chmod 0644 %s",
		shellEscape(cronContent(p)), shellEscape(path), shellEscape(path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("cron_job: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("cron_job: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("cron_job: wrote %s", path),
	}, nil
}

// Capture records whether the cron file existed and its prior content. It
// reads via the kernel-IO path (agent) or a shell cat with an absent
// sentinel, so capture is correct on both transports.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	path := p.Path
	priorContent, fileExisted, err := h.readFile(ctx, transport, path)
	if err != nil {
		return nil, err
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"path":          path,
			"file_existed":  fileExisted,
			"prior_content": priorContent,
		},
	}, nil
}

// Rollback restores the prior cron file state.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("cron_job: rollback called with nil pre-state")
	}
	path, _ := pre.Data["path"].(string)
	if path == "" {
		return nil, errors.New("cron_job: pre-state missing 'path'")
	}
	fileExisted, _ := pre.Data["file_existed"].(bool)
	priorContent, _ := pre.Data["prior_content"].(string)

	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.rollbackKernel(ctx, ft, path, priorContent, fileExisted)
	}

	var cmd string
	if fileExisted {
		cmd = fmt.Sprintf("printf '%%s' %s > %s", shellEscape(priorContent), shellEscape(path))
	} else {
		cmd = fmt.Sprintf("rm -f %s", shellEscape(path))
	}

	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("cron_job: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("cron_job: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("cron_job: restored %s (file_existed=%v)", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackKernel restores the prior cron file content atomically (or removes
// it if it did not exist before Apply) through the funnel.
func (h *Handler) rollbackKernel(ctx context.Context, ft kernelio.FileTransport, path, priorContent string, fileExisted bool) (*api.RollbackResult, error) {
	if fileExisted {
		if err := kernelio.WriteFile(ctx, ft, path, existingMode(path), []byte(priorContent)); err != nil {
			return nil, fmt.Errorf("cron_job: rollback restore %s: %w", path, err)
		}
	} else if err := kernelio.RemoveFile(ctx, ft, path); err != nil {
		return nil, fmt.Errorf("cron_job: rollback remove %s: %w", path, err)
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("cron_job: restored %s (file_existed=%v) (kernel-io)", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// readFile returns path's content and existence, via the kernel-IO read
// (agent) or a shell base64 read (exact bytes) with an absent sentinel.
func (h *Handler) readFile(ctx context.Context, transport api.Transport, path string) (string, bool, error) {
	if ft, ok := transport.(kernelio.FileTransport); ok {
		c, existed, err := ft.ReadFileIfExists(path)
		if err != nil {
			return "", false, fmt.Errorf("cron_job: capture read %s: %w (%v)", path, api.ErrCaptureIncomplete, err)
		}
		return c, existed, nil
	}
	cmd := shellcapture.ExistenceReadCmd("-e", shellEscape(path), "__KENSA_ABSENT__")
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return "", false, fmt.Errorf("cron_job: capture transport error: %w", err)
	}
	if !res.OK() {
		return "", false, fmt.Errorf("cron_job: capture failed for %s: %w (stderr: %s)", path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	if res.Stdout == "__KENSA_ABSENT__" {
		return "", false, nil
	}
	// base64-decode to the file's EXACT bytes (the transport trims the trailing
	// newline; base64 round-trips it — #247).
	content, decErr := shellcapture.DecodeContent(res.Stdout)
	if decErr != nil {
		return "", false, fmt.Errorf("cron_job: capture decode failed for %s: %w", path, decErr)
	}
	return content, true, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
