// Package cronjob implements the cron_job handler: write a cron job
// entry to /etc/cron.d/. Capture records whether the file existed and
// its prior content for rollback.
// Spec: specs/handlers/cron_job.spec.yaml.
package cronjob

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// mechanism is the canonical handler name.
const mechanism = "cron_job"

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

// Apply writes the cron job file to /etc/cron.d/. Idempotent.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	path := p.Path
	// /etc/cron.d/ files need 0644 mode. The format is:
	//   <schedule> <user> <command>
	content := fmt.Sprintf("# Managed by Kensa.\n%s %s %s\n", p.Schedule, p.User, p.Command)
	cmd := fmt.Sprintf(
		"printf '%%s' %s > %s && chmod 0644 %s",
		shellEscape(content), shellEscape(path), shellEscape(path),
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

// Capture records whether the cron file existed and its prior content.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	path := p.Path
	cmd := fmt.Sprintf(
		"test -e %[1]s && cat %[1]s || printf '__KENSA_ABSENT__'",
		shellEscape(path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("cron_job: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("cron_job: capture failed for %s: %w (stderr: %s)",
			path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	fileExisted := res.Stdout != "__KENSA_ABSENT__"
	priorContent := ""
	if fileExisted {
		priorContent = res.Stdout
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

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
