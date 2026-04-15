package filepermissions

import (
	"context"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name. Referenced by rule YAML's
// `mechanism: file_permissions` field.
const mechanism = "file_permissions"

// Handler implements the file_permissions mechanism. Capturable: the
// engine captures owner/group/mode/SELinux context before apply and
// restores them on rollback.
type Handler struct{}

// New returns a fresh Handler. Equivalent to &Handler{} but conventional.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "file_permissions".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true: file_permissions has full capture and
// rollback support per handler-file-permissions spec.
func (h *Handler) Capturable() bool { return true }

// Apply sets owner, group, mode, and (when specified) SELinux context
// on the target path. Missing optional fields leave the corresponding
// attribute unchanged.
//
// Per handler-file-permissions spec C-03 / AC-07, the three commands
// (chown, chmod, chcon) execute as a single chained shell pipeline
// joined by `&&`. If any step fails, the host shell stops and the
// later steps do not run. The handler reports the failed command in
// the [api.StepResult.Detail].
//
// Per handler-file-permissions spec C-01 / AC-02, Apply is idempotent:
// re-running with the same params is a no-op since chown/chmod/chcon
// are themselves idempotent against the same target values.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	cmds := buildApplyCommands(p)
	if len(cmds) == 0 {
		// Nothing to do — caller specified path with no attributes.
		return &api.StepResult{
			Success: true,
			Detail:  fmt.Sprintf("file_permissions: no attributes to set on %s", p.Path),
		}, nil
	}

	// Chain with `&&` so a failing command aborts the rest. This
	// satisfies the C-03 atomicity-as-unit requirement.
	pipeline := strings.Join(cmds, " && ")
	res, err := transport.Run(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("file_permissions: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("file_permissions: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("file_permissions: applied to %s", p.Path),
	}, nil
}

// buildApplyCommands returns the ordered list of shell commands that
// implement the apply for p. Returns an empty slice if no attribute
// is set.
func buildApplyCommands(p *Params) []string {
	cmds := make([]string, 0, 3)
	if p.Owner != "" || p.Group != "" {
		// chown user:group path — colon syntax handles either or both.
		spec := p.Owner
		if p.Group != "" {
			spec += ":" + p.Group
		}
		cmds = append(cmds, fmt.Sprintf("chown %s %s", spec, shellQuote(p.Path)))
	}
	if p.Mode != "" {
		cmds = append(cmds, fmt.Sprintf("chmod %s %s", p.Mode, shellQuote(p.Path)))
	}
	if p.SELinuxContext != "" {
		// Use --no-dereference so symlinks are labeled in place rather
		// than the symlink target. Per handler-file-permissions spec
		// C-04 / AC-08, this is chcon with the verbatim context;
		// restorecon is explicitly out of scope.
		cmds = append(cmds, fmt.Sprintf("chcon --no-dereference %s %s", shellQuote(p.SELinuxContext), shellQuote(p.Path)))
	}
	return cmds
}

// shellQuote wraps s in single quotes and escapes any embedded single
// quotes. Sufficient for path and SELinux context values; not a
// general-purpose shell escaper.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
