package filepermissions

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// Rollback restores owner, group, mode, and SELinux context from the
// captured pre-state. Idempotent per handler-file-permissions spec
// AC-06: a second invocation against already-restored state is a no-op
// because chown/chmod/chcon are themselves idempotent.
//
// Per spec C-04 / AC-08, restoration uses chcon with the captured
// context verbatim. The implementation never invokes restorecon;
// default-policy fallback is explicitly out of scope.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, fmt.Errorf("file_permissions: rollback called with nil pre-state")
	}

	path, ok := pre.Data["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("file_permissions: pre-state missing 'path'")
	}
	owner, _ := pre.Data["owner"].(string)
	group, _ := pre.Data["group"].(string)
	mode, _ := pre.Data["mode"].(string)
	selinux, _ := pre.Data["selinux_context"].(string)

	cmds := buildRollbackCommands(path, owner, group, mode, selinux)
	if len(cmds) == 0 {
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("file_permissions: nothing to rollback for %s", path),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	pipeline := strings.Join(cmds, " && ")
	res, err := transport.Run(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("file_permissions: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("file_permissions: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("file_permissions: restored %s to captured pre-state", path),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// buildRollbackCommands assembles the ordered shell commands to
// restore captured pre-state. Empty owner/group/mode/selinux are
// skipped — the captured value was empty at capture time, so there is
// nothing to restore.
func buildRollbackCommands(path, owner, group, mode, selinux string) []string {
	cmds := make([]string, 0, 3)
	if owner != "" || group != "" {
		// spec is shell-quoted: although the captured owner/group come from a
		// stat at capture, quoting keeps the construction injection-proof and
		// symmetric with Apply (defense-in-depth on the root-privileged path).
		spec := owner
		if group != "" {
			spec += ":" + group
		}
		cmds = append(cmds, fmt.Sprintf("chown %s %s", shellQuote(spec), shellQuote(path)))
	}
	if mode != "" {
		cmds = append(cmds, fmt.Sprintf("chmod %s %s", shellQuote(mode), shellQuote(path)))
	}
	if selinux != "" {
		cmds = append(cmds, fmt.Sprintf("chcon --no-dereference %s %s", shellQuote(selinux), shellQuote(path)))
	}
	return cmds
}
