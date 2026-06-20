// Package kernelmoduledisable implements the kernel_module_disable
// handler: blacklist a kernel module via /etc/modprobe.d/ and remove
// it from the running kernel if loaded. Capture records whether the
// blacklist file existed for rollback.
// Spec: specs/handlers/kernel_module_disable.spec.yaml.
//
// Dual path: when the transport implements kernelio.ModuleTransport
// (agent mode on the target host) the handler writes the blacklist
// drop-in atomically (fsatomic) and unloads via delete_module(2),
// instead of the shell printf + modprobe pipeline. Otherwise it falls
// back to the shell path. The runtime unload is best-effort on both
// paths — the persistent blacklist+install-/bin/true entry is what keeps
// the module out. Both paths write a byte-identical drop-in and record an
// identical PreState shape, so capture/rollback are path-agnostic.
package kernelmoduledisable

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// mechanism is the canonical handler name.
const mechanism = "kernel_module_disable"

// blacklistMode is the modprobe.d drop-in file mode.
const blacklistMode = 0o644

// blacklistContent renders the canonical drop-in body, so the kernel-IO
// and shell paths write byte-identical files. The `install ... /bin/true`
// line prevents loading even via explicit modprobe; blacklist alone does
// not.
func blacklistContent(module string) string {
	return fmt.Sprintf("# Managed by Kensa.\nblacklist %s\ninstall %s /bin/true\n", module, module)
}

// Params is the decoded parameter struct for kernel_module_disable.
type Params struct {
	// Module is the kernel module name (e.g. "usb-storage", "cramfs").
	// Required.
	Module string
}

// errMissingName is returned when params lacks the required name.
var errMissingName = errors.New("kernel_module_disable: params missing required 'name'")

// decodeParams converts api.Params into the typed Params struct.
//
// The input key is "name" per CANONICAL_RULE_SCHEMA_V1.md §3.5.4 (the
// corpus and internal/mechanism.Contracts agree on "name"). The internal
// Params.Module field and the pre.Data["module"] key are unchanged so the
// capture/rollback round-trip stays byte-identical.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingName
	}
	v, ok := p["name"].(string)
	if !ok || v == "" {
		return nil, errMissingName
	}
	return &Params{Module: v}, nil
}

// blacklistPath returns the modprobe.d file path for a module.
func blacklistPath(module string) string {
	return "/etc/modprobe.d/kensa-disable-" + module + ".conf"
}

// Handler implements the kernel_module_disable mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "kernel_module_disable".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply writes the blacklist + install-as-true entry to modprobe.d and
// unloads the module from the running kernel (best-effort).
//
// Idempotent: rewriting the same blacklist file is a no-op.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if mt, ok := transport.(kernelio.ModuleTransport); ok {
		return h.applyKernel(ctx, mt, p)
	}
	return h.applyShell(ctx, transport, p)
}

// applyKernel writes the blacklist drop-in atomically and unloads the
// module via delete_module(2). The unload is best-effort: a module in use
// (EBUSY) or not loaded (ErrModuleNotLoaded) is not a failure — the
// persistent blacklist is what guarantees it stays out.
func (h *Handler) applyKernel(ctx context.Context, mt kernelio.ModuleTransport, p *Params) (*api.StepResult, error) {
	path := blacklistPath(p.Module)
	if err := kernelio.WriteFile(ctx, mt, path, blacklistMode, []byte(blacklistContent(p.Module))); err != nil {
		return nil, fmt.Errorf("kernel_module_disable: write blacklist: %w", err)
	}
	// Best-effort unload; the blacklist is the load-bearing change.
	_ = mt.DeleteModule(p.Module)
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("kernel_module_disable: blacklisted %s at %s (kernel-io)", p.Module, path),
	}, nil
}

// applyShell writes the blacklist via printf and unloads via modprobe -r
// (best-effort).
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
	path := blacklistPath(p.Module)
	cmd := fmt.Sprintf(
		"printf '%%s' %s > %s && modprobe -r %s 2>/dev/null || true",
		shellEscape(blacklistContent(p.Module)), shellEscape(path), shellEscape(p.Module),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("kernel_module_disable: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("kernel_module_disable: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("kernel_module_disable: blacklisted %s at %s", p.Module, path),
	}, nil
}

// Capture records whether the blacklist file existed and its content.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if mt, ok := transport.(kernelio.ModuleTransport); ok {
		return h.captureKernel(mt, p)
	}
	return h.captureShell(ctx, transport, p)
}

// captureKernel reads the blacklist file directly.
func (h *Handler) captureKernel(mt kernelio.ModuleTransport, p *Params) (*api.PreState, error) {
	path := blacklistPath(p.Module)
	content, existed, err := mt.ReadFileIfExists(path)
	if err != nil {
		return nil, fmt.Errorf("kernel_module_disable: capture read %s: %w (%v)", path, api.ErrCaptureIncomplete, err)
	}
	return h.preState(p, path, existed, content), nil
}

// captureShell reads the blacklist file via cat + an absent sentinel.
func (h *Handler) captureShell(ctx context.Context, transport api.Transport, p *Params) (*api.PreState, error) {
	path := blacklistPath(p.Module)
	cmd := fmt.Sprintf(
		"test -e %[1]s && cat %[1]s || printf '__KENSA_ABSENT__'",
		shellEscape(path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("kernel_module_disable: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("kernel_module_disable: capture failed for %s: %w (stderr: %s)",
			path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	existed := res.Stdout != "__KENSA_ABSENT__"
	content := ""
	if existed {
		content = res.Stdout
	}
	return h.preState(p, path, existed, content), nil
}

// preState builds the canonical PreState shape used by both capture
// paths, so Rollback is path-agnostic.
func (h *Handler) preState(p *Params, path string, fileExisted bool, priorContent string) *api.PreState {
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"module":        p.Module,
			"path":          path,
			"file_existed":  fileExisted,
			"prior_content": priorContent,
		},
	}
}

// Rollback removes the blacklist file (or restores prior content).
// Re-enabling the module at runtime after removal can require a manual
// step or reboot in some configurations — a disclosed limitation that
// both paths share.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("kernel_module_disable: rollback called with nil pre-state")
	}
	path, _ := pre.Data["path"].(string)
	if path == "" {
		return nil, errors.New("kernel_module_disable: pre-state missing 'path'")
	}
	fileExisted, _ := pre.Data["file_existed"].(bool)
	priorContent, _ := pre.Data["prior_content"].(string)

	if mt, ok := transport.(kernelio.ModuleTransport); ok {
		return h.rollbackKernel(ctx, mt, path, fileExisted, priorContent)
	}
	return h.rollbackShell(ctx, transport, path, fileExisted, priorContent)
}

// rollbackKernel restores or removes the blacklist drop-in atomically.
func (h *Handler) rollbackKernel(ctx context.Context, mt kernelio.ModuleTransport, path string, fileExisted bool, priorContent string) (*api.RollbackResult, error) {
	if fileExisted {
		if err := kernelio.WriteFile(ctx, mt, path, blacklistMode, []byte(priorContent)); err != nil {
			return nil, fmt.Errorf("kernel_module_disable: rollback rewrite %s: %w", path, err)
		}
	} else if err := kernelio.RemoveFile(ctx, mt, path); err != nil {
		return nil, fmt.Errorf("kernel_module_disable: rollback remove %s: %w", path, err)
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("kernel_module_disable: restored %s (file_existed=%v) (kernel-io); module re-enable may require reboot", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell restores or removes the blacklist file via shell.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, path string, fileExisted bool, priorContent string) (*api.RollbackResult, error) {
	var cmd string
	if fileExisted {
		cmd = fmt.Sprintf("printf '%%s' %s > %s", shellEscape(priorContent), shellEscape(path))
	} else {
		cmd = fmt.Sprintf("rm -f %s", shellEscape(path))
	}

	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("kernel_module_disable: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("kernel_module_disable: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("kernel_module_disable: restored %s (file_existed=%v); module re-enable may require reboot", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
