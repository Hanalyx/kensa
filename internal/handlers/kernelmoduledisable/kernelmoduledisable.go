// Package kernelmoduledisable implements the kernel_module_disable
// handler: blacklist a kernel module via /etc/modprobe.d/ and remove
// it from the running kernel if loaded. Capture records whether the
// blacklist file existed and whether the module was loaded; when it was,
// Rollback re-loads it via modprobe and verifies against /proc/modules,
// reporting a verified-partial restore if the module does not return.
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
	"github.com/Hanalyx/kensa/internal/shellcapture"
	"github.com/Hanalyx/kensa/internal/valueguard"
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
	// The module name is written into blacklist/install lines in the
	// modprobe.d drop-in; a newline injects extra directives (security.md #13b).
	if err := valueguard.NoControlChars("kernel_module_disable module", v); err != nil {
		return nil, err
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

// Capture records whether the blacklist file existed and its content, plus
// whether the module is currently loaded in the running kernel — the signal
// Rollback uses to decide whether a runtime re-load is needed.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	wasLoaded, err := moduleLoaded(ctx, transport, p.Module)
	if err != nil {
		return nil, fmt.Errorf("kernel_module_disable: capture module state for %s: %w (%v)", p.Module, api.ErrCaptureIncomplete, err)
	}
	if mt, ok := transport.(kernelio.ModuleTransport); ok {
		return h.captureKernel(mt, p, wasLoaded)
	}
	return h.captureShell(ctx, transport, p, wasLoaded)
}

// captureKernel reads the blacklist file directly.
func (h *Handler) captureKernel(mt kernelio.ModuleTransport, p *Params, wasLoaded bool) (*api.PreState, error) {
	path := blacklistPath(p.Module)
	content, existed, err := mt.ReadFileIfExists(path)
	if err != nil {
		return nil, fmt.Errorf("kernel_module_disable: capture read %s: %w (%v)", path, api.ErrCaptureIncomplete, err)
	}
	return h.preState(p, path, existed, wasLoaded, content), nil
}

// captureShell reads the blacklist file via base64 (exact bytes) + an absent sentinel.
func (h *Handler) captureShell(ctx context.Context, transport api.Transport, p *Params, wasLoaded bool) (*api.PreState, error) {
	path := blacklistPath(p.Module)
	cmd := shellcapture.ExistenceReadCmd("-e", shellEscape(path), "__KENSA_ABSENT__")
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
		content, err = shellcapture.DecodeContent(res.Stdout)
		if err != nil {
			return nil, fmt.Errorf("kernel_module_disable: capture decode failed for %s: %w", path, err)
		}
	}
	return h.preState(p, path, existed, wasLoaded, content), nil
}

// preState builds the canonical PreState shape used by both capture
// paths, so Rollback is path-agnostic.
func (h *Handler) preState(p *Params, path string, fileExisted, wasLoaded bool, priorContent string) *api.PreState {
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"module":        p.Module,
			"path":          path,
			"file_existed":  fileExisted,
			"prior_content": priorContent,
			"was_loaded":    wasLoaded,
		},
	}
}

// Rollback removes the blacklist file (or restores prior content), then —
// when the module was loaded at capture — re-loads it and verifies it is
// loaded again by reading /proc/modules back. A confirmed re-load is a
// clean success; a module that does not come back is a verified-partial
// restore with a remedy. A module that was NOT loaded at capture needs no
// re-load: removing the blacklist already matches the prior runtime state.
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
	module, _ := pre.Data["module"].(string)
	wasLoaded, _ := pre.Data["was_loaded"].(bool)

	if mt, ok := transport.(kernelio.ModuleTransport); ok {
		return h.rollbackKernel(ctx, mt, transport, path, fileExisted, priorContent, module, wasLoaded)
	}
	return h.rollbackShell(ctx, transport, path, fileExisted, priorContent, module, wasLoaded)
}

// rollbackKernel restores or removes the blacklist drop-in atomically, then
// re-loads the module when it was loaded at capture.
func (h *Handler) rollbackKernel(ctx context.Context, mt kernelio.ModuleTransport, transport api.Transport, path string, fileExisted bool, priorContent, module string, wasLoaded bool) (*api.RollbackResult, error) {
	if fileExisted {
		if err := kernelio.WriteFile(ctx, mt, path, blacklistMode, []byte(priorContent)); err != nil {
			return nil, fmt.Errorf("kernel_module_disable: rollback rewrite %s: %w", path, err)
		}
	} else if err := kernelio.RemoveFile(ctx, mt, path); err != nil {
		return nil, fmt.Errorf("kernel_module_disable: rollback remove %s: %w", path, err)
	}
	if wasLoaded && module != "" {
		return h.reenable(ctx, transport, path, module, fileExisted), nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("kernel_module_disable: restored %s (file_existed=%v) (kernel-io); module was not loaded at capture", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell restores or removes the blacklist file via shell, then
// re-loads the module when it was loaded at capture.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, path string, fileExisted bool, priorContent, module string, wasLoaded bool) (*api.RollbackResult, error) {
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
	if wasLoaded && module != "" {
		return h.reenable(ctx, transport, path, module, fileExisted), nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("kernel_module_disable: restored %s (file_existed=%v); module was not loaded at capture", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// procModules is the kernel's loaded-module list.
const procModules = "/proc/modules"

// normalizeModule maps a module name to the underscore form the kernel uses
// in /proc/modules. modprobe accepts both "usb-storage" and "usb_storage",
// but /proc/modules always reports the underscore form.
func normalizeModule(name string) string { return strings.ReplaceAll(name, "-", "_") }

// moduleLoaded reports whether the named module is present in the running
// kernel, by reading /proc/modules. It uses the FileTransport read on the
// agent path and a shell read otherwise, so it works on both transports.
func moduleLoaded(ctx context.Context, transport api.Transport, module string) (bool, error) {
	norm := normalizeModule(module)
	var content string
	if ft, ok := transport.(kernelio.FileTransport); ok {
		c, _, err := ft.ReadFileIfExists(procModules)
		if err != nil {
			return false, err
		}
		content = c
	} else {
		res, err := transport.Run(ctx, "cat /proc/modules 2>/dev/null")
		if err != nil {
			return false, err
		}
		content = res.Stdout
	}
	for _, line := range strings.Split(content, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == norm {
			return true, nil
		}
	}
	return false, nil
}

// reloadCmd re-inserts a module via modprobe, which resolves dependencies
// and module-image decompression. The rollback re-enable uses it (on both
// transports) rather than a raw kernel load, so Kensa does not reimplement
// the module loader for the rare re-enable case.
func reloadCmd(module string) string {
	return fmt.Sprintf("modprobe %s", shellEscape(module))
}

// reenable re-loads a module that was loaded at capture and verifies it is
// loaded again by reading /proc/modules back. A confirmed re-load is a
// clean success; a module that does not come back (in-use conflict,
// boot-time-only, or a load error) is a verified-partial restore with a
// remedy — never a silent success. The blacklist drop-in has already been
// restored/removed by the caller, so modprobe is no longer blocked by the
// install-/bin/true line.
func (h *Handler) reenable(ctx context.Context, transport api.Transport, path, module string, fileExisted bool) *api.RollbackResult {
	res, runErr := transport.Run(ctx, reloadCmd(module))
	loaded, verifyErr := moduleLoaded(ctx, transport, module)
	if verifyErr == nil && loaded {
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("kernel_module_disable: restored %s (file_existed=%v) and re-loaded %s, verified", path, fileExisted, module),
			ExecutedAt: time.Now().UTC(),
		}
	}
	detail := fmt.Sprintf("kernel_module_disable: restored %s (file_existed=%v) but module %s did not re-load; remedy: 'modprobe %s' or reboot", path, fileExisted, module, module)
	if runErr == nil && res != nil && !res.OK() {
		detail += fmt.Sprintf(" (modprobe exit %d)", res.ExitCode)
	}
	return &api.RollbackResult{
		Success:        false,
		PartialRestore: true,
		Detail:         detail,
		ExecutedAt:     time.Now().UTC(),
	}
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
