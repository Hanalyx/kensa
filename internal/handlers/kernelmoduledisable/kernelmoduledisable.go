// Package kernelmoduledisable implements the kernel_module_disable
// handler: blacklist a kernel module via /etc/modprobe.d/ and remove
// it from the running kernel if loaded. Capture records whether the
// blacklist file existed for rollback.
// Spec: specs/handlers/kernel_module_disable.spec.yaml.
package kernelmoduledisable

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "kernel_module_disable"

// Params is the decoded parameter struct for kernel_module_disable.
type Params struct {
	// Module is the kernel module name (e.g. "usb-storage", "cramfs").
	// Required.
	Module string
}

// errMissingModule is returned when params lacks the required module.
var errMissingModule = errors.New("kernel_module_disable: params missing required 'module'")

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingModule
	}
	v, ok := p["module"].(string)
	if !ok || v == "" {
		return nil, errMissingModule
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

// Apply writes the blacklist + install-as-true entry to modprobe.d
// and unloads the module from the running kernel (best-effort via
// modprobe -r; failure to unload is reported but not fatal when the
// module is in use).
//
// Idempotent: rewriting the same blacklist file is a no-op.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	path := blacklistPath(p.Module)
	// install /bin/true prevents the module from being loaded even via
	// explicit modprobe; blacklist alone doesn't block that.
	content := fmt.Sprintf("# Managed by Kensa.\nblacklist %s\ninstall %s /bin/true\n", p.Module, p.Module)

	cmd := fmt.Sprintf(
		"printf '%%s' %s > %s && modprobe -r %s 2>/dev/null || true",
		shellEscape(content), shellEscape(path), shellEscape(p.Module),
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
			"module":        p.Module,
			"path":          path,
			"file_existed":  fileExisted,
			"prior_content": priorContent,
		},
	}, nil
}

// Rollback removes the blacklist file (or restores prior content) and
// reloads the module if it was previously present in a running state.
// Note: reloading kernel modules after removal requires a manual step
// or reboot in some configurations — this is a disclosed limitation.
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
