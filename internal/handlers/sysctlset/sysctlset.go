// Package sysctlset implements the sysctl_set handler: set a kernel
// parameter both at runtime and persistently (via a drop-in file under
// /etc/sysctl.d/). Spec: specs/handlers/sysctl_set.spec.yaml.
//
// Dual path: when the transport implements kernelio.SysctlTransport
// (agent mode on the target host) the handler applies the runtime value
// by writing /proc/sys directly and the persist drop-in via the atomic
// file primitives — no sysctl(8)/shell. Otherwise it falls back to the
// `sysctl -w` + shell file-write path. The two paths write a
// byte-identical drop-in file and record an identical PreState shape, so
// capture/rollback are path-agnostic. Because the kernel-IO primitives
// are syscalls (always available in agent mode), the type assertion
// alone selects the path — there is no "primitive absent" fallback.
package sysctlset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// persistMode is the drop-in file mode (root-readable config).
const persistMode = 0o644

// persistContent renders the canonical drop-in body for a key/value, so
// the kernel-IO and shell paths write byte-identical files.
func persistContent(key, value string) string {
	return fmt.Sprintf("# Managed by Kensa.\n%s = %s\n", key, value)
}

// mechanism is the canonical handler name.
const mechanism = "sysctl_set"

// defaultPersistFile returns the default drop-in path for one sysctl key.
// Each key gets its OWN file so remediating several sysctl rules never
// clobbers a shared file (the whole-file writer would otherwise leave only
// the last key persisted — the rest set at runtime but lost on reboot) and
// rolling one rule back never disturbs another's persisted value. Because a
// file is owned by exactly one rule, capture/apply/rollback are byte-perfect
// and order-independent. 99-* keeps CIS-style highest precedence.
func defaultPersistFile(key string) string {
	return "/etc/sysctl.d/99-kensa-" + sanitizeKeyForFilename(key) + ".conf"
}

// sanitizeKeyForFilename maps a sysctl key to a safe filename component. Real
// sysctl keys are [a-z0-9._] (dot-separated), so this is a defensive no-op for
// them; it only rewrites characters that could otherwise escape the path.
func sanitizeKeyForFilename(key string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, key)
}

// Params is the decoded parameter struct for the sysctl_set
// mechanism.
type Params struct {
	// Key is the sysctl parameter name (e.g. "net.ipv4.ip_forward"). Required.
	Key string
	// Value is the desired runtime value as a string (sysctl values
	// are string-typed at the syscall layer). Required.
	Value string
	// PersistFile is the drop-in path. Defaults to a per-key file
	// /etc/sysctl.d/99-kensa-<key>.conf when empty (see defaultPersistFile).
	PersistFile string
}

// errMissingKey is returned when params lacks the required key.
var errMissingKey = errors.New("sysctl_set: params missing required 'key'")

// errMissingValue is returned when params lacks the required value.
var errMissingValue = errors.New("sysctl_set: params missing required 'value'")

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingKey
	}
	keyRaw, ok := p["key"]
	if !ok {
		return nil, errMissingKey
	}
	key, ok := keyRaw.(string)
	if !ok || key == "" {
		return nil, errMissingKey
	}
	valRaw, ok := p["value"]
	if !ok {
		return nil, errMissingValue
	}
	val, ok := valRaw.(string)
	if !ok {
		return nil, fmt.Errorf("sysctl_set: 'value' must be a string, got %T", valRaw)
	}
	out := &Params{Key: key, Value: val, PersistFile: defaultPersistFile(key)}
	if v, ok := p["persist_file"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("sysctl_set: 'persist_file' must be a non-empty string, got %T", v)
		}
		out.PersistFile = s
	}
	return out, nil
}

// Handler implements the sysctl_set mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "sysctl_set".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply sets the kernel parameter at runtime via `sysctl -w` and
// writes the persistent assignment to the drop-in file.
//
// Per handler-sysctl-set spec C-02 / AC-02, both operations are
// idempotent: sysctl -w with the same value is a no-op, and the
// drop-in writer overwrites the file with the canonical "key = value"
// form.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if k, ok := transport.(kernelio.SysctlTransport); ok {
		return h.applyKernel(ctx, k, p)
	}
	return h.applyShell(ctx, transport, p)
}

// applyKernel sets the runtime value via a direct /proc/sys write and
// writes the persist drop-in atomically. Runtime first: if the kernel
// rejects the value the write errors and we abort before touching the
// persist file (handler-sysctl-set spec AC-06).
func (h *Handler) applyKernel(_ context.Context, k kernelio.SysctlTransport, p *Params) (*api.StepResult, error) {
	if err := k.WriteSysctl(p.Key, p.Value); err != nil {
		// A rejected value (kernel EINVAL) is a non-compliant outcome,
		// not a transport failure — surface it as a failed step, mirroring
		// the shell path's non-zero sysctl -w exit.
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("sysctl_set: runtime apply failed: %v", err),
		}, nil
	}
	if err := kernelio.WriteFile(context.Background(), k, p.PersistFile, persistMode, []byte(persistContent(p.Key, p.Value))); err != nil {
		return nil, fmt.Errorf("sysctl_set: persist write failed: %w", err)
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("sysctl_set: %s=%s applied to runtime + %s (kernel-io)", p.Key, p.Value, p.PersistFile),
	}, nil
}

// applyShell sets the runtime value via `sysctl -w` and writes the
// persist drop-in via a shell redirect.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
	// Runtime first. If the kernel rejects the value, we abort before
	// touching the persist file (handler-sysctl-set spec AC-06).
	runtimeCmd := fmt.Sprintf("sysctl -w %s=%s", shellEscape(p.Key), shellEscape(p.Value))
	res, err := transport.Run(ctx, runtimeCmd)
	if err != nil {
		return nil, fmt.Errorf("sysctl_set: runtime apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("sysctl_set: runtime apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}

	// Persist. Atomically overwrite the file with a single canonical
	// "key = value\n" line, plus a header so future reviewers know
	// who wrote it.
	persistCmd := fmt.Sprintf("printf %s > %s", shellEscape(persistContent(p.Key, p.Value)), shellEscape(p.PersistFile))
	res, err = transport.Run(ctx, persistCmd)
	if err != nil {
		return nil, fmt.Errorf("sysctl_set: persist write transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("sysctl_set: persist write failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}

	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("sysctl_set: %s=%s applied to runtime + %s", p.Key, p.Value, p.PersistFile),
	}, nil
}

// Capture records the runtime value and the persist-file content.
//
// Per handler-sysctl-set spec AC-03, Capture distinguishes "file does
// not exist" from "file is empty" via a separate persist_file_existed
// boolean; rollback uses this to decide between rewrite-with-content
// and remove-the-file.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if k, ok := transport.(kernelio.SysctlTransport); ok {
		return h.captureKernel(k, p)
	}
	return h.captureShell(ctx, transport, p)
}

// captureKernel records the runtime value (direct /proc/sys read) and the
// persist-file content/existence (direct file read).
func (h *Handler) captureKernel(k kernelio.SysctlTransport, p *Params) (*api.PreState, error) {
	runtimeValue, err := k.ReadSysctl(p.Key)
	if err != nil {
		return nil, fmt.Errorf("sysctl_set: capture runtime failed for %s: %w (%v)",
			p.Key, api.ErrCaptureIncomplete, err)
	}
	content, existed, err := k.ReadFileIfExists(p.PersistFile)
	if err != nil {
		return nil, fmt.Errorf("sysctl_set: capture persist failed for %s: %w (%v)",
			p.PersistFile, api.ErrCaptureIncomplete, err)
	}
	return h.preState(p, runtimeValue, content, existed), nil
}

// captureShell records the runtime value and persist-file content via shell.
func (h *Handler) captureShell(ctx context.Context, transport api.Transport, p *Params) (*api.PreState, error) {
	// Runtime value via `sysctl -n` (no key prefix in output).
	runtimeRes, err := transport.Run(ctx, fmt.Sprintf("sysctl -n %s", shellEscape(p.Key)))
	if err != nil {
		return nil, fmt.Errorf("sysctl_set: capture runtime transport error: %w", err)
	}
	if !runtimeRes.OK() {
		return nil, fmt.Errorf("sysctl_set: capture runtime failed for %s: %w (stderr: %s)",
			p.Key, api.ErrCaptureIncomplete, strings.TrimSpace(runtimeRes.Stderr))
	}

	// Persist-file content: read with cat; check existence with test
	// -e first so we can distinguish absent-vs-empty.
	checkCmd := fmt.Sprintf("test -e %s && cat %s || printf '__KENSA_ABSENT__'", shellEscape(p.PersistFile), shellEscape(p.PersistFile))
	persistRes, err := transport.Run(ctx, checkCmd)
	if err != nil {
		return nil, fmt.Errorf("sysctl_set: capture persist transport error: %w", err)
	}
	content := persistRes.Stdout
	existed := true
	if content == "__KENSA_ABSENT__" {
		content = ""
		existed = false
	}
	return h.preState(p, strings.TrimSpace(runtimeRes.Stdout), content, existed), nil
}

// preState builds the canonical PreState shape used by both capture
// paths, so Rollback is path-agnostic.
func (h *Handler) preState(p *Params, runtimeValue, persistFileContent string, persistFileExisted bool) *api.PreState {
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"key":                  p.Key,
			"persist_file":         p.PersistFile,
			"runtime_value":        runtimeValue,
			"persist_file_content": persistFileContent,
			"persist_file_existed": persistFileExisted,
		},
	}
}

// Rollback restores the runtime value and the persist file from
// captured pre-state. Idempotent.
//
// Per handler-sysctl-set spec AC-04 / AC-05:
//   - persist_file_existed=true: rewrite the file with captured content.
//   - persist_file_existed=false: remove the file.
//   - runtime: always re-apply via `sysctl -w` from the captured runtime value.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("sysctl_set: rollback called with nil pre-state")
	}
	key, _ := pre.Data["key"].(string)
	persistFile, _ := pre.Data["persist_file"].(string)
	runtimeValue, _ := pre.Data["runtime_value"].(string)
	persistContent, _ := pre.Data["persist_file_content"].(string)
	persistExisted, _ := pre.Data["persist_file_existed"].(bool)

	if key == "" || persistFile == "" {
		return nil, fmt.Errorf("sysctl_set: pre-state missing 'key' or 'persist_file'")
	}

	if k, ok := transport.(kernelio.SysctlTransport); ok {
		return h.rollbackKernel(k, key, persistFile, runtimeValue, persistContent, persistExisted)
	}
	return h.rollbackShell(ctx, transport, key, persistFile, runtimeValue, persistContent, persistExisted)
}

// rollbackKernel restores the persist drop-in (atomic rewrite or remove)
// and the runtime value (direct /proc/sys write).
func (h *Handler) rollbackKernel(k kernelio.SysctlTransport, key, persistFile, runtimeValue, persistFileContent string, persistFileExisted bool) (*api.RollbackResult, error) {
	// Restore persist layer first; the runtime write then sets the
	// captured runtime value (which may differ from the file's value).
	if persistFileExisted {
		if err := kernelio.WriteFile(context.Background(), k, persistFile, persistMode, []byte(persistFileContent)); err != nil {
			return nil, fmt.Errorf("sysctl_set: rollback persist write failed: %w", err)
		}
	} else if err := kernelio.RemoveFile(context.Background(), k, persistFile); err != nil {
		return nil, fmt.Errorf("sysctl_set: rollback persist remove failed: %w", err)
	}
	if err := k.WriteSysctl(key, runtimeValue); err != nil {
		// Persist already restored; runtime failed → PartialRestore.
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("sysctl_set: persist restored but runtime restore failed: %v", err),
			ExecutedAt:     time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("sysctl_set: restored %s=%s and %s (kernel-io)", key, runtimeValue, persistFile),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell restores the persist file and runtime value via shell.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, key, persistFile, runtimeValue, persistFileContent string, persistFileExisted bool) (*api.RollbackResult, error) {
	// Restore persist layer first; the next sysctl -w then overrides
	// with the runtime value (which may differ from what's in the file
	// if the file used a different value than runtime at capture time).
	var persistCmd string
	if persistFileExisted {
		persistCmd = fmt.Sprintf("printf %s > %s", shellEscape(persistFileContent), shellEscape(persistFile))
	} else {
		persistCmd = fmt.Sprintf("rm -f %s", shellEscape(persistFile))
	}
	if res, err := transport.Run(ctx, persistCmd); err != nil {
		return nil, fmt.Errorf("sysctl_set: rollback persist transport error: %w", err)
	} else if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("sysctl_set: rollback persist failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	// Restore runtime.
	runtimeCmd := fmt.Sprintf("sysctl -w %s=%s", shellEscape(key), shellEscape(runtimeValue))
	if res, err := transport.Run(ctx, runtimeCmd); err != nil {
		return nil, fmt.Errorf("sysctl_set: rollback runtime transport error: %w", err)
	} else if !res.OK() {
		// Persist already restored; runtime failed. Surface as
		// PartialRestore so the operator knows to investigate.
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("sysctl_set: persist restored but runtime restore failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt:     time.Now().UTC(),
		}, nil
	}

	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("sysctl_set: restored %s=%s and %s", key, runtimeValue, persistFile),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
