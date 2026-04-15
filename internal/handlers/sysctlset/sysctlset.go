// Package sysctlset implements the sysctl_set handler: set a kernel
// parameter both at runtime (via sysctl -w) and persistently (via a
// drop-in file under /etc/sysctl.d/). Spec:
// specs/handlers/sysctl_set.spec.yaml.
package sysctlset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "sysctl_set"

// defaultPersistFile is the default drop-in location when the rule
// does not specify persist_file. CIS-style hardening conventionally
// uses 99-* for highest precedence.
const defaultPersistFile = "/etc/sysctl.d/99-kensa.conf"

// Params is the decoded parameter struct for the sysctl_set
// mechanism.
type Params struct {
	// Key is the sysctl parameter name (e.g. "net.ipv4.ip_forward"). Required.
	Key string
	// Value is the desired runtime value as a string (sysctl values
	// are string-typed at the syscall layer). Required.
	Value string
	// PersistFile is the drop-in path. Defaults to
	// /etc/sysctl.d/99-kensa.conf when empty.
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
	out := &Params{Key: key, Value: val, PersistFile: defaultPersistFile}
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
	content := fmt.Sprintf("# Managed by Kensa.\n%s = %s\n", p.Key, p.Value)
	persistCmd := fmt.Sprintf("printf %s > %s", shellEscape(content), shellEscape(p.PersistFile))
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
	persistContent := persistRes.Stdout
	persistExisted := true
	if persistContent == "__KENSA_ABSENT__" {
		persistContent = ""
		persistExisted = false
	}

	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"key":                  p.Key,
			"persist_file":         p.PersistFile,
			"runtime_value":        strings.TrimSpace(runtimeRes.Stdout),
			"persist_file_content": persistContent,
			"persist_file_existed": persistExisted,
		},
	}, nil
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

	// Restore persist layer first; the next sysctl -w then overrides
	// with the runtime value (which may differ from what's in the file
	// if the file used a different value than runtime at capture time).
	var persistCmd string
	if persistExisted {
		persistCmd = fmt.Sprintf("printf %s > %s", shellEscape(persistContent), shellEscape(persistFile))
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
