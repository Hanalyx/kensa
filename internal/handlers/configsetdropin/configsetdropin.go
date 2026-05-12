// Package configsetdropin implements the config_set_dropin handler:
// write a single-key drop-in configuration file to a specified path.
// Capture records whether the file existed and its prior content for
// rollback. Spec: specs/handlers/config_set_dropin.spec.yaml.
package configsetdropin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "config_set_dropin"

// Params is the decoded parameter struct for config_set_dropin.
type Params struct {
	// Path is the absolute drop-in file path. Required.
	Path string
	// Key is the configuration key. Required.
	Key string
	// Value is the desired value. Required.
	Value string
	// Separator is the key-value separator. Defaults to "=".
	Separator string
}

var (
	errMissingPath  = errors.New("config_set_dropin: params missing required 'path'")
	errMissingKey   = errors.New("config_set_dropin: params missing required 'key'")
	errMissingValue = errors.New("config_set_dropin: params missing required 'value'")
)

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingPath
	}
	path, ok := p["path"].(string)
	if !ok || path == "" {
		return nil, errMissingPath
	}
	key, ok := p["key"].(string)
	if !ok || key == "" {
		return nil, errMissingKey
	}
	value, ok := p["value"].(string)
	if !ok {
		return nil, errMissingValue
	}
	sep := "="
	if v, ok := p["separator"]; ok {
		s, _ := v.(string)
		if s != "" {
			sep = s
		}
	}
	return &Params{Path: path, Key: key, Value: value, Separator: sep}, nil
}

// Handler implements the config_set_dropin mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "config_set_dropin".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply writes a complete drop-in file containing a Kensa header and
// the key-value pair. Creates the parent directory if needed.
// Idempotent per spec C-01.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	content := fmt.Sprintf("# Managed by Kensa.\n%s%s%s\n", p.Key, p.Separator, p.Value)

	// Ensure the parent directory exists, then atomically write the file.
	cmd := fmt.Sprintf(
		"mkdir -p %s && printf '%%s' %s > %s",
		shellEscape(parentDir(p.Path)),
		shellEscape(content),
		shellEscape(p.Path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("config_set_dropin: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("config_set_dropin: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("config_set_dropin: wrote %s%s%s to %s", p.Key, p.Separator, p.Value, p.Path),
	}, nil
}

// Capture records file_existed and prior_content. An absent file is
// a valid capture result (file_existed=false).
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	cmd := fmt.Sprintf(
		"test -e %[1]s && cat %[1]s || printf '__KENSA_ABSENT__'",
		shellEscape(p.Path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("config_set_dropin: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("config_set_dropin: capture failed for %s: %w (stderr: %s)",
			p.Path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}

	stdout := res.Stdout
	if stdout == "__KENSA_ABSENT__" {
		return &api.PreState{
			Mechanism:  mechanism,
			Capturable: true,
			CapturedAt: time.Now().UTC(),
			Data: map[string]interface{}{
				"path":          p.Path,
				"file_existed":  false,
				"prior_content": "",
			},
		}, nil
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"path":          p.Path,
			"file_existed":  true,
			"prior_content": stdout,
		},
	}, nil
}

// Rollback restores the prior drop-in file state per spec C-03.
// When file_existed=true, the file is rewritten with prior_content.
// When file_existed=false, the drop-in file is removed.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("config_set_dropin: rollback called with nil pre-state")
	}
	path, _ := pre.Data["path"].(string)
	if path == "" {
		return nil, errors.New("config_set_dropin: pre-state missing 'path'")
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
		return nil, fmt.Errorf("config_set_dropin: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("config_set_dropin: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("config_set_dropin: restored %s (file_existed=%v)", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// parentDir returns the directory component of a path.
func parentDir(path string) string {
	idx := strings.LastIndexByte(path, '/')
	if idx <= 0 {
		return "/"
	}
	return path[:idx]
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
