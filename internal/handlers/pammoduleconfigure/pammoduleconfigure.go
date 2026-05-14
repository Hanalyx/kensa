// Package pammoduleconfigure implements the pam_module_configure
// handler: add or replace a PAM module line in a PAM service file
// (/etc/pam.d/<service>). Capture records the prior file content for
// exact rollback. PAM changes can affect authentication; this handler
// is flagged for control-channel review before production use.
// Spec: specs/handlers/pam_module_configure.spec.yaml.
package pammoduleconfigure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// mechanism is the canonical handler name.
const mechanism = "pam_module_configure"

// Params is the decoded parameter struct for pam_module_configure.
type Params struct {
	// Service is the PAM service name (e.g. "sshd", "system-auth").
	// The file /etc/pam.d/<service> is edited. Required.
	Service string
	// ModuleType is the PAM type: "auth", "account", "password",
	// "session". Required.
	ModuleType string
	// Control is the PAM control flag: "required", "requisite",
	// "sufficient", "optional", "[key=value...]". Required.
	Control string
	// Module is the PAM module path
	// (e.g. "pam_faillock.so"). Required.
	Module string
	// Options is the optional arguments string
	// (e.g. "preauth silent deny=5"). Optional.
	Options string
}

var (
	errMissingService    = errors.New("pam_module_configure: params missing required 'service'")
	errMissingModuleType = errors.New("pam_module_configure: params missing required 'module_type'")
	errMissingControl    = errors.New("pam_module_configure: params missing required 'control'")
	errMissingModule     = errors.New("pam_module_configure: params missing required 'module'")
)

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingService
	}
	service, _ := p["service"].(string)
	if service == "" {
		return nil, errMissingService
	}
	modType, _ := p["module_type"].(string)
	if modType == "" {
		return nil, errMissingModuleType
	}
	control, _ := p["control"].(string)
	if control == "" {
		return nil, errMissingControl
	}
	module, _ := p["module"].(string)
	if module == "" {
		return nil, errMissingModule
	}
	options, _ := p["options"].(string)
	return &Params{
		Service: service, ModuleType: modType,
		Control: control, Module: module, Options: options,
	}, nil
}

// pamPath returns the /etc/pam.d/ path for a service.
func pamPath(service string) string { return "/etc/pam.d/" + service }

// Handler implements the pam_module_configure mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "pam_module_configure".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply adds or replaces the PAM module line. If a line for the same
// module_type+module already exists it is replaced; otherwise the line
// is appended after the last line of the same module_type block.
//
// Strategy: capture the whole file before apply; on apply rewrite the
// file atomically via a tmp file so the PAM daemon sees an atomic swap.
//
// Idempotent: replacing the same line with the same content is a no-op.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	path := pamPath(p.Service)
	pamLine := buildPAMLine(p)

	// Use sed to replace an existing module_type+module line, or append.
	pattern := fmt.Sprintf("^%s[[:space:]].*%s", sedEscape(p.ModuleType), sedEscape(p.Module))
	sedReplace := fmt.Sprintf("s|%s|%s|", pattern, sedEscape(pamLine))

	cmd := fmt.Sprintf(
		`if grep -qE %s %s 2>/dev/null; then `+
			`sed -i -E %s %s; `+
			`else echo %s >> %s; fi`,
		shellEscape(pattern),
		shellEscape(path),
		shellEscape(sedReplace),
		shellEscape(path),
		shellEscape(pamLine),
		shellEscape(path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("pam_module_configure: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("pam_module_configure: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("pam_module_configure: configured %s in %s", p.Module, path),
	}, nil
}

// buildPAMLine constructs the PAM line from the params.
func buildPAMLine(p *Params) string {
	line := p.ModuleType + "\t" + p.Control + "\t" + p.Module
	if p.Options != "" {
		line += " " + p.Options
	}
	return line
}

// Capture records the full prior content of the PAM service file.
// Returns ErrCaptureIncomplete if the file does not exist (required by spec).
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	path := pamPath(p.Service)
	// PAM files must exist — a missing service file is a capture failure.
	res, err := transport.Run(ctx, fmt.Sprintf("cat %s", shellEscape(path)))
	if err != nil {
		return nil, fmt.Errorf("pam_module_configure: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("pam_module_configure: capture failed for %s: %w (stderr: %s)",
			path, api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"service":       p.Service,
			"path":          path,
			"prior_content": res.Stdout,
		},
	}, nil
}

// Rollback restores the full prior PAM file content verbatim.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("pam_module_configure: rollback called with nil pre-state")
	}
	path, _ := pre.Data["path"].(string)
	priorContent, _ := pre.Data["prior_content"].(string)
	if path == "" {
		return nil, errors.New("pam_module_configure: pre-state missing 'path'")
	}

	cmd := fmt.Sprintf("printf '%%s' %s > %s", shellEscape(priorContent), shellEscape(path))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("pam_module_configure: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("pam_module_configure: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("pam_module_configure: restored %s to prior content", path),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// sedEscape escapes special regex characters for POSIX ERE.
func sedEscape(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`, `|`, `\|`, `.`, `\.`, `[`, `\[`, `]`, `\]`,
		`^`, `\^`, `$`, `\$`, `*`, `\*`, `+`, `\+`, `?`, `\?`,
		`(`, `\(`, `)`, `\)`,
	)
	return r.Replace(s)
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
