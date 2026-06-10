// Package auditruleset implements the audit_rule_set handler:
// write an audit rule to /etc/audit/rules.d/ and reload with
// augenrules --load. Capture records whether the rule file existed and
// its prior content for rollback.
// Spec: specs/handlers/audit_rule_set.spec.yaml.
package auditruleset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// mechanism is the canonical handler name.
const mechanism = "audit_rule_set"

// defaultRulesDir is the standard drop-in location for auditd rules.
const defaultRulesDir = "/etc/audit/rules.d"

// defaultPersistFile is the drop-in path used when the rule does not
// specify persist_file. CIS-style hardening conventionally lands managed
// audit rules in a single Kensa-owned drop-in.
const defaultPersistFile = defaultRulesDir + "/99-kensa.rules"

// Params is the decoded parameter struct for audit_rule_set.
type Params struct {
	// RuleFile is the absolute path of the drop-in file under
	// /etc/audit/rules.d/ to write (the schema "persist_file" key).
	// Optional in the contract; defaults to defaultPersistFile.
	RuleFile string
	// Rule is the complete audit rule line(s) to write. Required.
	Rule string
}

var errMissingRule = errors.New("audit_rule_set: params missing required 'rule'")

// decodeParams converts api.Params into the typed Params struct.
//
// Input keys follow CANONICAL_RULE_SCHEMA_V1.md §3.5.4: "rule" carries the
// audit rule text (required) and "persist_file" the absolute drop-in path
// (optional, defaulting to defaultPersistFile). The internal RuleFile field
// and the pre.Data["path"] capture key are unchanged so the capture/rollback
// round-trip stays byte-identical.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingRule
	}
	rule, ok := p["rule"].(string)
	if !ok || rule == "" {
		return nil, errMissingRule
	}
	persist := defaultPersistFile
	if v, ok := p["persist_file"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("audit_rule_set: 'persist_file' must be a non-empty string, got %T", v)
		}
		persist = s
	}
	return &Params{RuleFile: persist, Rule: rule}, nil
}

// Handler implements the audit_rule_set mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "audit_rule_set".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply writes the rule file to /etc/audit/rules.d/ and reloads
// the audit subsystem via `augenrules --load`. Idempotent: writing
// the same rule content twice is a no-op for augenrules.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	path := p.RuleFile
	content := "# Managed by Kensa.\n" + p.Rule + "\n"

	cmd := fmt.Sprintf(
		"printf '%%s' %s > %s && augenrules --load",
		shellEscape(content), shellEscape(path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("audit_rule_set: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("audit_rule_set: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("audit_rule_set: wrote %s and reloaded audit rules", path),
	}, nil
}

// Capture records whether the rule file existed and its prior content.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	path := p.RuleFile
	cmd := fmt.Sprintf(
		"test -e %[1]s && cat %[1]s || printf '__KENSA_ABSENT__'",
		shellEscape(path),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("audit_rule_set: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("audit_rule_set: capture failed for %s: %w (stderr: %s)",
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

// Rollback restores the prior rule file state and reloads augenrules.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("audit_rule_set: rollback called with nil pre-state")
	}
	path, _ := pre.Data["path"].(string)
	if path == "" {
		return nil, errors.New("audit_rule_set: pre-state missing 'path'")
	}
	fileExisted, _ := pre.Data["file_existed"].(bool)
	priorContent, _ := pre.Data["prior_content"].(string)

	var cmd string
	if fileExisted {
		cmd = fmt.Sprintf(
			"printf '%%s' %s > %s && augenrules --load",
			shellEscape(priorContent), shellEscape(path),
		)
	} else {
		cmd = fmt.Sprintf("rm -f %s && augenrules --load", shellEscape(path))
	}

	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("audit_rule_set: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("audit_rule_set: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("audit_rule_set: restored %s and reloaded audit rules (file_existed=%v)", path, fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
