// Package auditruleset implements the audit_rule_set handler:
// write an audit rule to /etc/audit/rules.d/ and load it into the kernel.
// Capture records whether the rule file existed and its prior content for
// rollback. Spec: specs/handlers/audit_rule_set.spec.yaml.
//
// Dual path: when the transport implements auditnl.AuditTransport (agent
// mode with AUDIT netlink available) the handler loads each rule line into
// the running kernel via AUDIT_ADD_RULE and writes the drop-in atomically
// (fsatomic), instead of shelling out to augenrules. The netlink model is
// ADDITIVE per-rule (it loads this rule's lines into the kernel's flat
// rule list) rather than augenrules' whole-rules.d compile-and-load — so
// Capture records exactly which lines were NOT already loaded ("added_rules")
// and Rollback deletes only those, never a rule another drop-in owns.
// When netlink cannot be opened (no privilege / no audit, or an immutable
// audit config), the handler falls back to the augenrules shell path —
// which a host without netlink access behaves identically to before.
package auditruleset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
)

// mechanism is the canonical handler name.
const mechanism = "audit_rule_set"

// auditFileMode is the drop-in file mode (audit rule files are sensitive).
const auditFileMode = 0o640

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
	if at, ok := transport.(auditnl.AuditTransport); ok {
		res, err := h.applyNetlink(ctx, at, p)
		if !errors.Is(err, auditnl.ErrAuditUnavailable) {
			return res, err
		}
		// Netlink unavailable (no privilege / immutable audit) → shell.
	}
	return h.applyShell(ctx, transport, p)
}

// applyNetlink loads each rule line into the kernel via AUDIT_ADD_RULE and
// writes the drop-in atomically.
func (h *Handler) applyNetlink(ctx context.Context, at auditnl.AuditTransport, p *Params) (*api.StepResult, error) {
	c, err := at.AuditClient()
	if err != nil {
		return nil, err // ErrAuditUnavailable propagates for fallback
	}
	defer c.Close()

	for _, line := range auditnl.RuleLines(p.Rule) {
		wire, berr := auditnl.BuildRule(line)
		if berr != nil {
			// A malformed rule line is a non-compliant outcome, not a
			// transport error.
			return &api.StepResult{Success: false, Detail: fmt.Sprintf("audit_rule_set: %v", berr)}, nil
		}
		if aerr := c.AddRule(wire); aerr != nil && !errors.Is(aerr, unix.EEXIST) {
			return &api.StepResult{Success: false, Detail: fmt.Sprintf("audit_rule_set: load rule %q: %v", line, aerr)}, nil
		}
	}

	content := "# Managed by Kensa.\n" + p.Rule + "\n"
	if werr := at.AtomicReplace(ctx, p.RuleFile, auditFileMode, []byte(content)); werr != nil {
		return nil, fmt.Errorf("audit_rule_set: persist write: %w", werr)
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("audit_rule_set: loaded rules into kernel + wrote %s (netlink)", p.RuleFile),
	}, nil
}

// applyShell writes the drop-in and reloads via augenrules.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
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

// Capture records whether the rule file existed and its prior content,
// plus (on the netlink path) which of the rule's lines are NOT already
// loaded in the kernel — the set Rollback will unload.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if at, ok := transport.(auditnl.AuditTransport); ok {
		pre, err := h.captureNetlink(ctx, at, p)
		if !errors.Is(err, auditnl.ErrAuditUnavailable) {
			return pre, err
		}
		// Netlink unavailable → shell capture.
	}
	return h.captureShell(ctx, transport, p)
}

// captureNetlink records the file state and the added_rules set (rule
// lines not already loaded — by wire-format equality against the kernel's
// current rule list).
func (h *Handler) captureNetlink(ctx context.Context, at auditnl.AuditTransport, p *Params) (*api.PreState, error) {
	c, err := at.AuditClient()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	loaded, err := c.GetRules()
	if err != nil {
		return nil, fmt.Errorf("audit_rule_set: capture list rules: %w (%v)", api.ErrCaptureIncomplete, err)
	}
	var added []string
	for _, line := range auditnl.RuleLines(p.Rule) {
		wire, berr := auditnl.BuildRule(line)
		if berr != nil {
			return nil, fmt.Errorf("audit_rule_set: capture %w: %v", api.ErrCaptureIncomplete, berr)
		}
		if !containsWire(loaded, wire) {
			added = append(added, line) // we will add it → rollback unloads it
		}
	}

	content, existed, err := at.ReadFileIfExists(p.RuleFile)
	if err != nil {
		return nil, fmt.Errorf("audit_rule_set: capture read %s: %w (%v)", p.RuleFile, api.ErrCaptureIncomplete, err)
	}
	return h.preState(p, existed, content, added), nil
}

// captureShell records whether the rule file existed and its content.
func (h *Handler) captureShell(ctx context.Context, transport api.Transport, p *Params) (*api.PreState, error) {
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
	return h.preState(p, fileExisted, priorContent, nil), nil
}

// preState builds the canonical PreState. added is the netlink-path set of
// rule lines to unload on rollback; nil/empty on the shell path.
func (h *Handler) preState(p *Params, fileExisted bool, priorContent string, added []string) *api.PreState {
	data := map[string]interface{}{
		"path":          p.RuleFile,
		"file_existed":  fileExisted,
		"prior_content": priorContent,
	}
	if len(added) > 0 {
		data["added_rules"] = added
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data:       data,
	}
}

// containsWire reports whether want appears in the set of wire-format rules.
func containsWire(set [][]byte, want []byte) bool {
	for _, w := range set {
		if bytesEqual(w, want) {
			return true
		}
	}
	return false
}

// bytesEqual is a tiny dependency-free []byte compare (avoids importing
// bytes solely for this).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// addedRules coerces the pre-state added_rules value (which round-trips
// through JSON as []interface{} from the store, or stays []string
// in-process) into a []string.
func addedRules(v interface{}) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, e := range val {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Rollback restores the prior rule-file state and unloads the rules the
// Apply added (netlink path) or reloads augenrules (shell path).
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
	added := addedRules(pre.Data["added_rules"])

	if at, ok := transport.(auditnl.AuditTransport); ok {
		res, err := h.rollbackNetlink(ctx, at, path, fileExisted, priorContent, added)
		if !errors.Is(err, auditnl.ErrAuditUnavailable) {
			return res, err
		}
		// Netlink unavailable → shell rollback.
	}
	return h.rollbackShell(ctx, transport, path, fileExisted, priorContent)
}

// rollbackNetlink restores the drop-in atomically and unloads exactly the
// rule lines Apply added (added_rules) — never a rule another drop-in owns.
func (h *Handler) rollbackNetlink(ctx context.Context, at auditnl.AuditTransport, path string, fileExisted bool, priorContent string, added []string) (*api.RollbackResult, error) {
	// Restore persist layer first.
	if fileExisted {
		if err := at.AtomicReplace(ctx, path, auditFileMode, []byte(priorContent)); err != nil {
			return nil, fmt.Errorf("audit_rule_set: rollback persist write: %w", err)
		}
	} else if err := at.AtomicRemove(ctx, path); err != nil {
		return nil, fmt.Errorf("audit_rule_set: rollback persist remove: %w", err)
	}

	c, err := at.AuditClient()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	for _, line := range added {
		wire, berr := auditnl.BuildRule(line)
		if berr != nil {
			continue // unbuildable now but Apply built it; skip defensively
		}
		if derr := c.DeleteRule(wire); derr != nil && !errors.Is(derr, unix.ENOENT) {
			return &api.RollbackResult{
				Success:        false,
				PartialRestore: true,
				Detail:         fmt.Sprintf("audit_rule_set: file restored but unload of %q failed: %v", line, derr),
				ExecutedAt:     time.Now().UTC(),
			}, nil
		}
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("audit_rule_set: restored %s and unloaded %d rule(s) (netlink; file_existed=%v)", path, len(added), fileExisted),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell restores the drop-in and reloads augenrules.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, path string, fileExisted bool, priorContent string) (*api.RollbackResult, error) {
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
