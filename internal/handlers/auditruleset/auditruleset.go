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
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/shellcapture"
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

// auditStatusCmd reads the audit subsystem status. The shell rollback path
// uses it to detect an immutable configuration (enabled 2): when the kernel
// refuses all rule changes, augenrules cannot reconcile the live ruleset, so
// the file-only restore is reported as a verified-partial rather than a
// silent success.
const auditStatusCmd = "auditctl -s 2>/dev/null"

// auditImmutableShell reports whether the live audit configuration is
// immutable (auditctl -s prints "enabled 2"). A read-back error or an
// unparseable status is treated as not-immutable (best-effort): the goal is
// to flag the case we are certain about, not to over-alarm.
func auditImmutableShell(ctx context.Context, transport api.Transport) bool {
	res, err := transport.Run(ctx, auditStatusCmd)
	if err != nil || !res.OK() {
		return false
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "enabled" && f[1] == "2" {
			return true
		}
	}
	return false
}

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

	// Merge this rule's lines into the (possibly shared) drop-in rather than
	// overwriting it — the shared-file clobber fix. Preserves sibling rules
	// grouped into the same file by CIS convention.
	existing, _, rerr := at.ReadFileIfExists(p.RuleFile)
	if rerr != nil {
		return nil, fmt.Errorf("audit_rule_set: read %s for merge: %w", p.RuleFile, rerr)
	}
	merged, _ := mergeRuleLines(existing, auditnl.RuleLines(p.Rule))
	if werr := kernelio.WriteFile(ctx, at, p.RuleFile, auditFileMode, []byte(merged)); werr != nil {
		return nil, fmt.Errorf("audit_rule_set: persist write: %w", werr)
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("audit_rule_set: loaded rules into kernel + merged into %s (netlink)", p.RuleFile),
	}, nil
}

// applyShell merges the rule into the drop-in and reloads via augenrules. It
// reads the current file first so a rule sharing a CIS-grouped file (e.g.
// 50-privileged.rules) merges in rather than overwriting its siblings.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
	path := p.RuleFile

	existing, rerr := h.readFileShell(ctx, transport, path)
	if rerr != nil {
		return nil, rerr
	}
	merged, _ := mergeRuleLines(existing, auditnl.RuleLines(p.Rule))

	cmd := fmt.Sprintf(
		"printf '%%s' %s > %s && augenrules --load",
		shellEscape(merged), shellEscape(path),
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
		Detail:  fmt.Sprintf("audit_rule_set: merged into %s and reloaded audit rules", path),
	}, nil
}

// readFileShell returns the current content of path over the shell transport,
// or "" if the file does not exist.
func (h *Handler) readFileShell(ctx context.Context, transport api.Transport, path string) (string, error) {
	cmd := shellcapture.ExistenceReadCmd("-e", shellEscape(path), "__KENSA_ABSENT__")
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return "", fmt.Errorf("audit_rule_set: read %s: %w", path, err)
	}
	if !res.OK() {
		return "", fmt.Errorf("audit_rule_set: read %s failed (exit %d): %s", path, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	if res.Stdout == "__KENSA_ABSENT__" {
		return "", nil
	}
	// base64-decode to exact bytes so the shell rollback path (which re-reads and
	// removeRuleLines-rewrites this file) is byte-perfect (#247).
	content, decErr := shellcapture.DecodeContent(res.Stdout)
	if decErr != nil {
		return "", fmt.Errorf("audit_rule_set: decode %s: %w", path, decErr)
	}
	return content, nil
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
	// Which of this rule's lines are NOT already in the drop-in — the lines
	// Apply will add and Rollback must remove (leaving any sibling's lines).
	_, fileAdded := mergeRuleLines(content, auditnl.RuleLines(p.Rule))
	return h.preState(p, existed, content, added, fileAdded), nil
}

// captureShell records whether the rule file existed and its content.
func (h *Handler) captureShell(ctx context.Context, transport api.Transport, p *Params) (*api.PreState, error) {
	path := p.RuleFile
	cmd := shellcapture.ExistenceReadCmd("-e", shellEscape(path), "__KENSA_ABSENT__")
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
		// base64-decode to exact bytes (#247): keeps prior_content byte-identical
		// to the netlink path and byte-perfect for the shell rollback rewrite.
		priorContent, err = shellcapture.DecodeContent(res.Stdout)
		if err != nil {
			return nil, fmt.Errorf("audit_rule_set: capture decode failed for %s: %w", path, err)
		}
	}
	_, fileAdded := mergeRuleLines(priorContent, auditnl.RuleLines(p.Rule))
	return h.preState(p, fileExisted, priorContent, nil, fileAdded), nil
}

// preState builds the canonical PreState. added is the netlink-path set of
// rule lines to unload from the kernel on rollback (nil/empty on the shell
// path). fileAdded is the set of this rule's lines that were NOT already in the
// drop-in at capture — the lines rollback removes from the (possibly shared)
// file, so a sibling rule's line survives. prior_content / file_existed are
// retained as evidence; the file restore is line-based via fileAdded.
func (h *Handler) preState(p *Params, fileExisted bool, priorContent string, added, fileAdded []string) *api.PreState {
	data := map[string]interface{}{
		"path":          p.RuleFile,
		"file_existed":  fileExisted,
		"prior_content": priorContent,
	}
	if len(added) > 0 {
		data["added_rules"] = added
	}
	if len(fileAdded) > 0 {
		data["file_added_lines"] = fileAdded
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
	added := addedRules(pre.Data["added_rules"])
	fileAdded := addedRules(pre.Data["file_added_lines"])

	if at, ok := transport.(auditnl.AuditTransport); ok {
		res, err := h.rollbackNetlink(ctx, at, path, added, fileAdded)
		if !errors.Is(err, auditnl.ErrAuditUnavailable) {
			return res, err
		}
		// Netlink unavailable → shell rollback.
	}
	return h.rollbackShell(ctx, transport, path, fileAdded)
}

// rollbackNetlink restores the drop-in by removing exactly the lines Apply
// added to the file (fileAdded) — leaving any sibling rule's lines in a shared
// drop-in intact — and unloads exactly the rule lines Apply added to the kernel
// (added), never a rule another drop-in owns.
func (h *Handler) rollbackNetlink(ctx context.Context, at auditnl.AuditTransport, path string, added, fileAdded []string) (*api.RollbackResult, error) {
	// Restore persist layer first: strip only this rule's lines from the
	// current file. If no managed rule line remains, remove the file;
	// otherwise write the reduced content (preserving siblings).
	current, _, rerr := at.ReadFileIfExists(path)
	if rerr != nil {
		return nil, fmt.Errorf("audit_rule_set: rollback read %s: %w", path, rerr)
	}
	if reduced, remaining := removeRuleLines(current, fileAdded); remaining {
		if err := kernelio.WriteFile(ctx, at, path, auditFileMode, []byte(reduced)); err != nil {
			return nil, fmt.Errorf("audit_rule_set: rollback persist write: %w", err)
		}
	} else if err := kernelio.RemoveFile(ctx, at, path); err != nil {
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

	// Verify the unload took by reading the live rule list back and
	// confirming none of the rules we added are still loaded — a positive
	// read-back rather than trusting the delete return alone.
	if len(added) > 0 {
		loaded, gerr := c.GetRules()
		if gerr != nil {
			return &api.RollbackResult{
				Success:        false,
				PartialRestore: true,
				Detail:         fmt.Sprintf("audit_rule_set: restored %s but could not verify live rules: %v", path, gerr),
				ExecutedAt:     time.Now().UTC(),
			}, nil
		}
		for _, line := range added {
			wire, berr := auditnl.BuildRule(line)
			if berr != nil {
				continue
			}
			if containsWire(loaded, wire) {
				return &api.RollbackResult{
					Success:        false,
					PartialRestore: true,
					Detail:         fmt.Sprintf("audit_rule_set: file restored but rule %q still loaded after unload; remedy: reboot", line),
					ExecutedAt:     time.Now().UTC(),
				}, nil
			}
		}
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("audit_rule_set: restored %s (removed %d line(s)) and unloaded %d rule(s), verified (netlink)", path, len(fileAdded), len(added)),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell removes only this rule's lines from the drop-in (preserving
// siblings in a shared file), deleting the file if no managed rule remains,
// then reloads augenrules.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, path string, fileAdded []string) (*api.RollbackResult, error) {
	current, rerr := h.readFileShell(ctx, transport, path)
	if rerr != nil {
		return nil, rerr
	}
	var cmd string
	if reduced, remaining := removeRuleLines(current, fileAdded); remaining {
		cmd = fmt.Sprintf(
			"printf '%%s' %s > %s && augenrules --load",
			shellEscape(reduced), shellEscape(path),
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
	// augenrules --load exited cleanly, but on an immutable audit config
	// (enabled 2) the kernel silently refuses live rule changes — the file
	// is restored yet the running ruleset cannot be reconciled until reboot.
	// Report that honestly instead of a clean success.
	if auditImmutableShell(ctx, transport) {
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("audit_rule_set: restored %s but audit config is immutable (enabled 2); live ruleset unchanged until reboot", path),
			ExecutedAt:     time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("audit_rule_set: restored %s and reloaded audit rules", path),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
