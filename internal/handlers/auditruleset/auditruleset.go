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
	"github.com/Hanalyx/kensa/internal/check"
	"github.com/Hanalyx/kensa/internal/prestate"
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

// auditRulesScanCmd emits every watch/syscall rule LINE in the files augenrules
// compiles and loads at reboot: each *.rules file in /etc/audit/rules.d,
// followed through a symlink as augenrules reads it. The conflict guard
// compares a to-be-written rule against these (not just the live ruleset) so
// it also catches an unloaded pre-existing duplicate and a sibling staged to
// another file earlier in the same run. The pattern takes a flag written
// against its argument (-w/etc/x, -Aexit,always), which auditctl accepts.
// A rules.d directory that does not exist holds no rules and exits 0, but
// only when /etc/audit itself can be searched: otherwise the directory may
// exist unseen, and the scan exits 2. A rules.d the reader cannot list or
// search exits 2 too, since an unexpanded glob would read as no files. grep's exit 1 (no rule lines) is an
// empty scan; anything else, such as exit 2 for a file the reader cannot
// open, is returned so the guard refuses rather than skipping the scan.
const auditRulesScanCmd = "if [ ! -d " + defaultRulesDir + " ]; then [ -x /etc/audit ] && exit 0; exit 2; fi; " +
	"[ -r " + defaultRulesDir + " ] && [ -x " + defaultRulesDir + " ] || exit 2; " +
	"set -- " + defaultRulesDir + "/*.rules; [ -e \"$1\" ] || [ -L \"$1\" ] || exit 0; " +
	"grep -hE '^[[:space:]]*-(w|a|A)' \"$@\"; rc=$?; [ $rc -le 1 ] && exit 0; exit $rc"

// auditListCmd lists the loaded rules as auditctl prints them.
const auditListCmd = "auditctl -l"

// auditImmutableShell reports whether the live audit configuration is
// immutable (auditctl -s prints "enabled 2"). A read-back error or an
// unparseable status is treated as not-immutable (best-effort). Apply and
// Capture use it to choose the staged path; rollback uses
// auditStatusShell, which reports the read error.
func auditImmutableShell(ctx context.Context, transport api.Transport) bool {
	immutable, _ := auditStatusShell(ctx, transport)
	return immutable
}

// auditStatusShell reads whether the live audit configuration is immutable.
// A transport error, a non-zero exit, or output with no "enabled" line is
// an error: the caller cannot tell.
func auditStatusShell(ctx context.Context, transport api.Transport) (bool, error) {
	res, err := transport.Run(ctx, auditStatusCmd)
	if err != nil {
		return false, err
	}
	if !res.OK() {
		return false, fmt.Errorf("auditctl -s exited %d", res.ExitCode)
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "enabled" {
			return f[1] == "2", nil
		}
	}
	return false, errors.New("auditctl -s printed no enabled line")
}

// auditListShell reads the loaded rules with auditctl -l. A transport error,
// a non-zero exit, or no output at all is an error, never an empty listing:
// auditctl prints "No rules" when none are loaded.
func auditListShell(ctx context.Context, transport api.Transport) ([]string, error) {
	res, err := transport.Run(ctx, auditListCmd)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, fmt.Errorf("auditctl -l exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	if strings.TrimSpace(res.Stdout) == "" {
		return nil, errors.New("auditctl -l printed nothing")
	}
	return strings.Split(res.Stdout, "\n"), nil
}

// stagedImmutableDirective reports whether lines hold the -e 2 control line,
// which makes the audit configuration immutable when auditd loads it at boot.
func stagedImmutableDirective(lines []string) bool {
	for _, l := range lines {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "-e" && f[1] == "2" {
			return true
		}
	}
	return false
}

// stagedVerdict is the result of a staged rollback once the drop-in is
// restored. The host may have rebooted after Apply, so auditd may have
// loaded a staged rule, or set the immutable flag from a staged -e 2, and
// neither can be undone until the next boot. listed is the loaded ruleset
// and listErr the error reading it. bootImmutable reports whether a staged
// -e 2 took effect, and bootErr the error reading that. Any read error is a
// partial restore that names what could not be read: the restore is never
// reported clean unless the live state shows it.
func stagedVerdict(ctx context.Context, transport api.Transport, path string, fileAdded, listed []string, listErr error, bootImmutable bool, bootErr error, via string) *api.RollbackResult {
	partial := func(format string, a ...interface{}) *api.RollbackResult {
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("audit_rule_set: removed staged drop-in %s, but ", path) + fmt.Sprintf(format, a...),
			ExecutedAt:     time.Now().UTC(),
		}
	}
	if bootErr != nil {
		return partial("the audit status could not be read, so whether the staged -e 2 took effect at boot is unknown: %v (%s)", bootErr, via)
	}
	if bootImmutable {
		return partial("the staged -e 2 made the audit config immutable at boot (host rebooted before rollback); it clears on next reboot (%s)", via)
	}
	if l := unshowableLine(fileAdded); l != "" {
		return partial("whether the staged control line %q took effect at a boot cannot be shown from the rule listing (%s)", l, via)
	}
	if listErr != nil {
		return partial("the loaded audit rules could not be read, so whether the host rebooted and loaded the staged rule is unknown: %v (%s)", listErr, via)
	}
	line, id, why, err := check.AuditLoadedAmong(ctx, transport, fileAdded, listed, via == "netlink")
	switch {
	case err != nil:
		return partial("whether the staged rule is loaded could not be read: %v (%s)", err, via)
	case id == check.AuditSame:
		return partial("the rule %q is loaded in the running kernel (host rebooted before rollback); this rollback does not unload a staged rule, and it clears on next reboot (%s)", line, via)
	case id == check.AuditUnresolved:
		return partial("a loaded rule may be the staged rule %q (%s), so the host may have loaded it at boot; runtime clears on next reboot (%s)", line, why, via)
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("audit_rule_set: restored %s (removed %d staged line(s)); no staged rule loaded (%s)", path, len(fileAdded), via),
		ExecutedAt: time.Now().UTC(),
	}
}

// Params is the decoded parameter struct for audit_rule_set.
type Params struct {
	// RuleFile is the absolute path of the drop-in file under
	// /etc/audit/rules.d/ to write (the schema "persist_file" key).
	// Optional in the contract; defaults to defaultPersistFile.
	RuleFile string
	// Rule is the complete audit rule line(s) to write. Required.
	Rule string
	// PersistOnly writes the drop-in and deliberately does NOT load into the
	// running kernel, terminating the transaction StatusStaged (PENDING
	// reboot).
	//
	// It exists for audit CONTROL directives rather than rules. `-e 2` makes
	// the audit configuration immutable: loading it blocks every later audit
	// change on that host until reboot, and no rollback can undo it, because
	// restoring the drop-in does not clear the kernel flag. Applying it at
	// runtime would therefore break the capture/rollback contract the engine
	// relies on. Persisting it and reporting PENDING reboot keeps that contract
	// and still converges the host at its next boot.
	//
	// This is the same shape as the immutable-host case below, declared by the
	// rule instead of detected from host state.
	PersistOnly bool
}

var errMissingRule = errors.New("audit_rule_set: params missing required 'rule'")

// decodeParams converts api.Params into the typed Params struct.
//
// Input keys follow the mechanism param contract (internal/mechanism):
// "rule" carries the
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
	persistOnly := false
	if v, ok := p["persist_only"]; ok {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("audit_rule_set: 'persist_only' must be a boolean, got %T", v)
		}
		persistOnly = b
	}
	return &Params{RuleFile: persist, Rule: rule, PersistOnly: persistOnly}, nil
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
	// Conflict guard: refuse to write a line that builds the same kernel rule,
	// key included, as a line already in some rules.d file, or one it cannot
	// show to be different. The duplicate collides at load ("Rule exists")
	// and aborts the audit ruleset load, which drops immutability at the next
	// reboot. Per the detect-the-conflict-don't-silently-apply contract,
	// surface it and stop; reconciling the existing rule is the operator's
	// decision, not Kensa's.
	if res := h.guardConflict(ctx, transport, p); res != nil {
		return res, nil
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

// guardConflict returns a non-nil, Success=false StepResult when applying this
// rule could introduce a duplicate audit rule: a line this apply adds builds,
// on this host, the same kernel rule as a line already in some rules.d file
// (check.AuditRuleIdentity). At the next reboot augenrules would load both,
// the kernel would answer "Rule exists", and the load would abort and drop
// immutability. A pair the predicate cannot show to be distinct, because a
// fact it needs is not known, is refused the same way.
//
// Lines the same apply adds are compared with each other as well, since a
// rule whose own lines alias each other would collide the same way.
//
// The guard fails closed. When the target drop-in, the rules.d scan or the
// host facts the comparison depends on cannot be read, it refuses: an apply
// that cannot show it is not writing a duplicate does not write.
func (h *Handler) guardConflict(ctx context.Context, transport api.Transport, p *Params) *api.StepResult {
	refuse := func(format string, a ...interface{}) *api.StepResult {
		return &api.StepResult{Success: false, Detail: "audit_rule_set: not applied: " + fmt.Sprintf(format, a...)}
	}
	existing, err := h.readFileShell(ctx, transport, p.RuleFile)
	if err != nil {
		return refuse("cannot read %s to check for a duplicate rule: %v", p.RuleFile, err)
	}
	// Only lines NOT already in this drop-in can introduce a NEW duplicate;
	// re-applying our own file is idempotent, not a conflict.
	_, fileAdded := mergeRuleLines(existing, auditnl.RuleLines(p.Rule))
	if len(fileAdded) == 0 {
		return nil
	}
	res, rerr := transport.Run(ctx, auditRulesScanCmd)
	if rerr != nil {
		return refuse("cannot read %s to check for a duplicate rule: %v", defaultRulesDir, rerr)
	}
	if !res.OK() {
		return refuse("cannot read %s to check for a duplicate rule (exit %d): %s", defaultRulesDir,
			res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	var onDisk []string
	for _, l := range strings.Split(res.Stdout, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			onDisk = append(onDisk, l)
		}
	}
	if len(onDisk) == 0 && len(fileAdded) < 2 {
		return nil
	}
	target, terr := check.ReadAuditTarget(ctx, transport, append(append([]string{}, fileAdded...), onDisk...))
	if terr != nil {
		return refuse("cannot read the host facts needed to compare audit rules: %v", terr)
	}
	for _, line := range fileAdded {
		for _, d := range onDisk {
			switch id, why := check.AuditRuleIdentity(line, d, target); id {
			case check.AuditSame:
				return refuse("conflict — %q builds the same kernel rule as %q already in %s; writing it to %s "+
					"would duplicate it and abort the audit load at reboot (reconcile the existing rule or accept "+
					"it as satisfying the control)", line, d, defaultRulesDir, p.RuleFile)
			case check.AuditUnresolved:
				return refuse("cannot show that %q and %q in %s are different kernel rules (%s); a duplicate would "+
					"abort the audit load at reboot", line, d, defaultRulesDir, why)
			}
		}
	}
	// Two lines this apply adds can also be one kernel rule, written two ways.
	for i, a := range fileAdded {
		for _, b := range fileAdded[i+1:] {
			switch id, why := check.AuditRuleIdentity(a, b, target); id {
			case check.AuditSame:
				return refuse("conflict — %q and %q in this rule build the same kernel rule; writing both to %s "+
					"would abort the audit load at reboot", a, b, p.RuleFile)
			case check.AuditUnresolved:
				return refuse("cannot show that %q and %q in this rule are different kernel rules (%s); a "+
					"duplicate would abort the audit load at reboot", a, b, why)
			}
		}
	}
	return nil
}

// applyNetlink loads each rule line into the kernel via AUDIT_ADD_RULE and
// writes the drop-in atomically.
func (h *Handler) applyNetlink(ctx context.Context, at auditnl.AuditTransport, p *Params) (*api.StepResult, error) {
	c, err := at.AuditClient()
	if err != nil {
		return nil, err // ErrAuditUnavailable propagates for fallback
	}
	defer c.Close()

	// Immutable audit config (enabled 2): the kernel refuses all runtime rule
	// loads until reboot. Positively detect it BEFORE attempting AddRule (which
	// would EPERM), stage the persist layer, and defer convergence to reboot.
	// The drop-in is fully captured, so rollback stays byte-perfect. A status
	// read error is non-fatal here: fall through to the normal load path, whose
	// AddRule failure is surfaced as a non-compliant StepResult.
	if p.PersistOnly {
		return h.stagePersistNetlink(ctx, at, p)
	}
	if enabled, serr := c.GetStatus(); serr == nil && enabled == 2 {
		return h.stagePersistNetlink(ctx, at, p)
	}

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

// stagePersistNetlink merges the rule into the (possibly shared) drop-in and
// returns a Staged step result WITHOUT loading into the kernel — used when the
// audit config is immutable (enabled 2). The engine terminates such a
// transaction StatusStaged: the persist change takes effect on reboot, and the
// runtime ruleset is intentionally left unchanged (it cannot be changed until
// reboot anyway). Rollback removes exactly these lines from captured pre-state.
func (h *Handler) stagePersistNetlink(ctx context.Context, at auditnl.AuditTransport, p *Params) (*api.StepResult, error) {
	existing, _, rerr := at.ReadFileIfExists(p.RuleFile)
	if rerr != nil {
		return nil, fmt.Errorf("audit_rule_set: read %s for staged merge: %w", p.RuleFile, rerr)
	}
	merged, _ := mergeRuleLines(existing, auditnl.RuleLines(p.Rule))
	if werr := kernelio.WriteFile(ctx, at, p.RuleFile, auditFileMode, []byte(merged)); werr != nil {
		return nil, fmt.Errorf("audit_rule_set: staged persist write: %w", werr)
	}
	reason := "audit config immutable (enabled 2)"
	if p.PersistOnly {
		reason = "persist_only directive, never loaded at runtime"
	}
	return &api.StepResult{
		Success: true,
		Staged:  true,
		Detail:  fmt.Sprintf("audit_rule_set: %s; staged into %s, PENDING reboot to load (netlink)", reason, p.RuleFile),
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

	// Immutable audit config (enabled 2): the kernel refuses runtime loads
	// until reboot, so stage the persist layer and defer convergence. The file
	// write is gated with && so a write failure still surfaces; augenrules
	// --load is run (to regenerate the compiled /etc/audit/audit.rules for a
	// consistent reboot) but its exit is tolerated, because on an immutable
	// host the load sub-step is expected to no-op.
	// persist_only: write the drop-in and do not load. Running augenrules here
	// would compile and load the directive, which is the thing this flag exists
	// to avoid.
	if p.PersistOnly {
		cmd := fmt.Sprintf("printf '%%s' %s > %s", shellEscape(merged), shellEscape(path))
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("audit_rule_set: persist_only write transport error: %w", err)
		}
		if !res.OK() {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("audit_rule_set: persist_only write failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			}, nil
		}
		return &api.StepResult{
			Success: true,
			Staged:  true,
			Detail:  fmt.Sprintf("audit_rule_set: persist_only directive, never loaded at runtime; staged into %s, PENDING reboot to load (shell)", path),
		}, nil
	}

	if auditImmutableShell(ctx, transport) {
		cmd := fmt.Sprintf(
			"printf '%%s' %s > %s && { augenrules --load >/dev/null 2>&1 || true; }",
			shellEscape(merged), shellEscape(path),
		)
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("audit_rule_set: staged apply transport error: %w", err)
		}
		if !res.OK() {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("audit_rule_set: staged persist write failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			}, nil
		}
		return &api.StepResult{
			Success: true,
			Staged:  true,
			Detail:  fmt.Sprintf("audit_rule_set: audit config immutable (enabled 2); staged into %s, PENDING reboot to load (shell)", path),
		}, nil
	}

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
	// When the audit config is immutable (enabled 2), Apply will STAGE the rule
	// (write the drop-in, load nothing) — so Rollback has nothing to unload.
	// Recording added_rules from "not currently loaded" here would make Rollback
	// call DeleteRule on a rule that was never loaded; an immutable kernel
	// rejects that unload with EPERM (only ENOENT is tolerated), falsely
	// reporting a partial restore of a host that is byte-perfect. Record an
	// empty unload set and mark the pre-state staged.
	immutableStaged := false
	if enabled, serr := c.GetStatus(); serr == nil && enabled == 2 {
		immutableStaged = true
	}
	// A persist_only directive is never loaded, so there is nothing for
	// Rollback to unload. Skip the wire build entirely: its text is a control
	// directive (`-e 2`), not a rule, and BuildRule cannot parse one — which
	// would fail capture and, correctly but unhelpfully, refuse the whole
	// remediation.
	staged := immutableStaged || p.PersistOnly
	var added []string
	if !staged {
		for _, line := range auditnl.RuleLines(p.Rule) {
			wire, berr := auditnl.BuildRule(line)
			if berr != nil {
				return nil, fmt.Errorf("audit_rule_set: capture %w: %v", api.ErrCaptureIncomplete, berr)
			}
			if !containsWire(loaded, wire) {
				added = append(added, line) // we will add it → rollback unloads it
			}
		}
	}

	content, existed, err := at.ReadFileIfExists(p.RuleFile)
	if err != nil {
		return nil, fmt.Errorf("audit_rule_set: capture read %s: %w (%v)", p.RuleFile, api.ErrCaptureIncomplete, err)
	}
	// Which of this rule's lines are NOT already in the drop-in — the lines
	// Apply will add and Rollback must remove (leaving any sibling's lines).
	_, fileAdded := mergeRuleLines(content, auditnl.RuleLines(p.Rule))
	return h.preState(p, existed, content, added, fileAdded, staged, immutableStaged), nil
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
	// Immutable (enabled 2) → Apply stages, nothing is loaded, so Rollback must
	// not report a partial restore just because the runtime is locked. Mark it.
	// applyShell stages a persist_only directive on any host, as the netlink
	// path does, so mark that staged too.
	immutable := auditImmutableShell(ctx, transport)
	return h.preState(p, fileExisted, priorContent, nil, fileAdded, immutable || p.PersistOnly, immutable), nil
}

// preState builds the canonical PreState. added is the netlink-path set of
// rule lines to unload from the kernel on rollback (nil/empty on the shell
// path). fileAdded is the set of this rule's lines that were NOT already in the
// drop-in at capture — the lines rollback removes from the (possibly shared)
// file, so a sibling rule's line survives. prior_content / file_existed are
// retained as evidence; the file restore is line-based via fileAdded.
// immutable records that capture read the audit config as immutable, so a
// staged -e 2 cannot have changed it; a persist_only directive staged on a
// mutable host leaves it false.
func (h *Handler) preState(p *Params, fileExisted bool, priorContent string, added, fileAdded []string, immutableStaged, immutable bool) *api.PreState {
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
	if immutableStaged {
		// The rule was staged (never loaded into the kernel) because the audit
		// config is immutable. Rollback removes the drop-in only — there is no
		// runtime rule to unload, so it must not report a partial restore.
		data["immutable_staged"] = true
	}
	if immutable {
		data["audit_immutable_at_capture"] = true
	}
	// Always recorded, so Rollback can tell a pre-state from before the field
	// existed. A persist_only Apply writes the drop-in and runs no load, so
	// Rollback runs none.
	data["persist_only"] = p.PersistOnly
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data:       data,
	}
}

// DescribePreState renders the drop-in's state plus the two things that
// distinguish this mechanism: how many of the rule's lines were not already
// in the (possibly shared) file, and whether the host's audit config was
// immutable, in which case Apply staged the change for the next boot rather
// than loading it. "added_rules" and "file_added_lines" are absent from Data
// when empty, so their absence reads as zero.
func (h *Handler) DescribePreState(pre *api.PreState) string {
	path := prestate.Field(pre.Data, "path", "audit rule file")
	var file string
	switch existed, known := prestate.Bool(pre.Data, "file_existed"); {
	case !known:
		file = path
	case existed:
		file = prestate.Join(path+" present", prestate.Size(pre.Data, "prior_content"))
	default:
		file = path + " absent"
	}

	var pending, unloaded, staged string
	if n, ok := prestate.Count(pre.Data, "file_added_lines"); ok && n > 0 {
		pending = fmt.Sprintf("%d rule line(s) not yet in the file", n)
	}
	if n, ok := prestate.Count(pre.Data, "added_rules"); ok && n > 0 {
		unloaded = fmt.Sprintf("%d rule(s) not loaded in the kernel", n)
	}
	if po, _ := prestate.Bool(pre.Data, "persist_only"); po {
		staged = "persist_only directive, staged for reboot"
	} else if immutable, _ := prestate.Bool(pre.Data, "immutable_staged"); immutable {
		staged = "audit config immutable, change staged for reboot"
	}
	return prestate.Join(file, pending, unloaded, staged)
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
	// A staged transaction (immutable at capture) never loaded a runtime rule,
	// so its rollback removes the drop-in only and reports success — never a
	// partial restore over an unreconcilable-runtime claim.
	immutableStaged, _ := pre.Data["immutable_staged"].(bool)
	// A pre-state from before persist_only was recorded does not say whether
	// a control line such as -e 2 was a persist_only directive. Every Apply
	// of one either staged it without a load or loaded it, so roll it back
	// as staged, with no load: the live status and the control-line check
	// decide the verdict, and a bare augenrules --load never runs.
	persistOnly, known := pre.Data["persist_only"].(bool)
	if !known && (stagedImmutableDirective(fileAdded) || unshowableLine(fileAdded) != "") {
		persistOnly, immutableStaged = true, true
	}

	if at, ok := transport.(auditnl.AuditTransport); ok {
		res, err := h.rollbackNetlink(ctx, transport, at, path, added, fileAdded, immutableStaged, capturedImmutable(pre.Data))
		if !errors.Is(err, auditnl.ErrAuditUnavailable) {
			return res, err
		}
		// Netlink unavailable → shell rollback.
	}
	return h.rollbackShell(ctx, transport, path, fileAdded, immutableStaged, persistOnly, capturedImmutable(pre.Data))
}

// rollbackNetlink restores the drop-in by removing exactly the lines Apply
// added to the file (fileAdded) — leaving any sibling rule's lines in a shared
// drop-in intact — and unloads exactly the rule lines Apply added to the kernel
// (added), never a rule another drop-in owns.
func (h *Handler) rollbackNetlink(ctx context.Context, transport api.Transport, at auditnl.AuditTransport, path string, added, fileAdded []string, immutableStaged, wasImmutable bool) (*api.RollbackResult, error) {
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

	// Staged transaction: the drop-in is now removed, so the rule will NOT
	// reload at the next reboot (eventual convergence is guaranteed). Nothing
	// was loaded AT CAPTURE, but the host may have rebooted before this
	// rollback, in which case auditd loaded the persisted rule into the running
	// kernel and re-locked immutable, and we cannot unload it now. Decide the
	// verdict from LIVE state, NOT the stale capture-time flag. At boot auditctl
	// built the rule, not BuildRule, and auditctl writes some rules another way
	// (a perm watch with an explicit -S, a directory watch), so a wire compare
	// misses a loaded rule. Render the loaded rules and compare each with the
	// staged lines by kernel identity instead. We never DeleteRule here (an
	// immutable kernel would EPERM on it).
	if immutableStaged {
		listed, skipped, lerr := auditnl.RulesText(c)
		if lerr == nil {
			lerr = unrenderedList(fileAdded, skipped)
		}
		var bootImmutable bool
		var bootErr error
		if !wasImmutable && stagedImmutableDirective(fileAdded) {
			var enabled int
			enabled, bootErr = c.GetStatus()
			bootImmutable = bootErr == nil && enabled == 2
		}
		return stagedVerdict(ctx, transport, path, fileAdded, listed, lerr, bootImmutable, bootErr, "netlink"), nil
	}

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
	// confirming none of the rules we added are still loaded, a positive
	// read-back rather than trusting the delete return alone. Compare by kernel
	// identity, not wire bytes: if the host rebooted after Apply, auditctl
	// loaded the drop-in line at boot in its own form, which DeleteRule of the
	// BuildRule wire misses with ENOENT and a wire compare would not find.
	if len(added) > 0 {
		partial := func(format string, a ...interface{}) *api.RollbackResult {
			return &api.RollbackResult{
				Success:        false,
				PartialRestore: true,
				Detail:         fmt.Sprintf("audit_rule_set: restored %s but ", path) + fmt.Sprintf(format, a...),
				ExecutedAt:     time.Now().UTC(),
			}
		}
		// Defensive: a current Capture never records a control line in
		// added_rules (BuildRule refuses one, and Capture then fails), but a
		// pre-state from elsewhere might.
		if l := unshowableLine(added); l != "" {
			return partial("the line %q cannot be compared with the listing, so its unload could not be verified", l), nil
		}
		listed, skipped, lerr := auditnl.RulesText(c)
		if lerr == nil {
			lerr = unrenderedList(added, skipped)
		}
		if lerr != nil {
			return partial("could not verify live rules: %v", lerr), nil
		}
		line, id, why, err := check.AuditLoadedAmong(ctx, transport, added, listed, true)
		switch {
		case err != nil:
			return partial("could not verify live rules: %v", err), nil
		case id == check.AuditSame:
			// Capture decides added_rules by wire bytes, so this copy may have
			// been loaded before the transaction, in auditctl's form, or may
			// have been reloaded at a boot since Apply. Report it either way.
			return partial("rule %q still loaded after unload: it may predate this change, or a reboot since Apply reloaded it from the drop-in", line), nil
		case id == check.AuditUnresolved:
			return partial("a loaded rule may be %q (%s), so the unload could not be verified", line, why), nil
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
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, path string, fileAdded []string, immutableStaged, persistOnly, wasImmutable bool) (*api.RollbackResult, error) {
	current, rerr := h.readFileShell(ctx, transport, path)
	if rerr != nil {
		return nil, rerr
	}
	// For a staged rollback the drop-in removal IS the complete restore (nothing
	// was loaded), and augenrules --load fails on the immutable kernel — so
	// tolerate the load failure exactly as the staged apply path (applyShell)
	// does, keeping res.OK() a verdict on the file operation alone. A committed
	// rollback keeps the bare `&&` so a genuine reload failure still surfaces.
	//
	// A persist_only Apply ran no load, so its rollback runs none either: on a
	// mutable host augenrules --load would load every rules.d file into the
	// kernel, a change the transaction never made.
	augenrules := " && augenrules --load"
	switch {
	case persistOnly:
		augenrules = ""
	case immutableStaged:
		augenrules = " && { augenrules --load >/dev/null 2>&1 || true; }"
	}
	var cmd string
	if reduced, remaining := removeRuleLines(current, fileAdded); remaining {
		cmd = fmt.Sprintf(
			"printf '%%s' %s > %s%s",
			shellEscape(reduced), shellEscape(path), augenrules,
		)
	} else {
		cmd = fmt.Sprintf("rm -f %s%s", shellEscape(path), augenrules)
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
	// Staged transaction: the drop-in is removed (won't reload next reboot). If
	// the host rebooted before this rollback, auditd loaded the rule into the
	// running kernel and re-locked immutable — decide the verdict from LIVE
	// state, not the stale capture-time flag. Still loaded ⇒ honest
	// PartialRestore (clears next reboot); not loaded ⇒ clean restore.
	if immutableStaged {
		listed, lerr := auditListShell(ctx, transport)
		var bootImmutable bool
		var bootErr error
		if !wasImmutable && stagedImmutableDirective(fileAdded) {
			bootImmutable, bootErr = auditStatusShell(ctx, transport)
		}
		return stagedVerdict(ctx, transport, path, fileAdded, listed, lerr, bootImmutable, bootErr, "shell"), nil
	}
	// augenrules --load exited cleanly, but on an immutable audit config
	// (enabled 2) the kernel silently refuses live rule changes — a rule that
	// WAS committed (loaded) cannot be unloaded until reboot, so the file is
	// restored yet the running ruleset cannot be reconciled. Report honestly.
	immutable, serr := auditStatusShell(ctx, transport)
	if serr == nil && immutable {
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("audit_rule_set: restored %s but audit config is immutable (enabled 2); live ruleset unchanged until reboot", path),
			ExecutedAt:     time.Now().UTC(),
		}, nil
	}
	// augenrules --load removes a rule from the kernel only when the compiled
	// rules start with -D, so its exit alone does not show the rule is gone.
	// Verify through the listing whether or not the status could be read.
	return verifyUnloadedShell(ctx, transport, path, fileAdded, serr), nil
}

// verifyUnloadedShell finishes a committed shell rollback on a config that
// is not known to be immutable. augenrules --load succeeded, but that removes
// a rule only when the compiled rules start with -D, and statusErr, when set,
// means auditctl -s could not be read, so the config may be immutable after
// all. The listing settles it: no line Apply added may still be loaded. A
// listing or fact read that fails, a loaded or possibly loaded line, a
// control line the listing cannot show, and an added -e 2 when the status
// could not be read are each a partial restore. This can report a partial
// restore of a host that is clean; it never reports a clean restore of one
// that is not.
func verifyUnloadedShell(ctx context.Context, transport api.Transport, path string, fileAdded []string, statusErr error) *api.RollbackResult {
	lead := fmt.Sprintf("audit_rule_set: restored %s and reloaded audit rules, but ", path)
	if statusErr != nil {
		lead = fmt.Sprintf("audit_rule_set: restored %s, but the audit status could not be read (%v) and ", path, statusErr)
	}
	partial := func(format string, a ...interface{}) *api.RollbackResult {
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         lead + fmt.Sprintf(format, a...),
			ExecutedAt:     time.Now().UTC(),
		}
	}
	if statusErr != nil && stagedImmutableDirective(fileAdded) {
		return partial("whether the -e 2 line took effect cannot be shown from the listing")
	}
	if l := unshowableLine(fileAdded); l != "" {
		return partial("whether the control line %q took effect cannot be shown from the listing", l)
	}
	hasRule := false
	for _, l := range fileAdded {
		if _, ok := check.AuditRuleList(l); ok {
			hasRule = true
		}
	}
	if !hasRule {
		// Apply added no rule line, so it loaded nothing to unload.
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("audit_rule_set: restored %s and reloaded audit rules; no rule line was added", path),
			ExecutedAt: time.Now().UTC(),
		}
	}
	listed, lerr := auditListShell(ctx, transport)
	if lerr != nil {
		return partial("the loaded rules could not be read, so the unload could not be verified: %v", lerr)
	}
	line, id, why, err := check.AuditLoadedAmong(ctx, transport, fileAdded, listed, false)
	switch {
	case err != nil:
		return partial("the unload could not be verified: %v", err)
	case id == check.AuditSame:
		return partial("the rule %q is still loaded; remedy: reboot", line)
	case id == check.AuditUnresolved:
		return partial("a loaded rule may be %q (%s), so the unload could not be verified", line, why)
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("audit_rule_set: restored %s and reloaded audit rules; the listing shows no added rule loaded", path),
		ExecutedAt: time.Now().UTC(),
	}
}

// unshowableLine returns the first line that is neither an audit rule nor
// -e 2, such as -b 8192, -f 2, -e 0 or --loginuid-immutable, or a rule line
// that also carries such an option. Such a line
// changes kernel audit settings when it loads, which no rule listing shows,
// so a rollback cannot show it is undone.
func unshowableLine(lines []string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || stagedImmutableDirective([]string{t}) {
			continue
		}
		if _, ok := check.AuditRuleList(t); !ok {
			return t
		}
		if f := check.AuditLineControlFlag(t); f != "" {
			return t
		}
	}
	return ""
}

// unrenderedList returns an error when a staged line is on a filter list
// that the netlink listing left a rule out of, because that listing cannot
// show the line is not loaded.
func unrenderedList(lines, skipped []string) error {
	for _, sk := range skipped {
		if strings.HasPrefix(sk, "list ") {
			return fmt.Errorf("a rule on an unknown filter list (%s) could not be rendered", sk)
		}
	}
	for _, l := range lines {
		list, ok := check.AuditRuleList(l)
		if !ok {
			continue
		}
		for _, sk := range skipped {
			if sk == list {
				return fmt.Errorf("a rule on the %s list could not be rendered", list)
			}
		}
	}
	return nil
}

// capturedImmutable reports whether capture read the audit config as
// immutable. A pre-state from before the field existed reads as false, so a
// rollback checks the live status rather than assume the flag was set.
func capturedImmutable(data map[string]interface{}) bool {
	v, _ := data["audit_immutable_at_capture"].(bool)
	return v
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
