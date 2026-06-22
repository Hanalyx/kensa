// Package mountoptionset implements the mount_option_set handler:
// add or replace a mount option in /etc/fstab and remount the
// filesystem to apply the change at runtime.
// Spec: specs/handlers/mount_option_set.spec.yaml.
//
// Dual path: when the transport implements kernelio.FileTransport (agent
// mode on the target host) the handler edits /etc/fstab by parsing it in
// Go and rewriting it atomically (fsatomic), instead of the awk + mv
// shell pipeline. The runtime remount deliberately STAYS on mount(8)
// (transport.Run "mount -o remount") on both paths: a raw MS_REMOUNT via
// unix.Mount would have to reconcile the filesystem's currently-applied
// flags, and getting that wrong is filesystem-destructive — mount(8) does
// it correctly. Founder-ratified. Both paths write byte-identical fstab
// content and record an identical PreState shape.
package mountoptionset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// mechanism is the canonical handler name.
const mechanism = "mount_option_set"

// fstabPath is the system mount table the handler edits.
const fstabPath = "/etc/fstab"

// fstabMode is the canonical /etc/fstab mode (root-owned, world-readable).
const fstabMode = 0o644

// remountCmd is the runtime-apply command, shared by both paths — the
// remount stays on mount(8) for correct MS_* flag reconciliation.
func remountCmd(mountPoint string) string {
	return fmt.Sprintf("mount -o remount %s", shellEscape(mountPoint))
}

// Params is the decoded parameter struct for mount_option_set.
type Params struct {
	// MountPoint is the target filesystem mount point
	// (e.g. "/tmp", "/var"). Required.
	MountPoint string
	// Option is the comma-separated set of mount options to add
	// (e.g. "noexec", "nodev,nosuid,noexec"). Required.
	//
	// The field name stays "Option" so the Capture pre-state key
	// (pre.Data["option"]) is byte-identical across this change; only
	// the *input* decode source changed from "option" to "options".
	Option string
}

var (
	errMissingMountPoint = errors.New("mount_option_set: params missing required 'mount_point'")
	errMissingOption     = errors.New("mount_option_set: params missing required 'options'")
)

// decodeParams converts api.Params into the typed Params struct.
//
// The input parameter names follow CANONICAL_RULE_SCHEMA_V1.md §3.5.4:
// the mount-option set is carried under the key "options". The corpus
// expresses it as a YAML list (e.g. ["nodev", "nosuid"]) which the rule
// parser delivers as []interface{}; a plain comma-separated string is
// also accepted. Either form is normalised to a single comma-separated
// string in Params.Option, which is what Apply/Capture/Rollback consume.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingMountPoint
	}
	mp, ok := p["mount_point"].(string)
	if !ok || mp == "" {
		return nil, errMissingMountPoint
	}
	opts, err := optionList(p["options"])
	if err != nil || len(opts) == 0 {
		return nil, errMissingOption
	}
	return &Params{MountPoint: mp, Option: strings.Join(opts, ",")}, nil
}

// optionList normalises the "options" parameter into a slice of option
// tokens. It accepts a YAML list ([]interface{} / []string) per
// CANONICAL_RULE_SCHEMA_V1.md §3.5.4, or a comma-separated string.
// Empty tokens are dropped. Returns an error if any list element is not
// a string.
func optionList(v interface{}) ([]string, error) {
	splitCSV := func(s string) []string {
		out := make([]string, 0, 1)
		for _, tok := range strings.Split(s, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				out = append(out, tok)
			}
		}
		return out
	}
	switch val := v.(type) {
	case nil:
		return nil, errMissingOption
	case string:
		return splitCSV(val), nil
	case []string:
		out := make([]string, 0, len(val))
		for _, s := range val {
			out = append(out, splitCSV(s)...)
		}
		return out, nil
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("mount_option_set: 'options' elements must be strings, got %T", item)
			}
			out = append(out, splitCSV(s)...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("mount_option_set: 'options' must be a list of strings or a comma-separated string, got %T", v)
	}
}

// Handler implements the mount_option_set mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "mount_option_set".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply adds the mount option to the fstab entry and remounts.
// Uses awk to edit the options field of the matching fstab line in
// place, then calls `mount -o remount` to apply at runtime.
//
// Idempotent: if the option is already present, awk leaves the line
// unchanged; remount with an already-applied option is a no-op.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.applyKernel(ctx, ft, transport, p)
	}
	return h.applyShell(ctx, transport, p)
}

// applyKernel edits /etc/fstab in Go (parse + atomic rewrite) and
// remounts via mount(8).
func (h *Handler) applyKernel(ctx context.Context, ft kernelio.FileTransport, transport api.Transport, p *Params) (*api.StepResult, error) {
	content, existed, err := ft.ReadFileIfExists(fstabPath)
	if err != nil {
		return nil, fmt.Errorf("mount_option_set: read fstab: %w", err)
	}
	if !existed {
		return &api.StepResult{Success: false, Detail: "mount_option_set: /etc/fstab not found"}, nil
	}
	newContent, err := kernelio.FstabAddOptions(content, p.MountPoint, strings.Split(p.Option, ","))
	if err != nil {
		// No matching entry → non-compliant outcome, not a transport error.
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("mount_option_set: %v for %s", err, p.MountPoint),
		}, nil
	}
	if err := ft.AtomicReplace(ctx, fstabPath, fstabMode, []byte(newContent)); err != nil {
		return nil, fmt.Errorf("mount_option_set: rewrite fstab: %w", err)
	}
	if step := remount(ctx, transport, p.MountPoint, "apply"); step != nil {
		return step, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("mount_option_set: added %s to %s and remounted (kernel-io)", p.Option, p.MountPoint),
	}, nil
}

// fstabAddAwk appends each missing option to field 4 of the matching fstab
// line. The mount point and the comma-separated options arrive as the
// environment variables KENSA_MP / KENSA_OPTS (read via awk ENVIRON), NOT
// interpolated into the program text — so the program is a fixed constant
// that a value (a single quote, a metacharacter) cannot break, and awk's
// -v escape processing (which would mangle octal-escaped fstab paths like
// \040) never runs. Idempotent per option: an already-present option leaves
// $4 unchanged.
const fstabAddAwk = `$2 == ENVIRON["KENSA_MP"] {
	n = split(ENVIRON["KENSA_OPTS"], a, ",")
	for (i = 1; i <= n; i++) {
		if (a[i] != "" && $4 !~ ("(^|,)" a[i] "(,|$)")) $4 = $4 "," a[i]
	}
}
{ print }`

// fstabRestoreAwk replaces the matching fstab line with the captured prior
// line, read from KENSA_LINE via ENVIRON (same injection/escape-safety as
// fstabAddAwk).
const fstabRestoreAwk = `$2 == ENVIRON["KENSA_MP"] { print ENVIRON["KENSA_LINE"]; next } { print }`

// applyShell rewrites fstab via awk + mv and remounts.
func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
	// Atomically rewrite fstab, then remount. Values travel as environment
	// variables (shell-escaped) consumed by ENVIRON in the awk program.
	cmd := fmt.Sprintf(
		`KENSA_MP=%s KENSA_OPTS=%s awk %s /etc/fstab > /etc/fstab.kensa.tmp && mv /etc/fstab.kensa.tmp /etc/fstab && mount -o remount %s`,
		shellEscape(p.MountPoint),
		shellEscape(p.Option),
		shellEscape(fstabAddAwk),
		shellEscape(p.MountPoint),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("mount_option_set: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("mount_option_set: apply failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("mount_option_set: added %s to %s and remounted", p.Option, p.MountPoint),
	}, nil
}

// remount runs `mount -o remount <mp>` and returns a non-nil failed
// StepResult if it did not succeed, or nil on success. phase labels the
// caller for the detail message.
func remount(ctx context.Context, transport api.Transport, mountPoint, phase string) *api.StepResult {
	res, err := transport.Run(ctx, remountCmd(mountPoint))
	if err != nil {
		return &api.StepResult{Success: false, Detail: fmt.Sprintf("mount_option_set: %s remount transport error: %v", phase, err)}
	}
	if !res.OK() {
		return &api.StepResult{Success: false, Detail: fmt.Sprintf("mount_option_set: %s remount failed (exit %d): %s", phase, res.ExitCode, strings.TrimSpace(res.Stderr))}
	}
	return nil
}

// Capture records the current fstab options line for the mount point.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.captureKernel(ft, p)
	}
	return h.captureShell(ctx, transport, p)
}

// captureKernel reads /etc/fstab directly and records the matching line.
func (h *Handler) captureKernel(ft kernelio.FileTransport, p *Params) (*api.PreState, error) {
	content, existed, err := ft.ReadFileIfExists(fstabPath)
	if err != nil {
		return nil, fmt.Errorf("mount_option_set: capture read fstab: %w (%v)", api.ErrCaptureIncomplete, err)
	}
	if !existed {
		return nil, fmt.Errorf("mount_option_set: capture failed for %s: %w (/etc/fstab not found)",
			p.MountPoint, api.ErrCaptureIncomplete)
	}
	line, found := kernelio.FstabFindLine(content, p.MountPoint)
	if !found {
		return nil, fmt.Errorf("mount_option_set: capture failed for %s: %w (no matching fstab entry)",
			p.MountPoint, api.ErrCaptureIncomplete)
	}
	return h.preState(p, line), nil
}

// captureShell extracts the matching fstab line via grep.
func (h *Handler) captureShell(ctx context.Context, transport api.Transport, p *Params) (*api.PreState, error) {
	// Extract the full fstab line for this mount point.
	cmd := fmt.Sprintf(
		`grep -E %s /etc/fstab | grep -v '^[[:space:]]*#' | head -1`,
		shellEscape(fmt.Sprintf(`^[^#].*[[:space:]]%s[[:space:]]`, p.MountPoint)),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("mount_option_set: capture transport error: %w", err)
	}
	if !res.OK() || strings.TrimSpace(res.Stdout) == "" {
		return nil, fmt.Errorf("mount_option_set: capture failed for %s: %w (no matching fstab entry)",
			p.MountPoint, api.ErrCaptureIncomplete)
	}
	return h.preState(p, strings.TrimSpace(res.Stdout)), nil
}

// preState builds the canonical PreState shape used by both capture
// paths, so Rollback is path-agnostic.
func (h *Handler) preState(p *Params, priorLine string) *api.PreState {
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"mount_point": p.MountPoint,
			"option":      p.Option,
			"prior_line":  priorLine,
		},
	}
}

// Rollback restores the prior fstab line and remounts.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("mount_option_set: rollback called with nil pre-state")
	}
	mountPoint, _ := pre.Data["mount_point"].(string)
	priorLine, _ := pre.Data["prior_line"].(string)
	if mountPoint == "" || priorLine == "" {
		return nil, errors.New("mount_option_set: pre-state missing 'mount_point' or 'prior_line'")
	}
	// The option(s) this rule applied — verified on rollback alongside the
	// CIS toggle set so the "verified" claim covers whatever Kensa managed.
	appliedOpt, _ := pre.Data["option"].(string)

	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.rollbackKernel(ctx, ft, transport, mountPoint, priorLine, appliedOpt)
	}
	return h.rollbackShell(ctx, transport, mountPoint, priorLine, appliedOpt)
}

// rollbackKernel restores the captured fstab line (Go parse + atomic
// rewrite) and remounts via mount(8).
func (h *Handler) rollbackKernel(ctx context.Context, ft kernelio.FileTransport, transport api.Transport, mountPoint, priorLine, appliedOpt string) (*api.RollbackResult, error) {
	content, existed, err := ft.ReadFileIfExists(fstabPath)
	if err != nil {
		return nil, fmt.Errorf("mount_option_set: rollback read fstab: %w", err)
	}
	if !existed {
		return &api.RollbackResult{Success: false, Detail: "mount_option_set: /etc/fstab not found", ExecutedAt: time.Now().UTC()}, nil
	}
	newContent, err := kernelio.FstabReplaceLine(content, mountPoint, priorLine)
	if err != nil {
		return &api.RollbackResult{Success: false, Detail: fmt.Sprintf("mount_option_set: %v for %s", err, mountPoint), ExecutedAt: time.Now().UTC()}, nil
	}
	if newContent == content {
		// fstab already holds the captured prior line — the step never
		// changed it (or this rollback already ran; recovery drives rollback
		// for every captured step, including un-applied ones). The rewrite and
		// remount are skipped (a `mount -o remount` of an unchanged mount is an
		// unnecessary live kernel operation), but the live mount is STILL read
		// back: an fstab that already matches does not prove the runtime does,
		// and a clean success must be verified, not assumed.
		if ok, why := verifyRemount(ctx, transport, mountPoint, priorLine, appliedOpt); !ok {
			return &api.RollbackResult{
				Success:        false,
				PartialRestore: true,
				Detail:         fmt.Sprintf("mount_option_set: fstab already at prior state for %s but live mount diverges — %s; remedy: manual remount or reboot (kernel-io)", mountPoint, why),
				ExecutedAt:     time.Now().UTC(),
			}, nil
		}
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("mount_option_set: fstab already at prior state for %s, verified live options; no remount needed (kernel-io)", mountPoint),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	if err := ft.AtomicReplace(ctx, fstabPath, fstabMode, []byte(newContent)); err != nil {
		return nil, fmt.Errorf("mount_option_set: rollback rewrite fstab: %w", err)
	}
	if step := remount(ctx, transport, mountPoint, "rollback"); step != nil {
		return &api.RollbackResult{Success: false, Detail: step.Detail, ExecutedAt: time.Now().UTC()}, nil
	}
	if ok, why := verifyRemount(ctx, transport, mountPoint, priorLine, appliedOpt); !ok {
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("mount_option_set: fstab restored for %s but runtime not reconciled — %s; remedy: manual remount or reboot (kernel-io)", mountPoint, why),
			ExecutedAt:     time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("mount_option_set: restored fstab entry and remounted %s, verified live options (kernel-io)", mountPoint),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// rollbackShell restores the captured fstab line via awk + mv and remounts.
func (h *Handler) rollbackShell(ctx context.Context, transport api.Transport, mountPoint, priorLine, appliedOpt string) (*api.RollbackResult, error) {
	// Replace the fstab line for this mount point with the captured prior
	// line. Values travel as environment variables (shell-escaped) consumed
	// by ENVIRON in the awk program.
	cmd := fmt.Sprintf(
		`KENSA_MP=%s KENSA_LINE=%s awk %s /etc/fstab > /etc/fstab.kensa.tmp && mv /etc/fstab.kensa.tmp /etc/fstab && mount -o remount %s`,
		shellEscape(mountPoint), shellEscape(priorLine), shellEscape(fstabRestoreAwk), shellEscape(mountPoint),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("mount_option_set: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("mount_option_set: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	if ok, why := verifyRemount(ctx, transport, mountPoint, priorLine, appliedOpt); !ok {
		return &api.RollbackResult{
			Success:        false,
			PartialRestore: true,
			Detail:         fmt.Sprintf("mount_option_set: fstab restored for %s but runtime not reconciled — %s; remedy: manual remount or reboot", mountPoint, why),
			ExecutedAt:     time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("mount_option_set: restored fstab entry and remounted %s, verified live options", mountPoint),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// verifiableMountOpts are the baseline toggle options whose live presence
// the rollback always verifies against the restored fstab line — the CIS
// nodev/nosuid/noexec set. The option(s) the rule actually applied are
// added on top per-rollback, so the verdict covers whatever Kensa managed,
// not just these three. Kernel-implicit options (rw, relatime, seclabel, …)
// carry no fstab intent and are ignored.
var verifiableMountOpts = []string{"nodev", "nosuid", "noexec"}

// optionsToVerify returns the deterministic, de-duplicated list of options
// to read back: the CIS baseline plus the comma-separated options the rule
// applied (appliedOpt), in that stable order.
func optionsToVerify(appliedOpt string) []string {
	out := append([]string{}, verifiableMountOpts...)
	seen := map[string]bool{"nodev": true, "nosuid": true, "noexec": true}
	for _, o := range strings.Split(appliedOpt, ",") {
		if o = strings.TrimSpace(o); o != "" && !seen[o] {
			out = append(out, o)
			seen[o] = true
		}
	}
	return out
}

// liveOptionsCmd reads the active mount options for a mount point. findmnt
// is util-linux (present on RHEL and Ubuntu); -rno OPTIONS prints just the
// comma-separated option list for the one mount.
func liveOptionsCmd(mountPoint string) string {
	return fmt.Sprintf("findmnt -rno OPTIONS %s", shellEscape(mountPoint))
}

// optionSet splits a comma-separated mount-option string into a set.
func optionSet(s string) map[string]bool {
	set := make(map[string]bool)
	for _, o := range strings.Split(s, ",") {
		if o = strings.TrimSpace(o); o != "" {
			set[o] = true
		}
	}
	return set
}

// fstabOptionSet returns the option field (field 4) of an fstab line as a set.
func fstabOptionSet(line string) map[string]bool {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return map[string]bool{}
	}
	return optionSet(fields[3])
}

// verifyRemount reads the live mount options back and checks that each
// verifiable toggle option's live presence matches the restored fstab
// line's intent. It returns ok=true only when the read-back succeeds and
// every verifiable option agrees; an unreadable mount table or any
// divergence returns ok=false with a human detail, so the caller reports a
// verified-partial restore rather than a silent success. A remount is
// always live-reconcilable, so a divergence here means the runtime did not
// actually take the restored options — operator attention (manual remount
// or reboot) is warranted.
func verifyRemount(ctx context.Context, transport api.Transport, mountPoint, priorLine, appliedOpt string) (bool, string) {
	res, err := transport.Run(ctx, liveOptionsCmd(mountPoint))
	if err != nil {
		return false, fmt.Sprintf("live mount options could not be read back: %v", err)
	}
	if !res.OK() || strings.TrimSpace(res.Stdout) == "" {
		return false, "live mount options could not be read back (findmnt returned nothing)"
	}
	live := optionSet(res.Stdout)
	want := fstabOptionSet(priorLine)
	for _, o := range optionsToVerify(appliedOpt) {
		if want[o] != live[o] {
			return false, fmt.Sprintf("live option %q=%v but restored fstab intends %v", o, live[o], want[o])
		}
	}
	return true, ""
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
