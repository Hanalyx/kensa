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
	"regexp"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/prestate"
	"github.com/Hanalyx/kensa/internal/valueguard"
)

// mechanism is the canonical handler name.
const mechanism = "mount_option_set"

// fstabPath is the system mount table the handler edits.
const fstabPath = "/etc/fstab"

// fstabMode is the canonical /etc/fstab mode (root-owned, world-readable).
const fstabMode = 0o644

// remountCmd is the runtime-apply command, shared by both paths — the
// remount stays on mount(8) for correct MS_* flag reconciliation.
//
// It rereads the options from fstab for a mount point that APPEARS in fstab,
// which is why it is sufficient after an edit and NOT sufficient after removing
// the only line: with nothing to reread it keeps the live option set. See
// rollbackAbsent, which negates explicitly for that reason.
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
	joined := strings.Join(opts, ",")
	// The option string is appended to field 4 of the matching /etc/fstab line;
	// a newline in an option (splitCSV splits only on ',') injects an entire new
	// fstab entry — an attacker-chosen mount (security.md #13 class). The mount
	// point selects the line; guard both.
	if err := valueguard.NoControlCharsIn(map[string]string{
		"mount_option_set mount_point": mp, "mount_option_set options": joined,
	}); err != nil {
		return nil, err
	}
	return &Params{MountPoint: mp, Option: joined}, nil
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
	if errors.Is(err, kernelio.ErrNoFstabEntry) {
		// systemd mounts some filesystems with no fstab line at all — /dev/shm
		// on every current EL and Ubuntu. Persisting the option means creating
		// the entry, built from what the kernel reports rather than a guess at
		// the device and filesystem type.
		source, fstype, live, ok := liveMount(ctx, transport, p.MountPoint)
		if !ok {
			return &api.StepResult{
				Success: false,
				Detail:  fmt.Sprintf("mount_option_set: %s has no fstab entry and is not mounted", p.MountPoint),
			}, nil
		}
		newContent = strings.TrimRight(content, "\n") + "\n" +
			synthesizeLine(source, p.MountPoint, fstype, live, p.Option) + "\n"
	} else if err != nil {
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

func (h *Handler) applyShell(ctx context.Context, transport api.Transport, p *Params) (*api.StepResult, error) {
	// One command, not three round trips. The awk program can only edit a line
	// that exists, and some filesystems are mounted by systemd with no fstab
	// line at all — /dev/shm on every current EL and Ubuntu. The else branch
	// creates the entry from what the host's own findmnt reports, so the device
	// and filesystem type are read rather than guessed.
	cmd := fmt.Sprintf(
		`if grep -qE %s /etc/fstab; then `+
			`KENSA_MP=%s KENSA_OPTS=%s awk %s /etc/fstab > /etc/fstab.kensa.tmp && mv /etc/fstab.kensa.tmp /etc/fstab; `+
			`else `+
			`set -- $(findmnt --kernel -n -o SOURCE,FSTYPE,OPTIONS %s) && `+
			`o=$(printf '%%s' "$3" | tr ',' '\n' | grep -vx seclabel | paste -sd, -) && `+
			`for x in $(printf '%%s' %s | tr ',' ' '); do case ",$o," in *",$x,"*) ;; *) o="$o,$x" ;; esac; done && `+
			`printf '%%s %s %%s %%s 0 0\n' "$1" "$2" "$o" >> /etc/fstab; `+
			`fi && mount -o remount %s`,
		shellEscape(fmt.Sprintf(`^[^#].*[[:space:]]%s[[:space:]]`, regexp.QuoteMeta(p.MountPoint))),
		shellEscape(p.MountPoint),
		shellEscape(p.Option),
		shellEscape(fstabAddAwk),
		shellEscape(p.MountPoint),
		shellEscape(p.Option),
		p.MountPoint,
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

func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.captureKernel(ctx, ft, transport, p)
	}
	return h.captureShell(ctx, transport, p)
}

// captureKernel reads /etc/fstab directly and records the matching line.
func (h *Handler) captureKernel(ctx context.Context, ft kernelio.FileTransport, transport api.Transport, p *Params) (*api.PreState, error) {
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
		return h.captureAbsent(ctx, transport, p)
	}
	return h.preState(p, line), nil
}

// captureAbsent records the pre-state for a mount point with no fstab entry.
//
// The prior state is fully describable — "no line, and the live mount carried
// these options" — so this is a complete capture, not an incomplete one. It is
// only ErrCaptureIncomplete when the path is not mounted either, because then
// there is nothing to read and nothing to restore to.
func (h *Handler) captureAbsent(ctx context.Context, transport api.Transport, p *Params) (*api.PreState, error) {
	source, fstype, options, ok := liveMount(ctx, transport, p.MountPoint)
	if !ok {
		return nil, fmt.Errorf("mount_option_set: capture failed for %s: %w (no fstab entry and not mounted)",
			p.MountPoint, api.ErrCaptureIncomplete)
	}
	pre := h.preState(p, "")
	pre.Data["prior_absent"] = true
	pre.Data["prior_options"] = options
	pre.Data["prior_source"] = source
	pre.Data["prior_fstype"] = fstype
	return pre, nil
}

// captureShell extracts the matching fstab line via grep.
func (h *Handler) captureShell(ctx context.Context, transport api.Transport, p *Params) (*api.PreState, error) {
	// Extract the full fstab line for this mount point.
	// regexp.QuoteMeta the mount point before embedding it in the grep -E
	// pattern: an unescaped ERE metacharacter in the mount point (e.g. "." or
	// "|") would otherwise widen the match and let Capture snapshot — and
	// Rollback restore — the wrong fstab line.
	cmd := fmt.Sprintf(
		`grep -E %s /etc/fstab | grep -v '^[[:space:]]*#' | head -1`,
		shellEscape(fmt.Sprintf(`^[^#].*[[:space:]]%s[[:space:]]`, regexp.QuoteMeta(p.MountPoint))),
	)
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("mount_option_set: capture transport error: %w", err)
	}
	if !res.OK() || strings.TrimSpace(res.Stdout) == "" {
		return h.captureAbsent(ctx, transport, p)
	}
	return h.preState(p, strings.TrimSpace(res.Stdout)), nil
}

// --- absent-entry support (KN-KN-026) -------------------------------------
//
// A mount point that systemd mounts without an /etc/fstab line — /dev/shm on
// every current EL and Ubuntu — used to be unremediable: Capture refused,
// because it read "no fstab line" as "cannot describe the prior state".
//
// It can be described. The prior state is "no line, and the live mount carried
// these options", and both halves are recoverable. What made the naive version
// dangerous is that undoing it needs more than deleting the line again; see
// rollbackAbsent.

// liveMount reads the source, filesystem type and options of a live mount.
// found is false when the path is not a mount point.
func liveMount(ctx context.Context, transport api.Transport, mountPoint string) (source, fstype, options string, found bool) {
	res, err := transport.Run(ctx, fmt.Sprintf(
		"findmnt --kernel -n -o SOURCE,FSTYPE,OPTIONS %s", shellEscape(mountPoint)))
	if err != nil || !res.OK() {
		return "", "", "", false
	}
	f := strings.Fields(strings.TrimSpace(res.Stdout))
	if len(f) < 3 {
		return "", "", "", false
	}
	return f[0], f[1], f[2], true
}

// notMountOptions are flags findmnt reports back that mount(8) will not accept
// as input. seclabel is how the kernel says SELinux labelling is in effect; it
// is not something an fstab line may ask for.
var notMountOptions = map[string]bool{"seclabel": true}

// carriedOptions returns the live options that are safe to write into an fstab
// line. It is a denylist rather than an allowlist on purpose: filesystem
// specific options such as inode64, usrquota and size= are legitimate and must
// survive, and enumerating every one of them would guarantee dropping the next.
func carriedOptions(liveOptions string) []string {
	out := make([]string, 0, 8)
	for _, o := range strings.Split(liveOptions, ",") {
		if o = strings.TrimSpace(o); o != "" && !notMountOptions[o] {
			out = append(out, o)
		}
	}
	return out
}

// synthesizeLine builds the fstab entry for a mount point that had none.
//
// Source and filesystem type come from what the kernel reports, because
// guessing them would work for /dev/shm and be wrong everywhere else.
//
// The options are the LIVE options plus the one being applied — not "defaults"
// plus the one being applied. That difference is the whole of a defect this
// code shipped once: /dev/shm is mounted nosuid,nodev by systemd, so a line
// reading "defaults,noexec" silently DROPPED nosuid and nodev at the next
// remount. Adding one security option must never remove two.
func synthesizeLine(source, mountPoint, fstype, liveOptions, option string) string {
	opts := carriedOptions(liveOptions)
	have := make(map[string]bool, len(opts))
	for _, o := range opts {
		have[o] = true
	}
	for _, o := range strings.Split(option, ",") {
		if o = strings.TrimSpace(o); o != "" && !have[o] {
			opts = append(opts, o)
			have[o] = true
		}
	}
	if len(opts) == 0 {
		opts = []string{"defaults"}
	}
	return fmt.Sprintf("%s %s %s %s 0 0", source, mountPoint, fstype, strings.Join(opts, ","))
}

// negations pairs each mount option this handler sets with the option that
// turns it off.
//
// Rollback needs these because `mount -o remount <dir>` with no options keeps
// the live option set — it only rereads fstab for a mount point that APPEARS in
// fstab. When the rollback has just removed the only line, there is nothing to
// reread, and the option stays applied while the rollback reports success.
//
// Replaying the captured option list instead is not an alternative: it contains
// kernel-internal flags such as seclabel and inode64 that mount(8) rejects as
// remount arguments.
var negations = map[string]string{
	"nodev":       "dev",
	"nosuid":      "suid",
	"noexec":      "exec",
	"ro":          "rw",
	"rw":          "ro",
	"noatime":     "atime",
	"nodiratime":  "diratime",
	"nosymfollow": "symfollow",
}

// negate returns the remount arguments that undo opts, skipping any option the
// mount already carried before this transaction, because those were not ours to
// undo.
func negate(applied, priorOptions string) []string {
	had := make(map[string]bool)
	for _, o := range strings.Split(priorOptions, ",") {
		had[strings.TrimSpace(o)] = true
	}
	var out []string
	for _, o := range strings.Split(applied, ",") {
		o = strings.TrimSpace(o)
		if o == "" || had[o] {
			continue
		}
		if n, ok := negations[o]; ok {
			out = append(out, n)
		}
	}
	return out
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

// DescribePreState renders the captured fstab entry. The prior line is a
// single fstab record and is the thing an operator wants to read before
// approving a mount-option change, so it is rendered through
// [prestate.Text] rather than reported as a size.
func (h *Handler) DescribePreState(pre *api.PreState) string {
	mount := prestate.Field(pre.Data, "mount_point", "mount point")
	line, ok := prestate.String(pre.Data, "prior_line")
	switch {
	case !ok:
		return mount + ", fstab entry not captured"
	case strings.TrimSpace(line) == "":
		return mount + ", no fstab entry"
	}
	// Line, not Text: an fstab entry carries mount options, and cifs entries
	// put `password=` and `credentials=` among them.
	return prestate.Join(mount, prestate.Line(line))
}

// Rollback restores the prior fstab line and remounts.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("mount_option_set: rollback called with nil pre-state")
	}
	mountPoint, _ := pre.Data["mount_point"].(string)
	priorLine, _ := pre.Data["prior_line"].(string)
	if mountPoint == "" {
		return nil, errors.New("mount_option_set: pre-state missing 'mount_point'")
	}
	// The absent case is checked BEFORE the prior_line guard: its prior_line is
	// deliberately empty, because what it restores to is the ABSENCE of a line.
	if absent, _ := pre.Data["prior_absent"].(bool); absent {
		return h.rollbackAbsent(ctx, transport, pre, mountPoint)
	}
	if priorLine == "" {
		return nil, errors.New("mount_option_set: pre-state missing 'prior_line'")
	}
	// The option(s) this rule applied — verified on rollback alongside the
	// CIS toggle set so the "verified" claim covers whatever Kensa managed.
	appliedOpt, _ := pre.Data["option"].(string)

	if ft, ok := transport.(kernelio.FileTransport); ok {
		return h.rollbackKernel(ctx, ft, transport, mountPoint, priorLine, appliedOpt)
	}
	return h.rollbackShell(ctx, transport, mountPoint, priorLine, appliedOpt)
}

// rollbackAbsent undoes an entry this engine created for a mount point that had
// none, and it is deliberately not "delete the line again".
//
// Two things make the obvious version wrong, both measured on a live host:
//
//  1. Sibling rules share the line. /dev/shm has three rules (nodev, nosuid,
//     noexec) and /tmp, /home and /var/tmp have three each. Whichever runs
//     first creates the entry; the others add to it. Deleting the line on the
//     first one's rollback would throw away the other two rules' work. So this
//     removes only the option this transaction applied, and removes the LINE
//     only when nothing else is left on it.
//
//  2. `mount -o remount <dir>` keeps the live option set. It rereads fstab only
//     for a mount point that appears there, so once the line is gone there is
//     nothing to reread and the option stays applied — a rollback that reports
//     success and leaves the host changed. The applied option has to be negated
//     explicitly.
func (h *Handler) rollbackAbsent(ctx context.Context, transport api.Transport, pre *api.PreState, mountPoint string) (*api.RollbackResult, error) {
	appliedOpt, _ := pre.Data["option"].(string)
	priorOptions, _ := pre.Data["prior_options"].(string)
	now := func() time.Time { return time.Now().UTC() }

	read := func() (string, bool, error) {
		if ft, ok := transport.(kernelio.FileTransport); ok {
			return ft.ReadFileIfExists(fstabPath)
		}
		res, err := transport.Run(ctx, "cat /etc/fstab")
		if err != nil {
			return "", false, err
		}
		return res.Stdout, res.OK(), nil
	}
	write := func(content string) error {
		if ft, ok := transport.(kernelio.FileTransport); ok {
			return ft.AtomicReplace(ctx, fstabPath, fstabMode, []byte(content))
		}
		res, err := transport.Run(ctx, fmt.Sprintf(
			"printf '%%s' %s > /etc/fstab.kensa.tmp && mv /etc/fstab.kensa.tmp /etc/fstab", shellEscape(content)))
		if err != nil {
			return err
		}
		if !res.OK() {
			return fmt.Errorf("write fstab: %s", strings.TrimSpace(res.Stderr))
		}
		return nil
	}

	content, existed, err := read()
	if err != nil {
		return nil, fmt.Errorf("mount_option_set: rollback read fstab: %w", err)
	}

	detail := "no fstab entry to remove"
	if existed {
		if opts, found := kernelio.FstabOptions(content, mountPoint); found {
			// What remains once this transaction's option is taken off. If that
			// is just the synthesized baseline, nobody else is using the line.
			// What is left once this transaction's options come off. Anything
			// that was already on the live mount at capture is not a sibling's
			// work — the synthesized line carries those forward deliberately,
			// so adding one option never drops the ones systemd already set.
			mine := make(map[string]bool)
			for _, o := range strings.Split(appliedOpt, ",") {
				if o = strings.TrimSpace(o); o != "" {
					mine[o] = true
				}
			}
			prior := map[string]bool{"defaults": true}
			for _, o := range carriedOptions(priorOptions) {
				prior[o] = true
			}
			remaining := make([]string, 0, len(opts))
			for _, o := range opts {
				if !mine[o] && !prior[o] {
					remaining = append(remaining, o)
				}
			}
			var newContent string
			if len(remaining) == 0 {
				newContent, err = kernelio.FstabRemoveLine(content, mountPoint)
				detail = "removed the fstab entry this transaction created"
			} else {
				newContent, err = kernelio.FstabRemoveOptions(content, mountPoint, strings.Split(appliedOpt, ","))
				detail = fmt.Sprintf("kept the fstab entry, %d option(s) from other transactions remain", len(remaining))
			}
			if err != nil {
				return &api.RollbackResult{Success: false, Detail: fmt.Sprintf("mount_option_set: %v for %s", err, mountPoint), ExecutedAt: now()}, nil
			}
			if err := write(newContent); err != nil {
				return nil, fmt.Errorf("mount_option_set: rollback rewrite fstab: %w", err)
			}
		}
	}

	// Negate what was applied. Without this the live mount keeps the option
	// even though fstab no longer asks for it.
	if neg := negate(appliedOpt, priorOptions); len(neg) > 0 {
		cmd := fmt.Sprintf("mount -o remount,%s %s", strings.Join(neg, ","), shellEscape(mountPoint))
		res, err := transport.Run(ctx, cmd)
		if err != nil {
			return nil, fmt.Errorf("mount_option_set: rollback remount transport error: %w", err)
		}
		if !res.OK() {
			return &api.RollbackResult{
				Success:    false,
				Detail:     fmt.Sprintf("mount_option_set: rollback remount failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
				ExecutedAt: now(),
			}, nil
		}
	}

	// Verified, not assumed: read the live mount back.
	if _, _, opts, ok := liveMount(ctx, transport, mountPoint); ok {
		for _, o := range strings.Split(appliedOpt, ",") {
			o = strings.TrimSpace(o)
			if o == "" {
				continue
			}
			for _, live := range strings.Split(opts, ",") {
				if live == o && !strings.Contains(priorOptions, o) {
					return &api.RollbackResult{
						Success:    false,
						Detail:     fmt.Sprintf("mount_option_set: %s still carries %s after rollback", mountPoint, o),
						ExecutedAt: now(),
					}, nil
				}
			}
		}
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("mount_option_set: %s restored to no-fstab-entry state (%s)", mountPoint, detail),
		ExecutedAt: now(),
	}, nil
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
