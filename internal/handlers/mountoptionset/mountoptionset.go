// Package mountoptionset implements the mount_option_set handler:
// add or replace a mount option in /etc/fstab and remount the
// filesystem to apply the change at runtime.
// Spec: specs/handlers/mount_option_set.spec.yaml.
package mountoptionset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// mechanism is the canonical handler name.
const mechanism = "mount_option_set"

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

	// awk script: for the matching mount point line, append each requested
	// option to field 4 (options) if it is not already present. Each option
	// is checked and appended independently so a multi-option request
	// (e.g. "nodev,nosuid") only adds the tokens that are missing.
	//
	// Idempotent per option: an already-present option leaves $4 unchanged.
	var clauses strings.Builder
	for _, opt := range strings.Split(p.Option, ",") {
		fmt.Fprintf(&clauses, `$2 == %[1]s && $4 !~ /(^|,)%[2]s(,|$)/ { $4 = $4 "," %[2]s } `,
			shellEscape(p.MountPoint), shellEscape(opt))
	}
	awkScript := clauses.String() + `{ print }`
	// Atomically rewrite fstab, then remount.
	cmd := fmt.Sprintf(
		`awk %s /etc/fstab > /etc/fstab.kensa.tmp && mv /etc/fstab.kensa.tmp /etc/fstab && mount -o remount %s`,
		shellEscape(awkScript),
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

// Capture records the current fstab options line for the mount point.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
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
	priorLine := strings.TrimSpace(res.Stdout)
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"mount_point": p.MountPoint,
			"option":      p.Option,
			"prior_line":  priorLine,
		},
	}, nil
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

	// Replace the fstab line for this mount point with the captured prior line.
	awkScript := fmt.Sprintf(
		`$2 == %s { print %s; next } { print }`,
		shellEscape(mountPoint), shellEscape(priorLine),
	)
	cmd := fmt.Sprintf(
		`awk %s /etc/fstab > /etc/fstab.kensa.tmp && mv /etc/fstab.kensa.tmp /etc/fstab && mount -o remount %s`,
		shellEscape(awkScript), shellEscape(mountPoint),
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
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("mount_option_set: restored fstab entry and remounted %s", mountPoint),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
