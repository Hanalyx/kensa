// Package packageabsent implements the package_absent handler:
// ensure an RPM package is removed via dnf. Rollback reinstalls the
// package when it was present at capture time. Note: the reinstalled
// version may differ from prior_version if the repo has been updated
// since capture — this is a disclosed, non-gated edge case per spec C-03.
// Spec: specs/handlers/package_absent.spec.yaml.
package packageabsent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "package_absent"

// Params is the decoded parameter struct for package_absent.
type Params struct {
	// Name is the RPM package name (e.g. "telnet", "rsh"). Required.
	Name string
}

// errMissingName is returned when params lacks the required name.
var errMissingName = errors.New("package_absent: params missing required 'name'")

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingName
	}
	v, ok := p["name"]
	if !ok {
		return nil, errMissingName
	}
	name, ok := v.(string)
	if !ok || name == "" {
		return nil, errMissingName
	}
	return &Params{Name: name}, nil
}

// Handler implements the package_absent mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "package_absent".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply removes the package with `dnf remove -y`. Idempotent: dnf
// remove of an already-absent package exits 0 with no change.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("dnf remove -y %s", shellEscape(p.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("package_absent: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("package_absent: dnf remove failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("package_absent: %s removed", p.Name),
	}, nil
}

// Capture records pkg_installed and prior_version. A not-installed
// package is a valid capture result (pkg_installed=false, rollback
// is a no-op).
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	res, err := transport.Run(ctx, fmt.Sprintf("rpm -q %s 2>&1 || true", shellEscape(p.Name)))
	if err != nil {
		return nil, fmt.Errorf("package_absent: capture transport error: %w", err)
	}

	stdout := strings.TrimSpace(res.Stdout)
	installed := !strings.Contains(stdout, "not installed") && stdout != ""
	version := ""
	if installed {
		version = stdout
	}

	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"name":          p.Name,
			"pkg_installed": installed,
			"prior_version": version,
		},
	}, nil
}

// Rollback reinstalls the package when it was present at capture time
// per spec C-03. When pkg_installed=false, rollback is a no-op.
//
// Edge case (disclosed, not gated): the reinstalled version may differ
// from prior_version if the RPM repository has been updated since
// capture. The operator should validate the version after rollback.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("package_absent: rollback called with nil pre-state")
	}
	name, _ := pre.Data["name"].(string)
	if name == "" {
		return nil, errors.New("package_absent: pre-state missing 'name'")
	}
	pkgInstalled, _ := pre.Data["pkg_installed"].(bool)

	if !pkgInstalled {
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("package_absent: no-op rollback for %s (was absent at capture)", name),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	// Package was installed at capture — reinstall it. Note: exact version
	// match is not guaranteed. See spec C-03 for the disclosed edge case.
	cmd := fmt.Sprintf("dnf install -y %s", shellEscape(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("package_absent: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("package_absent: rollback reinstall failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("package_absent: reinstalled %s (was present at capture)", name),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
