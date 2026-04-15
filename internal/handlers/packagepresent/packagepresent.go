// Package packagepresent implements the package_present handler:
// ensure an RPM package is installed via dnf. Rollback removes the
// package only when it was absent at capture time.
// Spec: specs/handlers/package_present.spec.yaml.
package packagepresent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "package_present"

// Params is the decoded parameter struct for package_present.
type Params struct {
	// Name is the RPM package name (e.g. "aide", "auditd"). Required.
	Name string
}

// errMissingName is returned when params lacks the required name.
var errMissingName = errors.New("package_present: params missing required 'name'")

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

// Handler implements the package_present mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "package_present".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply installs the package with `dnf install -y`. Idempotent: dnf
// install of an already-installed package exits 0 with no change.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("dnf install -y %s", shellEscape(p.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("package_present: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("package_present: dnf install failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("package_present: %s installed", p.Name),
	}, nil
}

// Capture records pkg_installed and prior_version via `rpm -q`.
// A not-installed package is a valid capture result (pkg_installed=false).
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	// rpm -q exits 0 when installed (prints "name-version-release.arch"),
	// exits 1 when not installed (prints "package not installed").
	res, err := transport.Run(ctx, fmt.Sprintf("rpm -q %s 2>&1 || true", shellEscape(p.Name)))
	if err != nil {
		return nil, fmt.Errorf("package_present: capture transport error: %w", err)
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

// Rollback removes the package when it was absent at capture time
// per spec C-03. When pkg_installed=true, the package was already
// present; rollback is a no-op.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("package_present: rollback called with nil pre-state")
	}
	name, _ := pre.Data["name"].(string)
	if name == "" {
		return nil, errors.New("package_present: pre-state missing 'name'")
	}
	pkgInstalled, _ := pre.Data["pkg_installed"].(bool)

	if pkgInstalled {
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("package_present: no-op rollback for %s (was installed at capture)", name),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	// Package was absent at capture — remove it.
	cmd := fmt.Sprintf("dnf remove -y %s", shellEscape(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("package_present: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("package_present: rollback remove failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("package_present: removed %s (was absent at capture)", name),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
