// Package aptpresent implements the apt_present handler:
// ensure a Debian/Ubuntu package is installed via apt-get.
// Rollback removes the package only when it was absent at capture time.
// This is the Ubuntu equivalent of package_present (which uses dnf).
// Gate rules on requires: [apt] to select this implementation on Ubuntu.
package aptpresent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

const mechanism = "apt_present"

var errMissingName = errors.New("apt_present: params missing required 'name'")

type params struct{ Name string }

func decodeParams(p api.Params) (*params, error) {
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
	return &params{Name: name}, nil
}

// Handler implements the apt_present mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns "apt_present".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply installs the package with `apt-get install -y`. Idempotent.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, p api.Params, _ *api.PreState) (*api.StepResult, error) {
	pr, err := decodeParams(p)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y %s", shellEscape(pr.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("apt_present: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("apt_present: apt-get install failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("apt_present: %s installed", pr.Name),
	}, nil
}

// Capture records pkg_installed and prior_version via dpkg -l.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, p api.Params) (*api.PreState, error) {
	pr, err := decodeParams(p)
	if err != nil {
		return nil, err
	}
	// dpkg -l exits 0 even when the package is not found; grep for '^ii' to
	// confirm the package is properly installed (not just partially configured).
	cmd := fmt.Sprintf("dpkg -l %s 2>/dev/null | grep '^ii' || true", shellEscape(pr.Name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("apt_present: capture transport error: %w", err)
	}
	line := strings.TrimSpace(res.Stdout)
	installed := line != ""
	version := ""
	if installed {
		// dpkg -l output: "ii  pkgname  version  arch  description"
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			version = fields[2]
		}
	}
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"name":          pr.Name,
			"pkg_installed": installed,
			"prior_version": version,
		},
	}, nil
}

// Rollback removes the package when it was absent at capture time.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("apt_present: rollback called with nil pre-state")
	}
	name, _ := pre.Data["name"].(string)
	if name == "" {
		return nil, errors.New("apt_present: pre-state missing 'name'")
	}
	if pkgInstalled, _ := pre.Data["pkg_installed"].(bool); pkgInstalled {
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("apt_present: no-op rollback for %s (was installed at capture)", name),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	cmd := fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get remove -y %s", shellEscape(name))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("apt_present: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("apt_present: rollback remove failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("apt_present: removed %s (was absent at capture)", name),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
