// Package cryptopolicyset implements the crypto_policy_set handler:
// set the system-wide RHEL crypto policy via update-crypto-policies,
// with capture and rollback support.
// Spec: specs/handlers/crypto_policy_set.spec.yaml.
package cryptopolicyset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa/api"
)

// mechanism is the canonical handler name.
const mechanism = "crypto_policy_set"

// showCmd reads the active system-wide crypto policy. Shared by Capture
// (to record the prior policy) and Rollback (to verify the restore took).
const showCmd = "update-crypto-policies --show 2>/dev/null"

// daemonRemedy is appended to a verified-restore detail. update-crypto-policies
// rewrites the policy files and back-end configs, but a service that already
// read its crypto config at startup keeps using it until restarted. The
// verdict is scoped to the policy itself (which this handler owns and verifies);
// reconciling long-lived daemons is an operator action, stated here as the
// remedy rather than counted as a failed restore.
const daemonRemedy = "; already-running services keep their startup crypto until restarted (e.g. systemctl restart sshd)"

// Params is the decoded parameter struct for the crypto_policy_set
// mechanism.
type Params struct {
	// Policy is the RHEL crypto policy name, e.g. "FIPS", "DEFAULT".
	// Required.
	Policy string
}

// errMissingPolicy is returned when params lacks the required policy.
var errMissingPolicy = errors.New("crypto_policy_set: params missing required 'policy'")

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingPolicy
	}
	v, ok := p["policy"]
	if !ok {
		return nil, errMissingPolicy
	}
	policy, ok := v.(string)
	if !ok || policy == "" {
		return nil, errMissingPolicy
	}
	return &Params{Policy: policy}, nil
}

// Handler implements the crypto_policy_set mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "crypto_policy_set".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply runs `update-crypto-policies --set <policy>`. Idempotent when
// the policy is already set to the desired value.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("update-crypto-policies --set %s", shellEscape(p.Policy))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("crypto_policy_set: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("crypto_policy_set: --set %s failed (exit %d): %s", p.Policy, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("crypto_policy_set: policy set to %s", p.Policy),
	}, nil
}

// Capture records the current crypto policy before Apply runs.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	_, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	res, err := transport.Run(ctx, showCmd)
	if err != nil {
		return nil, fmt.Errorf("crypto_policy_set: capture transport error: %w", err)
	}
	if !res.OK() {
		return nil, fmt.Errorf("crypto_policy_set: capture failed: %w (stderr: %s)",
			api.ErrCaptureIncomplete, strings.TrimSpace(res.Stderr))
	}

	priorPolicy := strings.TrimSpace(res.Stdout)
	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"prior_policy": priorPolicy,
		},
	}, nil
}

// Rollback restores the prior crypto policy and verifies the live policy
// matches by reading it back with `--show`. Idempotent.
//
// The verdict is scoped to the crypto policy, which this handler owns:
// a read-back that confirms the prior policy is a clean success; a
// mismatch (or an unverifiable read-back) is a failure, not a silent
// claim. Already-running services that hold startup-time crypto are
// reported as the remedy (daemonRemedy), not a failed restore — the same
// way every config handler leaves a running daemon's reload to the
// operator.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("crypto_policy_set: rollback called with nil pre-state")
	}
	priorPolicy, _ := pre.Data["prior_policy"].(string)
	if priorPolicy == "" {
		return nil, errors.New("crypto_policy_set: pre-state missing 'prior_policy'")
	}

	cmd := fmt.Sprintf("update-crypto-policies --set %s", shellEscape(priorPolicy))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("crypto_policy_set: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("crypto_policy_set: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	// Verify the restore took by reading the live policy back.
	show, err := transport.Run(ctx, showCmd)
	if err != nil {
		return nil, fmt.Errorf("crypto_policy_set: rollback verify transport error: %w", err)
	}
	got := strings.TrimSpace(show.Stdout)
	if !show.OK() || got != priorPolicy {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("crypto_policy_set: restore unverified — live policy is %q, want %q", got, priorPolicy),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("crypto_policy_set: policy restored to %s and verified%s", priorPolicy, daemonRemedy),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
