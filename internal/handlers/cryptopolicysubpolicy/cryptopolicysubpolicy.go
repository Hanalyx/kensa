// Package cryptopolicysubpolicy implements the crypto_policy_subpolicy
// handler: append a subpolicy module to the active RHEL crypto policy
// if not already present. Non-capturable because subpolicy changes
// stack and cannot be trivially reversed.
// Spec: specs/handlers/crypto_policy_subpolicy.spec.yaml.
package cryptopolicysubpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Hanalyx/kensa/api"
)

// mechanism is the canonical handler name.
const mechanism = "crypto_policy_subpolicy"

// Params is the decoded parameter struct for the
// crypto_policy_subpolicy mechanism.
type Params struct {
	// Subpolicy is the subpolicy module name, e.g. "NO-SHA1".
	// Required.
	Subpolicy string
}

// errMissingSubpolicy is returned when params lacks the required
// subpolicy.
var errMissingSubpolicy = errors.New("crypto_policy_subpolicy: params missing required 'subpolicy'")

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingSubpolicy
	}
	v, ok := p["subpolicy"]
	if !ok {
		return nil, errMissingSubpolicy
	}
	subpolicy, ok := v.(string)
	if !ok || subpolicy == "" {
		return nil, errMissingSubpolicy
	}
	return &Params{Subpolicy: subpolicy}, nil
}

// Handler implements the crypto_policy_subpolicy mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "crypto_policy_subpolicy".
func (h *Handler) Name() string { return mechanism }

// Capturable reports false. Subpolicy changes stack and cannot be
// trivially reversed without knowing the full prior subpolicy state.
func (h *Handler) Capturable() bool { return false }

// Apply retrieves the current crypto policy and appends the subpolicy
// if it is not already present. Idempotent when the subpolicy is
// already active.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	// Get current policy (may include existing subpolicies, e.g.
	// "DEFAULT:NO-SHA1").
	showRes, err := transport.Run(ctx, "update-crypto-policies --show")
	if err != nil {
		return nil, fmt.Errorf("crypto_policy_subpolicy: apply show transport error: %w", err)
	}
	if !showRes.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("crypto_policy_subpolicy: --show failed (exit %d): %s", showRes.ExitCode, strings.TrimSpace(showRes.Stderr)),
		}, nil
	}

	currentPolicy := strings.TrimSpace(showRes.Stdout)

	// Check if subpolicy is already active. The policy string uses
	// colon-separated subpolicies: "BASE:SUB1:SUB2".
	parts := strings.Split(currentPolicy, ":")
	for _, part := range parts {
		if strings.EqualFold(strings.TrimSpace(part), p.Subpolicy) {
			return &api.StepResult{
				Success: true,
				Detail:  fmt.Sprintf("crypto_policy_subpolicy: %s already active in %s (no-op)", p.Subpolicy, currentPolicy),
			}, nil
		}
	}

	// Append the subpolicy to the current base.
	newPolicy := currentPolicy + ":" + p.Subpolicy
	cmd := fmt.Sprintf("update-crypto-policies --set %s", shellEscape(newPolicy))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("crypto_policy_subpolicy: apply set transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("crypto_policy_subpolicy: --set %s failed (exit %d): %s", newPolicy, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("crypto_policy_subpolicy: applied %s (policy now %s)", p.Subpolicy, newPolicy),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
