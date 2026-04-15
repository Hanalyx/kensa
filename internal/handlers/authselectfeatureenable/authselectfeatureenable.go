// Package authselectfeatureenable implements the authselect_feature_enable
// handler: enable an authselect feature (e.g. "with-faillock") and
// capture/rollback the prior authselect state.
// Spec: specs/handlers/authselect_feature_enable.spec.yaml.
package authselectfeatureenable

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// mechanism is the canonical handler name.
const mechanism = "authselect_feature_enable"

// Params is the decoded parameter struct for the
// authselect_feature_enable mechanism.
type Params struct {
	// Feature is the authselect feature name, e.g. "with-faillock".
	// Required.
	Feature string
}

// errMissingFeature is returned when params lacks the required feature.
var errMissingFeature = errors.New("authselect_feature_enable: params missing required 'feature'")

// decodeParams converts api.Params into the typed Params struct.
func decodeParams(p api.Params) (*Params, error) {
	if p == nil {
		return nil, errMissingFeature
	}
	v, ok := p["feature"]
	if !ok {
		return nil, errMissingFeature
	}
	feature, ok := v.(string)
	if !ok || feature == "" {
		return nil, errMissingFeature
	}
	return &Params{Feature: feature}, nil
}

// Handler implements the authselect_feature_enable mechanism.
type Handler struct{}

// New returns a fresh Handler.
func New() *Handler { return &Handler{} }

// Name returns the mechanism identifier "authselect_feature_enable".
func (h *Handler) Name() string { return mechanism }

// Capturable reports true.
func (h *Handler) Capturable() bool { return true }

// Apply runs `authselect enable-feature <feature>`. The command is
// idempotent when the feature is already enabled.
func (h *Handler) Apply(ctx context.Context, transport api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("authselect enable-feature %s", shellEscape(p.Feature))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("authselect_feature_enable: apply transport error: %w", err)
	}
	if !res.OK() {
		return &api.StepResult{
			Success: false,
			Detail:  fmt.Sprintf("authselect_feature_enable: enable-feature %s failed (exit %d): %s", p.Feature, res.ExitCode, strings.TrimSpace(res.Stderr)),
		}, nil
	}
	return &api.StepResult{
		Success: true,
		Detail:  fmt.Sprintf("authselect_feature_enable: feature %s enabled", p.Feature),
	}, nil
}

// Capture records the full output of `authselect current --raw` before
// Apply runs so rollback can determine whether the feature was
// already present.
func (h *Handler) Capture(ctx context.Context, transport api.Transport, params api.Params) (*api.PreState, error) {
	p, err := decodeParams(params)
	if err != nil {
		return nil, err
	}

	res, err := transport.Run(ctx, "authselect current --raw 2>/dev/null")
	if err != nil {
		return nil, fmt.Errorf("authselect_feature_enable: capture transport error: %w", err)
	}
	// authselect current exits non-zero when no profile is selected;
	// we still store whatever output we got so rollback has context.

	return &api.PreState{
		Mechanism:  mechanism,
		Capturable: true,
		CapturedAt: time.Now().UTC(),
		Data: map[string]interface{}{
			"feature":      p.Feature,
			"prior_output": res.Stdout,
		},
	}, nil
}

// Rollback disables the feature if it was not present in the
// pre-captured authselect output. Idempotent.
func (h *Handler) Rollback(ctx context.Context, transport api.Transport, pre *api.PreState) (*api.RollbackResult, error) {
	if pre == nil || pre.Data == nil {
		return nil, errors.New("authselect_feature_enable: rollback called with nil pre-state")
	}
	feature, _ := pre.Data["feature"].(string)
	priorOutput, _ := pre.Data["prior_output"].(string)

	if feature == "" {
		return nil, errors.New("authselect_feature_enable: pre-state missing 'feature'")
	}

	// If the prior output already contained the feature, it was
	// pre-existing — do not disable it.
	if strings.Contains(priorOutput, feature) {
		return &api.RollbackResult{
			Success:    true,
			Detail:     fmt.Sprintf("authselect_feature_enable: feature %s was pre-existing, nothing to rollback", feature),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}

	cmd := fmt.Sprintf("authselect disable-feature %s", shellEscape(feature))
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("authselect_feature_enable: rollback transport error: %w", err)
	}
	if !res.OK() {
		return &api.RollbackResult{
			Success:    false,
			Detail:     fmt.Sprintf("authselect_feature_enable: rollback failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr)),
			ExecutedAt: time.Now().UTC(),
		}, nil
	}
	return &api.RollbackResult{
		Success:    true,
		Detail:     fmt.Sprintf("authselect_feature_enable: feature %s disabled (rollback)", feature),
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// shellEscape wraps s in single quotes for safe shell inclusion.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
