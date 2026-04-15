// Package manual implements the manual handler: a mechanism that records
// a human-action-required note in the transaction log without touching
// the target host.
//
// This handler is non-capturable. Rules using manual must declare
// transactional: false. The Apply call always succeeds so the step is
// recorded as committed; the detail text carries the action description
// that the operator must perform manually.
package manual

import (
	"context"
	"errors"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

const mechanism = "manual"

func init() { handler.Register(New()) }

// Handler implements the manual mechanism.
type Handler struct{}

// New returns a new Handler.
func New() *Handler { return &Handler{} }

// Name returns "manual".
func (h *Handler) Name() string { return mechanism }

// Capturable returns false — manual is non-capturable.
func (h *Handler) Capturable() bool { return false }

// Apply records the manual action description without running any remote
// command. Params:
//
//	description  string  human-readable action description (required)
func (h *Handler) Apply(_ context.Context, _ api.Transport, params api.Params, _ *api.PreState) (*api.StepResult, error) {
	if params == nil {
		return nil, errors.New("manual: params is nil")
	}
	desc := ""
	if v, ok := params["description"]; ok {
		desc, _ = v.(string)
	}
	if desc == "" {
		if v, ok := params["action"]; ok {
			desc, _ = v.(string)
		}
	}
	if desc == "" {
		desc = "manual action required (no description provided)"
	}
	return &api.StepResult{
		Success: true,
		Detail:  "manual: " + desc,
	}, nil
}
