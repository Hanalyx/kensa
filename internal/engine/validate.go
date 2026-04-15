package engine

import (
	"context"

	"github.com/Hanalyx/kensa-go/api"
)

// validate runs the post-apply round-trip check plus any declared
// dependent validators (engine-transaction spec: VALIDATE phase).
//
// The current Week-2 implementation returns success with no validators
// because the rule's Check structure is not yet decoded into runnable
// form by the engine layer — that work lands with the rule parser
// integration in Week 21 per KENSA_GO_DAY1_PLAN.md §11.5. Until then,
// a successful APPLY phase is treated as a successful VALIDATE phase.
//
// TODO(week-21): wire api.Rule.Implementations[selected].Check through
// internal/checks and run the post-apply re-check.
// TODO(week-21): support dependent validators (service health, config
// syntax, control-channel reachability).
func (e *Engine) validate(_ context.Context, _ api.Transport, _ *api.Transaction) ([]api.ValidatorResult, bool) {
	return nil, true
}
