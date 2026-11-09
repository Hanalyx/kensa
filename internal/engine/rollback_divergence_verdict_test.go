package engine_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
)

// These cases state the rollback verdict for a recaptured post-state that
// differs from the captured pre-state, before the change that makes it hold.
// Today the engine appends "[post-state: DIVERGES from pre-state]" to the
// step detail and keeps the status the handler reported. The rule to come:
// an observed divergence overrides the handler's report, the transaction is
// rollback_failed, and the step carries a typed PostStateDiverged flag. The
// flag does not exist yet, so the cases read it through JSON.
//
// @spec engine-transaction
// @ac AC-23, AC-24 (extended with the verdict rule; the new criteria are not in the spec yet)

// postStateHandler captures pre on the first call and post on every later
// call (the recapture), and reports every rollback as clean. A nil post
// makes the recapture fail, so the post-state is unobserved.
type postStateHandler struct {
	name string
	pre  map[string]interface{}
	post map[string]interface{}

	mu    sync.Mutex
	calls int
}

func (h *postStateHandler) Name() string     { return h.name }
func (h *postStateHandler) Capturable() bool { return true }
func (h *postStateHandler) Apply(context.Context, api.Transport, api.Params, *api.PreState) (*api.StepResult, error) {
	return &api.StepResult{Success: true}, nil
}

func (h *postStateHandler) Capture(context.Context, api.Transport, api.Params) (*api.PreState, error) {
	h.mu.Lock()
	h.calls++
	n := h.calls
	h.mu.Unlock()
	if n == 1 {
		return &api.PreState{Data: h.pre}, nil
	}
	if h.post == nil {
		return nil, errors.New("induced recapture failure")
	}
	return &api.PreState{Data: h.post}, nil
}

func (h *postStateHandler) Rollback(context.Context, api.Transport, *api.PreState) (*api.RollbackResult, error) {
	return &api.RollbackResult{Success: true, Detail: "restored"}, nil
}

func runRollback(t *testing.T, h *postStateHandler) *api.TransactionResult {
	t.Helper()
	r := handler.NewRegistry()
	r.Register(h)
	e := engine.New(engine.WithRegistry(r), engine.WithForceValidateFail())
	res, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn(h.name), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if len(res.RollbackResults) != 1 {
		t.Fatalf("want one rollback result, got %d", len(res.RollbackResults))
	}
	return res
}

func TestRollback_DivergedPostStateVerdict(t *testing.T) {
	t.Run("divergence demotes to rollback_failed with a typed flag", func(t *testing.T) {
		res := runRollback(t, &postStateHandler{
			name: "div_diverge",
			pre:  map[string]interface{}{"content": "PermitRootLogin no"},
			post: map[string]interface{}{"content": "PermitRootLogin yes"},
		})
		rb := res.RollbackResults[0]
		if !strings.Contains(rb.Detail, "[post-state: DIVERGES from pre-state]") {
			t.Fatalf("fixture did not diverge; detail is %q", rb.Detail)
		}
		if res.Status != api.StatusRollbackFailed {
			t.Errorf("an observed divergence did not override the handler's clean report: "+
				"status is %s, want rollback_failed", res.Status)
		}
		if v, ok := jsonBool(t, rb, "PostStateDiverged"); !ok || !v {
			t.Errorf("no typed flag on the diverging step: PostStateDiverged present=%v value=%v; "+
				"only the Detail text says DIVERGES", ok, v)
		}
	})

	t.Run("match keeps rolled_back", func(t *testing.T) {
		state := map[string]interface{}{"content": "PermitRootLogin no"}
		res := runRollback(t, &postStateHandler{name: "div_match", pre: state, post: state})
		rb := res.RollbackResults[0]
		if !strings.Contains(rb.Detail, "[post-state: matches pre-state]") {
			t.Fatalf("fixture did not match; detail is %q", rb.Detail)
		}
		if res.Status != api.StatusRolledBack {
			t.Errorf("a matching post-state changed the verdict: got %s, want rolled_back", res.Status)
		}
		if v, _ := jsonBool(t, rb, "PostStateDiverged"); v {
			t.Error("a matching step carries PostStateDiverged=true")
		}
	})

	t.Run("unobserved keeps the handler's status and its marker", func(t *testing.T) {
		res := runRollback(t, &postStateHandler{
			name: "div_unobserved",
			pre:  map[string]interface{}{"content": "PermitRootLogin no"},
		})
		rb := res.RollbackResults[0]
		if !strings.Contains(rb.Detail, "[post-state: unobserved]") {
			t.Errorf("an unobserved post-state lost its marker; detail is %q", rb.Detail)
		}
		if res.Status != api.StatusRolledBack {
			t.Errorf("an unobserved post-state changed the verdict: got %s, want rolled_back", res.Status)
		}
		if v, _ := jsonBool(t, rb, "PostStateDiverged"); v {
			t.Error("an unobserved step carries PostStateDiverged=true")
		}
	})
}

// Compile-time check that the handler satisfies the interface the registry
// takes.
var _ api.Handler = (*postStateHandler)(nil)
