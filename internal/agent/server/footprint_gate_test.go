package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/agent/wirev1"
	"github.com/Hanalyx/kensa/internal/handler"
)

// fakeFootprintHandler drives the agent-side gate/probe wiring end-to-end:
// Apply writes writePath through the transport funnel (so the recorder
// observes it), and CapturedFootprint declares declarePath. When the two
// differ, the gate must catch the uncaptured write; with the immutability
// probe injected, the pre-apply probe must refuse before Apply runs.
type fakeFootprintHandler struct {
	name        string
	writePath   string // file Apply writes via the funnel; "" = no write
	declarePath string // path CapturedFootprint declares
	applyCalled bool
}

func (h *fakeFootprintHandler) Name() string     { return h.name }
func (h *fakeFootprintHandler) Capturable() bool { return true }

func (h *fakeFootprintHandler) Apply(ctx context.Context, tr api.Transport, _ api.Params, _ *api.PreState) (*api.StepResult, error) {
	h.applyCalled = true
	if h.writePath != "" {
		ft, ok := tr.(interface {
			AtomicWrite(context.Context, string, string, os.FileMode, []byte) error
		})
		if !ok {
			return &api.StepResult{Success: false, Detail: "transport lacks AtomicWrite"}, nil
		}
		dir, base := filepath.Dir(h.writePath), filepath.Base(h.writePath)
		if err := ft.AtomicWrite(ctx, dir, base, 0o644, []byte("x")); err != nil {
			return &api.StepResult{Success: false, Detail: err.Error()}, nil
		}
	}
	return &api.StepResult{Success: true, Detail: "applied"}, nil
}

func (h *fakeFootprintHandler) CapturedFootprint(_ *api.PreState) (*footprint.Footprint, error) {
	f := footprint.New()
	f.Add(footprint.Entry{Path: h.declarePath, Op: footprint.OpModify})
	return f, nil
}

// applyWithPreState sends an ApplyRequest carrying a (minimal) pre-state, so
// the opt-in gate/probe — which fire only when pre != nil — engage.
func applyWithPreState(t *testing.T, mechanism string) *wirev1.Response {
	t.Helper()
	wirePre, err := wirev1.APIPreStateToWire(api.PreState{
		Mechanism: mechanism, Capturable: true,
		Data: map[string]interface{}{"marker": "x"},
	})
	if err != nil {
		t.Fatalf("APIPreStateToWire: %v", err)
	}
	return Handle(&wirev1.Request{
		SchemaVersion: 1, CorrelationId: 1,
		Payload: &wirev1.Request_Apply{Apply: &wirev1.ApplyRequest{
			Mechanism: mechanism,
			PreState:  wirePre,
		}},
	})
}

// The pre-commit gate catches an apply that writes a resource it did not
// capture: the step fails (Success=false) so the controller rolls back.
//
// @spec footprint-funnel
// @ac AC-04
func TestDispatchApply_GateCatchesUncapturedWrite(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	dir := t.TempDir()
	h := &fakeFootprintHandler{
		name:        "p6_gate_uncaptured",
		writePath:   filepath.Join(dir, "written"),  // observed
		declarePath: filepath.Join(dir, "declared"), // captured (different)
	}
	handler.Default().Register(h)

	resp := applyWithPreState(t, h.name)
	sr := resp.GetApplyResp().GetStepResult()
	if sr == nil {
		t.Fatalf("no StepResult; resp=%+v", resp)
	}
	if sr.GetSuccess() {
		t.Errorf("gate should have failed the step for an uncaptured write; detail=%q", sr.GetDetail())
	}
	if !strings.Contains(sr.GetDetail(), "footprint gate") {
		t.Errorf("detail = %q, want a footprint-gate message", sr.GetDetail())
	}
}

// The pre-apply restorability probe refuses (without running Apply) when a
// captured resource is immutable.
//
// @spec footprint-funnel
// @ac AC-05
func TestDispatchApply_RefusesImmutableCaptured(t *testing.T) {
	t.Run("footprint-funnel/AC-05", func(t *testing.T) {})
	h := &fakeFootprintHandler{
		name:        "p6_probe_immutable",
		declarePath: "/etc/kensa-p6-immutable-fake",
	}
	handler.Default().Register(h)

	// Inject: the declared path reads back immutable.
	orig := immutableProbe
	immutableProbe = func(p string) (bool, error) { return p == h.declarePath, nil }
	defer func() { immutableProbe = orig }()

	resp := applyWithPreState(t, h.name)
	sr := resp.GetApplyResp().GetStepResult()
	if sr == nil {
		t.Fatalf("no StepResult; resp=%+v", resp)
	}
	if sr.GetSuccess() {
		t.Errorf("probe should have refused an immutable captured resource; detail=%q", sr.GetDetail())
	}
	if !strings.Contains(sr.GetDetail(), "restorability gate") {
		t.Errorf("detail = %q, want a restorability-gate message", sr.GetDetail())
	}
	if h.applyCalled {
		t.Error("Apply must NOT run when the probe refuses (no mutation before refusal)")
	}
}
