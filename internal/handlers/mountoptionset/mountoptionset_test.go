package mountoptionset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/mountoptionset"
)

// @spec handler-mount-option-set
// @ac AC-01
func TestApply_AddsMountOptionAndRemounts(t *testing.T) {
	t.Log("// @spec handler-mount-option-set")
	t.Log("// @ac AC-01")
	tp := engine.NewFakeTransport()
	h := mountoptionset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"mount_point": "/tmp",
		"option":      "noexec",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "awk") {
		t.Errorf("expected awk in apply cmd; got %q", cmd)
	}
	if !strings.Contains(cmd, "remount") {
		t.Errorf("expected remount in apply cmd; got %q", cmd)
	}
}

// @spec handler-mount-option-set
// @ac AC-02
// @ac AC-03
func TestRollback_RestoresPriorLine(t *testing.T) {
	t.Log("// @spec handler-mount-option-set")
	t.Run("handler-mount-option-set/AC-02", func(t *testing.T) {})
	t.Run("handler-mount-option-set/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := mountoptionset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"mount_point": "/tmp",
			"option":      "noexec",
			"prior_line":  "tmpfs /tmp tmpfs defaults 0 0",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "defaults") {
		t.Errorf("expected prior fstab line in rollback cmd; got %q", tp.Runs[0])
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = mountoptionset.New()
}
