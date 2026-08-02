package serviceenabled_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/serviceenabled"
)

// TestRollbackRestoresBothLayersIndependently is the sibling of the matrix
// that caught service_disabled over-restoring. It exists to prove this
// handler does NOT share that defect, rather than to assert it from reading
// the code: a unit's enable and active layers are captured independently, so
// all four prior states must restore independently, and restoring more than
// was taken away is a restoration failure just as much as restoring less.
//
// @spec handler-service-enabled
// @ac AC-05
func TestRollbackRestoresBothLayersIndependently(t *testing.T) {
	t.Log("// @spec handler-service-enabled")
	t.Log("// @ac AC-05")

	for _, tc := range []struct {
		name         string
		priorEnabled string
		priorActive  string
		want         []string
		forbid       []string
	}{{
		// Apply ran `enable --now`. Prior was already both, so apply was a
		// no-op and rollback must not touch the unit.
		name:         "enabled and running: nothing to undo",
		priorEnabled: "enabled",
		priorActive:  "active",
		forbid:       []string{"systemctl"},
	}, {
		// Apply started it. Undo the start, leave the enable alone.
		name:         "enabled but stopped: stop only, never disable",
		priorEnabled: "enabled",
		priorActive:  "inactive",
		want:         []string{"systemctl stop"},
		forbid:       []string{"systemctl disable"},
	}, {
		// Apply enabled it; it was already running, so it must stay running.
		name:         "not enabled but running: disable only, never stop",
		priorEnabled: "disabled",
		priorActive:  "active",
		want:         []string{"systemctl disable"},
		forbid:       []string{"systemctl stop"},
	}, {
		name:         "neither: disable and stop",
		priorEnabled: "disabled",
		priorActive:  "inactive",
		want:         []string{"systemctl disable", "systemctl stop"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			tp := engine.NewFakeTransport()
			res, err := serviceenabled.New().Rollback(context.Background(), tp, &api.PreState{
				Data: map[string]interface{}{
					"name": "auditd", "prior_enabled": tc.priorEnabled, "prior_active": tc.priorActive,
				},
			})
			if err != nil {
				t.Fatalf("Rollback: %v", err)
			}
			if !res.Success {
				t.Errorf("Success=false: %s", res.Detail)
			}
			joined := strings.Join(tp.Runs, " ; ")
			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Errorf("commands %q do not contain %q", joined, want)
				}
			}
			for _, forbid := range tc.forbid {
				if strings.Contains(joined, forbid) {
					t.Errorf("commands %q contain forbidden %q", joined, forbid)
				}
			}
		})
	}
}
