package servicemasked_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/servicemasked"
)

// TestRollbackRestoresBothLayersIndependently is the sibling of the matrix
// that caught service_disabled over-restoring. It exists to prove this
// handler does NOT share that defect, rather than to assert it from reading
// the code: a unit's enable and active layers are captured independently, so
// all four prior states must restore independently, and restoring more than
// was taken away is a restoration failure just as much as restoring less.
//
// @spec handler-service-masked
// @ac AC-05
func TestRollbackRestoresBothLayersIndependently(t *testing.T) {
	t.Log("// @spec handler-service-masked")
	t.Log("// @ac AC-05")

	for _, tc := range []struct {
		name         string
		priorEnabled string
		priorActive  string
		want         []string
		forbid       []string
	}{{
		name:         "enabled and running: unmask then enable --now",
		priorEnabled: "enabled",
		priorActive:  "active",
		want:         []string{"systemctl unmask", "enable --now"},
	}, {
		name:         "enabled but stopped: unmask and enable, never start",
		priorEnabled: "enabled",
		priorActive:  "inactive",
		want:         []string{"systemctl unmask", "systemctl enable "},
		forbid:       []string{"--now", "systemctl start"},
	}, {
		name:         "not enabled but running: unmask and start, never enable",
		priorEnabled: "disabled",
		priorActive:  "active",
		want:         []string{"systemctl unmask", "systemctl start"},
		forbid:       []string{"systemctl enable"},
	}, {
		name:         "neither: unmask only",
		priorEnabled: "disabled",
		priorActive:  "inactive",
		want:         []string{"systemctl unmask"},
		forbid:       []string{"systemctl enable", "systemctl start"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			tp := engine.NewFakeTransport()
			res, err := servicemasked.New().Rollback(context.Background(), tp, &api.PreState{
				Data: map[string]interface{}{
					"name": "cups", "prior_enabled": tc.priorEnabled, "prior_active": tc.priorActive,
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
