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

// TestRollbackRefusesTransposedPreState covers the records already sitting in
// operators' transaction logs.
//
// Capture is fixed, but every service transaction recorded before that fix
// holds prior_enabled and prior_active transposed, and rollback cannot tell
// them apart by shape: both are non-empty strings. Acting on one drives the
// unit toward a state the host was never in and reports success. Fail closed
// instead, and issue no command at all.
//
// @spec service-unit-state-parse
// @ac AC-08
func TestRollbackRefusesTransposedPreState(t *testing.T) {
	t.Run("service-unit-state-parse/AC-08", func(t *testing.T) {})

	tp := engine.NewFakeTransport()
	// The exact shape a pre-fix capture of an enabled, running unit wrote.
	res, err := servicemasked.New().Rollback(context.Background(), tp, &api.PreState{
		Data: map[string]interface{}{
			"name": "cups", "prior_enabled": "active", "prior_active": "enabled",
		},
	})
	if err != nil {
		t.Fatalf("Rollback returned an error; want a failed result: %v", err)
	}
	if res.Success {
		t.Errorf("rollback acted on a transposed pre-state and reported success: %s", res.Detail)
	}
	if len(tp.Runs) != 0 {
		t.Errorf("rollback issued commands against a transposed pre-state: %v", tp.Runs)
	}
	if !strings.Contains(res.Detail, "kensa check") {
		t.Errorf("detail does not tell the operator what to do instead: %q", res.Detail)
	}
}
