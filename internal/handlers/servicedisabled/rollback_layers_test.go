package servicedisabled_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/servicedbus"
	"github.com/Hanalyx/kensa/internal/handlers/servicedisabled"
)

// TestRollbackRestoresBothLayersIndependently is the matrix the over-restore
// slipped through.
//
// A unit has two independent captured layers, enable and active, so there
// are four prior states and each has exactly one correct restoration.
// Rollback previously collapsed the enabled cases into `enable --now`, which
// is correct for one of the four and starts a stopped unit in another. A
// single-case test could not see that; the matrix is the point.
//
// Restoring MORE than was taken away is a restoration failure. Rolling back
// a disable of rsyncd, nfs-server or avahi-daemon (all in the corpus) under
// the old behavior left a listening network daemon running on a host that
// had it stopped, and reported success.
//
// @spec handler-service-disabled
// @ac AC-05
func TestRollbackRestoresBothLayersIndependently(t *testing.T) {
	t.Log("// @spec handler-service-disabled")
	t.Log("// @ac AC-05")

	for _, tc := range []struct {
		name          string
		priorEnabled  string
		priorActive   string
		wantCommands  []string
		forbidCommand []string
	}{{
		name:         "enabled and running: enable and start, --now covers both",
		priorEnabled: "enabled",
		priorActive:  "active",
		wantCommands: []string{"systemctl enable --now"},
	}, {
		name:          "enabled but stopped: enable only, never start",
		priorEnabled:  "enabled",
		priorActive:   "inactive",
		wantCommands:  []string{"systemctl enable "},
		forbidCommand: []string{"--now", "systemctl start"},
	}, {
		name:          "not enabled but running: start only, never enable",
		priorEnabled:  "disabled",
		priorActive:   "active",
		wantCommands:  []string{"systemctl start"},
		forbidCommand: []string{"systemctl enable"},
	}, {
		name:          "neither: no command at all",
		priorEnabled:  "disabled",
		priorActive:   "inactive",
		forbidCommand: []string{"systemctl"},
	}, {
		name:          "static unit that was running: start, never enable",
		priorEnabled:  "static",
		priorActive:   "active",
		wantCommands:  []string{"systemctl start"},
		forbidCommand: []string{"systemctl enable"},
	}} {
		t.Run("shell/"+tc.name, func(t *testing.T) {
			tp := engine.NewFakeTransport()
			res, err := servicedisabled.New().Rollback(context.Background(), tp, &api.PreState{
				Data: map[string]interface{}{
					"name": "rsyncd", "prior_enabled": tc.priorEnabled, "prior_active": tc.priorActive,
				},
			})
			if err != nil {
				t.Fatalf("Rollback: %v", err)
			}
			if !res.Success {
				t.Errorf("Success=false: %s", res.Detail)
			}
			joined := strings.Join(tp.Runs, " ; ")
			for _, want := range tc.wantCommands {
				if !strings.Contains(joined, want) {
					t.Errorf("commands %q do not contain %q", joined, want)
				}
			}
			for _, forbid := range tc.forbidCommand {
				if strings.Contains(joined, forbid) {
					t.Errorf("commands %q contain forbidden %q", joined, forbid)
				}
			}
		})

		t.Run("dbus/"+tc.name, func(t *testing.T) {
			f := servicedbus.NewFake()
			res, err := servicedisabled.New().Rollback(context.Background(), f, &api.PreState{
				Data: map[string]interface{}{
					"name": "rsyncd", "prior_enabled": tc.priorEnabled, "prior_active": tc.priorActive,
				},
			})
			if err != nil {
				t.Fatalf("Rollback (dbus): %v", err)
			}
			if !res.Success {
				t.Errorf("Success=false: %s", res.Detail)
			}
			calls := strings.Join(f.Calls, " ; ")
			// The D-Bus path has no --now; enable and start are separate ops,
			// which is precisely why it must decide them separately.
			wantEnable := tc.priorEnabled == "enabled" || tc.priorEnabled == "enabled-runtime"
			wantStart := tc.priorActive == "active"
			if got := strings.Contains(calls, "enable"); got != wantEnable {
				t.Errorf("enable op = %v, want %v (calls: %q)", got, wantEnable, calls)
			}
			if got := strings.Contains(calls, "start"); got != wantStart {
				t.Errorf("start op = %v, want %v (calls: %q)", got, wantStart, calls)
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
	res, err := servicedisabled.New().Rollback(context.Background(), tp, &api.PreState{
		Data: map[string]interface{}{
			"name": "rsyncd", "prior_enabled": "active", "prior_active": "enabled",
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
