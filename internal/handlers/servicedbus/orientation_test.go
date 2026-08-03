package servicedbus_test

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/handlers/servicedbus"
)

// TestCheckPreStateOrientationRejectsTransposedRecords covers the records
// that are already in operators' transaction logs.
//
// @spec service-unit-state-parse
// @ac AC-07
func TestCheckPreStateOrientationRejectsTransposedRecords(t *testing.T) {
	t.Run("service-unit-state-parse/AC-07", func(t *testing.T) {})

	for _, tc := range []struct {
		name         string
		priorEnabled string
		priorActive  string
		wantRejected bool
	}{{
		// The shape a pre-fix capture of an enabled, running unit produced.
		name:         "transposed: enabled and running",
		priorEnabled: "active",
		priorActive:  "enabled",
		wantRejected: true,
	}, {
		name:         "transposed: disabled and stopped",
		priorEnabled: "inactive",
		priorActive:  "disabled",
		wantRejected: true,
	}, {
		name:         "transposed: masked and failed",
		priorEnabled: "failed",
		priorActive:  "masked",
		wantRejected: true,
	}, {
		name:         "correct: enabled and running",
		priorEnabled: "enabled",
		priorActive:  "active",
	}, {
		name:         "correct: static and running",
		priorEnabled: "static",
		priorActive:  "active",
	}, {
		// A unit that does not exist: UnitFileState is empty. Legitimate,
		// and must not be mistaken for a transposition.
		name:        "correct: unknown unit leaves prior_enabled empty",
		priorActive: "inactive",
	}, {
		name: "correct: both empty",
	}, {
		// Forward compatibility: systemd gains property values over time.
		// An unrecognized value is not proof of transposition, and refusing
		// it would turn a version gap into an outage.
		name:         "unrecognized UnitFileState is allowed through",
		priorEnabled: "some-future-state",
		priorActive:  "active",
	}, {
		name:         "unrecognized ActiveState is allowed through",
		priorEnabled: "enabled",
		priorActive:  "some-future-state",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			err := servicedbus.CheckPreStateOrientation(tc.priorEnabled, tc.priorActive)
			if tc.wantRejected && err == nil {
				t.Errorf("prior_enabled=%q prior_active=%q accepted; want rejected as transposed",
					tc.priorEnabled, tc.priorActive)
			}
			if !tc.wantRejected && err != nil {
				t.Errorf("prior_enabled=%q prior_active=%q rejected: %v", tc.priorEnabled, tc.priorActive, err)
			}
			if tc.wantRejected && err != nil && !strings.Contains(err.Error(), "kensa check") {
				t.Errorf("rejection does not tell the operator what to do instead: %v", err)
			}
		})
	}
}

// TestPropertyDomainsAreDisjoint is the premise the guard rests on. If a
// future systemd introduced a value shared by both properties, detection
// would produce false positives and refuse legitimate rollbacks.
//
// @spec service-unit-state-parse
// @ac AC-07
func TestPropertyDomainsAreDisjoint(t *testing.T) {
	t.Run("service-unit-state-parse/AC-07", func(t *testing.T) {})

	// Exercised through the exported guard: a value in both domains would
	// make this pair report a transposition, since it would satisfy both
	// halves of the test.
	for _, v := range []string{
		"enabled", "enabled-runtime", "linked", "alias", "masked", "static",
		"indirect", "disabled", "generated", "transient", "bad",
	} {
		if err := servicedbus.CheckPreStateOrientation(v, v); err != nil {
			t.Errorf("UnitFileState value %q is also treated as an ActiveState: %v", v, err)
		}
	}
	for _, v := range []string{
		"active", "reloading", "inactive", "failed", "activating",
		"deactivating", "maintenance",
	} {
		if err := servicedbus.CheckPreStateOrientation(v, v); err != nil {
			t.Errorf("ActiveState value %q is also treated as a UnitFileState: %v", v, err)
		}
	}
}
