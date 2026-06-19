package servicemasked_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/handlers/servicedbus"
	"github.com/Hanalyx/kensa/internal/handlers/servicemasked"
)

// D-Bus path: Apply issues mask then stop.
//
// @spec service-dbus-consumption
// @ac AC-05
func TestApply_DBus_MaskThenStop(t *testing.T) {
	t.Run("service-dbus-consumption/AC-05", func(t *testing.T) {})
	f := servicedbus.NewFake()
	res, err := servicemasked.New().Apply(context.Background(), f, api.Params{"name": "avahi-daemon"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v", err, res.Success)
	}
	if want := []string{"mask", "stop"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}

// D-Bus path: Rollback unmasks first, then re-enables + starts a unit
// whose captured prior state was enabled+active.
//
// @spec service-dbus-consumption
// @ac AC-05
func TestRollback_DBus_UnmaskThenEnableStart(t *testing.T) {
	t.Run("service-dbus-consumption/AC-05", func(t *testing.T) {})
	f := servicedbus.NewFake()
	pre := servicedbus.PreState("service_masked", "avahi-daemon", "enabled", "active")
	res, err := servicemasked.New().Rollback(context.Background(), f, pre)
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, res.Success)
	}
	if want := []string{"unmask", "enable", "start"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}

// D-Bus path: Rollback of a unit whose prior state was disabled+inactive
// unmasks and stops there — unmask is the only restoration step.
//
// @spec service-dbus-consumption
// @ac AC-05
func TestRollback_DBus_UnmaskOnly(t *testing.T) {
	t.Run("service-dbus-consumption/AC-05", func(t *testing.T) {})
	f := servicedbus.NewFake()
	pre := servicedbus.PreState("service_masked", "avahi-daemon", "disabled", "inactive")
	res, err := servicemasked.New().Rollback(context.Background(), f, pre)
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, res.Success)
	}
	if want := []string{"unmask"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}
