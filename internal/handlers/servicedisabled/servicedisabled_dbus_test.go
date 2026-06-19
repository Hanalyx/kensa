package servicedisabled_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/handlers/servicedbus"
	"github.com/Hanalyx/kensa/internal/handlers/servicedisabled"
)

// D-Bus path: Apply issues disable then stop.
//
// @spec service-dbus-consumption
// @ac AC-04
func TestApply_DBus_DisableThenStop(t *testing.T) {
	t.Run("service-dbus-consumption/AC-04", func(t *testing.T) {})
	f := servicedbus.NewFake()
	res, err := servicedisabled.New().Apply(context.Background(), f, api.Params{"name": "cups"}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v", err, res.Success)
	}
	if want := []string{"disable", "stop"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}

// D-Bus path: prior enabled+active rolls back via enable + start.
//
// @spec service-dbus-consumption
// @ac AC-04
func TestRollback_DBus_ReEnablesAndStarts(t *testing.T) {
	t.Run("service-dbus-consumption/AC-04", func(t *testing.T) {})
	f := servicedbus.NewFake()
	pre := servicedbus.PreState("service_disabled", "cups", "enabled", "active")
	res, err := servicedisabled.New().Rollback(context.Background(), f, pre)
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, res.Success)
	}
	if want := []string{"enable", "start"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}

// D-Bus path: prior disabled-but-active rolls back via start only.
//
// @spec service-dbus-consumption
// @ac AC-04
func TestRollback_DBus_StartsOnlyWhenActiveButDisabled(t *testing.T) {
	t.Run("service-dbus-consumption/AC-04", func(t *testing.T) {})
	f := servicedbus.NewFake()
	pre := servicedbus.PreState("service_disabled", "cups", "disabled", "active")
	res, err := servicedisabled.New().Rollback(context.Background(), f, pre)
	if err != nil || !res.Success {
		t.Fatalf("Rollback: err=%v success=%v", err, res.Success)
	}
	if want := []string{"start"}; !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("ops = %v, want %v", f.Calls, want)
	}
}
