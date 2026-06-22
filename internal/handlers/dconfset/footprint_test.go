package dconfset_test

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/handlers/dconfset"
)

// CapturedFootprint declares the snippet, lock, shared profile, and every
// created directory, so the gate covers everything Apply funnels.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-dconf-set
// @ac AC-10
func TestCapturedFootprint_DeclaresAll(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-dconf-set/AC-10", func(t *testing.T) {})
	var fp footprint.Footprinter = dconfset.New()
	f, err := fp.CapturedFootprint(&api.PreState{
		Data: map[string]interface{}{
			"file_path":       "/etc/dconf/db/local.d/00-login",
			"lock_path":       "/etc/dconf/db/local.d/locks/00-login",
			"profile_path":    "/etc/dconf/profile/local",
			"db_dir":          "/etc/dconf/db/local.d",
			"profile_existed": false,
			"created_dirs":    "/etc/dconf/db/local.d/locks\n/etc/dconf/db/local.d",
		},
	})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	for _, want := range []string{
		"/etc/dconf/db/local.d/00-login",
		"/etc/dconf/db/local.d/locks/00-login",
		"/etc/dconf/profile/local",
		"/etc/dconf/db/local.d/locks",
		"/etc/dconf/db/local.d",
	} {
		if !f.Has(want) {
			t.Errorf("footprint missing %s; got %v", want, f.Entries())
		}
	}
}
