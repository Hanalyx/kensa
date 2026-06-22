package configsetdropin_test

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/handlers/configsetdropin"
)

// CapturedFootprint declares the drop-in file plus every created ancestor
// directory, so the gate covers the dirs Apply's MkdirAll creates.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-config-set-dropin
// @ac AC-07
func TestCapturedFootprint_FileAndDirs(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-config-set-dropin/AC-07", func(t *testing.T) {})
	var fp footprint.Footprinter = configsetdropin.New()
	f, err := fp.CapturedFootprint(&api.PreState{
		Data: map[string]interface{}{
			"path":         "/etc/dconf/db/local.d/00-login",
			"file_existed": false,
			"created_dirs": "/etc/dconf/db/local.d\n/etc/dconf/db",
		},
	})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	for _, want := range []string{
		"/etc/dconf/db/local.d/00-login",
		"/etc/dconf/db/local.d",
		"/etc/dconf/db",
	} {
		if !f.Has(want) {
			t.Errorf("footprint missing %s; got %v", want, f.Entries())
		}
	}
	if f.Len() != 3 {
		t.Errorf("footprint len = %d, want 3", f.Len())
	}
}

// With no created dirs, the footprint is just the file.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-config-set-dropin
// @ac AC-07
func TestCapturedFootprint_NoDirs(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	var fp footprint.Footprinter = configsetdropin.New()
	f, err := fp.CapturedFootprint(&api.PreState{
		Data: map[string]interface{}{
			"path": "/etc/sysctl.d/99-k.conf", "file_existed": true, "created_dirs": "",
		},
	})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	if f.Len() != 1 || !f.Has("/etc/sysctl.d/99-k.conf") {
		t.Errorf("footprint = %v, want just the file", f.Entries())
	}
}
