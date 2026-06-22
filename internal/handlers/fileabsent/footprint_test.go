package fileabsent_test

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/handlers/fileabsent"
)

// file_absent declares its single captured file to the gate.
//
// @spec footprint-funnel
// @ac AC-04
func TestCapturedFootprint(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	var fp footprint.Footprinter = fileabsent.New()
	f, err := fp.CapturedFootprint(&api.PreState{
		Data: map[string]interface{}{"path": "/etc/insecure.conf", "file_existed": true},
	})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	if !f.Has("/etc/insecure.conf") || f.Len() != 1 {
		t.Errorf("footprint = %v, want exactly /etc/insecure.conf", f.Entries())
	}
}
