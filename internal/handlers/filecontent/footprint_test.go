package filecontent_test

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/handlers/filecontent"
)

// file_content declares its single captured file to the gate.
//
// @spec footprint-funnel
// @ac AC-04
func TestCapturedFootprint(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	var fp footprint.Footprinter = filecontent.New()
	f, err := fp.CapturedFootprint(&api.PreState{
		Data: map[string]interface{}{"path": "/etc/issue", "file_existed": true},
	})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	if !f.Has("/etc/issue") || f.Len() != 1 {
		t.Errorf("footprint = %v, want exactly /etc/issue", f.Entries())
	}
}
