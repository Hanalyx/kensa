package configset_test

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/handlers/configset"
)

// config_set declares its single edited file (pre.Data["file"]) to the gate.
//
// @spec footprint-funnel
// @ac AC-04
func TestCapturedFootprint(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	var fp footprint.Footprinter = configset.New()
	f, err := fp.CapturedFootprint(&api.PreState{
		Data: map[string]interface{}{"file": "/etc/ssh/sshd_config"},
	})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	if !f.Has("/etc/ssh/sshd_config") || f.Len() != 1 {
		t.Errorf("footprint = %v, want exactly /etc/ssh/sshd_config", f.Entries())
	}
}
