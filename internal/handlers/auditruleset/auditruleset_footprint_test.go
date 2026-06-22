package auditruleset_test

import (
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

// audit_rule_set declares its single captured drop-in file to the pre-commit
// gate. The netlink rule load/unload is not a filesystem mutation, so the
// drop-in is the entire captured footprint.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-audit-rule-set
// @ac AC-05
func TestCapturedFootprint(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-audit-rule-set/AC-05", func(t *testing.T) {})

	var fp footprint.Footprinter = auditruleset.New()
	f, err := fp.CapturedFootprint(&api.PreState{Data: map[string]interface{}{
		"path":         auditPath,
		"file_existed": false,
	}})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	if !f.Has(auditPath) || f.Len() != 1 {
		t.Errorf("footprint = %v, want exactly %s", f.Entries(), auditPath)
	}
}
