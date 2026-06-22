package configsetdropin

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

const dropinPath = "/etc/dconf/db/local.d/00-login"

// Capture records the absent ancestor directories Apply will create.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-config-set-dropin
// @ac AC-07
func TestCapture_RecordsCreatedDirs(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-config-set-dropin/AC-07", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	params := api.Params{"dir": "/etc/dconf/db/local.d", "file": "00-login", "key": "x", "value": "y"}
	// Program the file check (absent) and the missing-dirs probe.
	f.RunResults = map[string]*api.CommandResult{
		missingAncestorDirsCmd(dropinPath): {Stdout: "/etc/dconf/db/local.d\n/etc/dconf/db\n"},
	}
	pre, err := New().Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	got, _ := pre.Data["created_dirs"].(string)
	if !strings.Contains(got, "/etc/dconf/db/local.d") || !strings.Contains(got, "/etc/dconf/db") {
		t.Errorf("created_dirs = %q, want the two absent levels", got)
	}
}

// Apply routes MkdirAll through the transport (the funnel), not os.MkdirAll —
// so the recorder can observe the created directories.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-config-set-dropin
// @ac AC-07
func TestApply_FunnelsMkdirAll(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-config-set-dropin/AC-07", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	params := api.Params{"dir": "/etc/dconf/db/local.d", "file": "00-login", "key": "x", "value": "y"}
	res, err := New().Apply(context.Background(), f, params, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	// FakeSysctlTransport.MkdirAll records into Dirs.
	var sawDir bool
	for _, d := range f.Dirs {
		if d == "/etc/dconf/db/local.d" {
			sawDir = true
		}
	}
	if !sawDir {
		t.Errorf("MkdirAll did not go through the transport funnel; Dirs=%v", f.Dirs)
	}
}

// Rollback rmdir's the created directories (deepest first), best-effort.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-config-set-dropin
// @ac AC-07
func TestRollback_RemovesCreatedDirs(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-config-set-dropin/AC-07", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Files[dropinPath] = "old"
	pre := &api.PreState{
		Mechanism: mechanism,
		Data: map[string]interface{}{
			"path": dropinPath, "file_existed": false, "prior_content": "",
			"created_dirs": "/etc/dconf/db/local.d\n/etc/dconf/db",
		},
	}
	if _, err := New().Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	var rmdirs []string
	for _, c := range f.Runs {
		if strings.HasPrefix(c, "rmdir ") {
			rmdirs = append(rmdirs, c)
		}
	}
	if len(rmdirs) != 2 {
		t.Fatalf("expected 2 rmdir calls (deepest first); got %v", rmdirs)
	}
	if !strings.Contains(rmdirs[0], "/etc/dconf/db/local.d") {
		t.Errorf("first rmdir should be the deepest level; got %q", rmdirs[0])
	}
}
