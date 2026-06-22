package dconfset

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
)

// decodeParams rejects a db/file that is not a single path component, so a
// crafted rule cannot compose a path escaping the dconf tree.
//
// @spec handler-dconf-set
// @ac AC-08
func TestDecodeParams_RejectsPathTraversal(t *testing.T) {
	t.Run("handler-dconf-set/AC-08", func(t *testing.T) {})
	base := api.Params{"schema": "org/gnome/x", "key": "k", "value": "v", "file": "00-x"}
	cases := []api.Params{
		{"schema": "org/gnome/x", "key": "k", "value": "v", "file": "../../etc/cron.d/evil"},
		{"schema": "org/gnome/x", "key": "k", "value": "v", "file": "sub/evil"},
		{"schema": "org/gnome/x", "key": "k", "value": "v", "file": "00-x", "db": "../escape"},
	}
	// Sanity: the base (clean) params decode fine.
	if _, err := decodeParams(base); err != nil {
		t.Fatalf("clean params should decode: %v", err)
	}
	for _, p := range cases {
		if _, err := decodeParams(p); err == nil {
			t.Errorf("expected rejection for traversal params %v", p)
		}
	}
}

// Capture records the created directories and that the profile was absent.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-dconf-set
// @ac AC-10
func TestCapture_RecordsDirsAndProfile(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-dconf-set/AC-10", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	params := api.Params{"schema": "org/gnome/login-screen", "key": "disable-user-list", "value": "true", "file": "00-login", "lock": true}
	p, _ := decodeParams(params)
	paths := pathsFor(p)
	f.RunResults = map[string]*api.CommandResult{
		missingAncestorDirsCmd(paths.locksD): {Stdout: paths.locksD + "\n" + paths.dbDir + "\n"},
	}
	pre, err := New().Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["profile_existed"] != false {
		t.Errorf("want profile_existed=false, got %v", pre.Data["profile_existed"])
	}
	if pre.Data["db_dir"] != paths.dbDir {
		t.Errorf("db_dir = %v, want %s", pre.Data["db_dir"], paths.dbDir)
	}
	cd, _ := pre.Data["created_dirs"].(string)
	if !strings.Contains(cd, paths.dbDir) || !strings.Contains(cd, paths.locksD) {
		t.Errorf("created_dirs = %q, want the db + locks dirs", cd)
	}
}

// Rollback removes the created dirs and — because the db dir is emptied (we
// created it) and we created the profile — removes the profile too.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-dconf-set
// @ac AC-10
func TestRollback_RemovesDirsAndCreatedProfile(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-dconf-set/AC-10", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	// rmdir of the db dir succeeds (empty) so the profile becomes removable.
	f.RunResults = map[string]*api.CommandResult{
		"rmdir '/etc/dconf/db/local.d' 2>/dev/null": {ExitCode: 0},
	}
	pre := &api.PreState{
		Mechanism: mechanism,
		Data: map[string]interface{}{
			"file_path": "/etc/dconf/db/local.d/00-login", "prior_content": "", "file_existed": false,
			"lock_path": "/etc/dconf/db/local.d/locks/00-login", "lock_content": "", "lock_existed": false,
			"profile_path": "/etc/dconf/profile/local", "profile_existed": false,
			"db_dir":       "/etc/dconf/db/local.d",
			"created_dirs": "/etc/dconf/db/local.d",
		},
	}
	rb, err := New().Rollback(context.Background(), f, pre)
	if err != nil || !rb.Success {
		t.Fatalf("Rollback: err=%v success=%v detail=%s", err, rb.Success, rb.Detail)
	}
	var sawRmdir, sawProfileRm bool
	for _, c := range f.Runs {
		if c == "rmdir '/etc/dconf/db/local.d' 2>/dev/null" {
			sawRmdir = true
		}
		if c == "rm -f '/etc/dconf/profile/local'" {
			sawProfileRm = true
		}
	}
	if !sawRmdir {
		t.Errorf("expected rmdir of the created db dir; Runs=%v", f.Runs)
	}
	if !sawProfileRm {
		t.Errorf("expected the created profile to be removed once the db dir was emptied; Runs=%v", f.Runs)
	}
}

// When the db dir is NOT empty (rmdir fails), the created profile is LEFT in
// place — a shared resource is reclaimed only when nothing else needs it.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-dconf-set
// @ac AC-10
func TestRollback_KeepsProfileWhenDirShared(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-dconf-set/AC-10", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	// rmdir fails (dir not empty — another snippet remains).
	f.RunResults = map[string]*api.CommandResult{
		"rmdir '/etc/dconf/db/local.d' 2>/dev/null": {ExitCode: 1, Stderr: "directory not empty"},
	}
	pre := &api.PreState{
		Mechanism: mechanism,
		Data: map[string]interface{}{
			"file_path": "/etc/dconf/db/local.d/00-login", "prior_content": "", "file_existed": false,
			"lock_path": "/etc/dconf/db/local.d/locks/00-login", "lock_content": "", "lock_existed": false,
			"profile_path": "/etc/dconf/profile/local", "profile_existed": false,
			"db_dir":       "/etc/dconf/db/local.d",
			"created_dirs": "/etc/dconf/db/local.d",
		},
	}
	if _, err := New().Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	for _, c := range f.Runs {
		if c == "rm -f '/etc/dconf/profile/local'" {
			t.Errorf("profile must NOT be removed when the db dir is still shared; Runs=%v", f.Runs)
		}
	}
}
