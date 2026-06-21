package dconfset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/dconfset"
)

const (
	profilePath = "/etc/dconf/profile/local"
	snippetPath = "/etc/dconf/db/local.d/00-login"
	lockPath    = "/etc/dconf/db/local.d/locks/00-login"
)

func lockedParams() api.Params {
	return api.Params{
		"schema": "org/gnome/login-screen",
		"key":    "disable-user-list",
		"value":  "true",
		"file":   "00-login",
		"lock":   true,
	}
}

// Kernel-IO Apply writes the profile / snippet / lock files atomically and
// runs `dconf update` via the shell.
//
// @spec kernelio-dconf
// @ac AC-01
func TestApply_Kernel(t *testing.T) {
	t.Run("kernelio-dconf/AC-01", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	res, err := dconfset.New().Apply(context.Background(), f, lockedParams(), nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	if !strings.Contains(f.Files[snippetPath], "[org/gnome/login-screen]") || !strings.Contains(f.Files[snippetPath], "disable-user-list=true") {
		t.Errorf("snippet = %q", f.Files[snippetPath])
	}
	if !strings.Contains(f.Files[profilePath], "system-db:local") {
		t.Errorf("profile = %q", f.Files[profilePath])
	}
	if f.Files[lockPath] != "/org/gnome/login-screen/disable-user-list\n" {
		t.Errorf("lock = %q", f.Files[lockPath])
	}
	var sawUpdate bool
	for _, c := range f.Runs {
		if c == "dconf update" {
			sawUpdate = true
		}
	}
	if !sawUpdate {
		t.Errorf("expected `dconf update`; Runs=%v", f.Runs)
	}
}

// A pre-existing profile is not overwritten.
//
// @spec kernelio-dconf
// @ac AC-01
func TestApply_Kernel_KeepsExistingProfile(t *testing.T) {
	t.Run("kernelio-dconf/AC-01", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Files[profilePath] = "user\nsystem-db:local\n# operator note\n"
	if _, err := dconfset.New().Apply(context.Background(), f, lockedParams(), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(f.Files[profilePath], "# operator note") {
		t.Errorf("existing profile should be left untouched; got %q", f.Files[profilePath])
	}
}

// Kernel-IO Capture → Apply → Rollback removes a snippet that did not
// exist at capture.
//
// @spec kernelio-dconf
// @ac AC-02
func TestRoundTrip_Kernel_RemovesWhenAbsent(t *testing.T) {
	t.Run("kernelio-dconf/AC-02", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	h := dconfset.New()
	params := lockedParams()

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != false {
		t.Fatalf("want file_existed=false, got %+v", pre.Data)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, ok := f.Files[snippetPath]; !ok {
		t.Fatal("apply should have written the snippet")
	}
	if _, ok := f.Files[lockPath]; !ok {
		t.Fatal("apply (lock:true) should have written the lock")
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, ok := f.Files[snippetPath]; ok {
		t.Error("rollback should have removed the snippet that did not exist at capture")
	}
	// Regression: rollback must also remove the lock that Apply created, or
	// the override enforcement survives a reverted value (orphaned lock).
	if _, ok := f.Files[lockPath]; ok {
		t.Error("rollback should have removed the lock that did not exist at capture (lock-orphan regression)")
	}
}

// A pre-existing snippet is restored to its prior content on rollback.
//
// @spec kernelio-dconf
// @ac AC-02
func TestRoundTrip_Kernel_RestoresPrior(t *testing.T) {
	t.Run("kernelio-dconf/AC-02", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Files[snippetPath] = "[org/gnome/login-screen]\ndisable-user-list=false\n"
	h := dconfset.New()
	params := lockedParams()

	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["file_existed"] != true {
		t.Fatalf("want file_existed=true, got %+v", pre.Data)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if f.Files[snippetPath] != "[org/gnome/login-screen]\ndisable-user-list=false\n" {
		t.Errorf("rolled-back snippet = %q, want prior", f.Files[snippetPath])
	}
}

// Fallback: a transport without the kernelio capability uses the shell path.
//
// @spec kernelio-dconf
// @ac AC-03
func TestApply_FallsBackToShell(t *testing.T) {
	t.Run("kernelio-dconf/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	res, err := dconfset.New().Apply(context.Background(), tp, lockedParams(), nil)
	if err != nil || !res.Success {
		t.Fatalf("shell Apply: err=%v success=%v", err, res.Success)
	}
	var sawPrintf, sawUpdate bool
	for _, c := range tp.Runs {
		if strings.Contains(c, "printf") {
			sawPrintf = true
		}
		if c == "dconf update" {
			sawUpdate = true
		}
	}
	if !sawPrintf || !sawUpdate {
		t.Errorf("expected shell printf + dconf update; Runs=%v", tp.Runs)
	}
}
