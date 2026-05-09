// Tests for the --config-dir auto-detect chain.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withEnv sets env vars for the duration of fn and restores
// the previous values on exit. Pass ("", "") to clear a var.
func withEnv(t *testing.T, vars map[string]string, fn func()) {
	t.Helper()
	prev := make(map[string]string, len(vars))
	for k, v := range vars {
		prev[k] = os.Getenv(k)
		if v == "" {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, v)
		}
	}
	defer func() {
		for k, v := range prev {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()
	fn()
}

func TestResolveConfigDir_ExplicitWins(t *testing.T) {
	dir := t.TempDir()
	got := resolveConfigDir(dir)
	if got != dir {
		t.Errorf("explicit value should win; got %q want %q", got, dir)
	}
}

func TestResolveConfigDir_KensaEnv(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{
		"KENSA_CONFIG_DIR": dir,
		"XDG_CONFIG_HOME":  "",
		"HOME":             "",
	}, func() {
		got := resolveConfigDir("")
		if got != dir {
			t.Errorf("got %q want %q", got, dir)
		}
	})
}

func TestResolveConfigDir_XDG(t *testing.T) {
	xdg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(xdg, "kensa"), 0o755); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{
		"KENSA_CONFIG_DIR": "",
		"XDG_CONFIG_HOME":  xdg,
		"HOME":             "",
	}, func() {
		got := resolveConfigDir("")
		want := filepath.Join(xdg, "kensa")
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	})
}

func TestResolveConfigDir_Home(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "kensa"), 0o755); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{
		"KENSA_CONFIG_DIR": "",
		"XDG_CONFIG_HOME":  "",
		"HOME":             home,
	}, func() {
		got := resolveConfigDir("")
		want := filepath.Join(home, ".config", "kensa")
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	})
}

func TestResolveConfigDir_KensaEnvBeatsXDG(t *testing.T) {
	// Explicit env > XDG.
	kensaDir := t.TempDir()
	xdg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(xdg, "kensa"), 0o755); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{
		"KENSA_CONFIG_DIR": kensaDir,
		"XDG_CONFIG_HOME":  xdg,
		"HOME":             "",
	}, func() {
		got := resolveConfigDir("")
		if got != kensaDir {
			t.Errorf("KENSA_CONFIG_DIR should beat XDG; got %q", got)
		}
	})
}

func TestResolveConfigDir_ExplicitBeatsAllEnv(t *testing.T) {
	explicit := t.TempDir()
	withEnv(t, map[string]string{
		"KENSA_CONFIG_DIR": "/some/other/path",
		"XDG_CONFIG_HOME":  "/yet/another",
		"HOME":             "/yet/yet/another",
	}, func() {
		got := resolveConfigDir(explicit)
		if got != explicit {
			t.Errorf("explicit must win over all env; got %q", got)
		}
	})
}

func TestResolveConfigDir_NonExistentSkipped(t *testing.T) {
	// KENSA_CONFIG_DIR points at a non-existent dir; XDG points
	// at a real one. Auto-detect should skip the bad one.
	xdg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(xdg, "kensa"), 0o755); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{
		"KENSA_CONFIG_DIR": "/no/such/path/exists",
		"XDG_CONFIG_HOME":  xdg,
		"HOME":             "",
	}, func() {
		got := resolveConfigDir("")
		want := filepath.Join(xdg, "kensa")
		if got != want {
			t.Errorf("non-existent KENSA_CONFIG_DIR should be skipped; got %q want %q", got, want)
		}
	})
}

func TestResolveConfigDir_EmptyWhenNothingSet(t *testing.T) {
	withEnv(t, map[string]string{
		"KENSA_CONFIG_DIR": "",
		"XDG_CONFIG_HOME":  "",
		"HOME":             "/no/such/user",
	}, func() {
		got := resolveConfigDir("")
		// /etc/kensa might exist on the dev box; if so, the test
		// returns it. We can't assert == "" portably. Instead
		// assert the function is deterministic — running twice
		// produces the same result.
		got2 := resolveConfigDir("")
		if got != got2 {
			t.Errorf("non-deterministic: %q vs %q", got, got2)
		}
		// Either "" (no /etc/kensa on this system) or "/etc/kensa"
		// (the last-resort tier). Anything else is wrong.
		if got != "" && got != "/etc/kensa" {
			t.Errorf("unexpected fallback: %q", got)
		}
	})
}

func TestResolveConfigDir_FileNotDir(t *testing.T) {
	// A regular file at the candidate path should NOT be picked
	// (it's not a directory). isDir's defensive false means we
	// fall through.
	tmp := t.TempDir()
	regularFile := filepath.Join(tmp, "kensa") // file, not dir
	if err := os.WriteFile(regularFile, []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{
		"KENSA_CONFIG_DIR": "",
		"XDG_CONFIG_HOME":  tmp,
		"HOME":             "",
	}, func() {
		got := resolveConfigDir("")
		// Should NOT have picked tmp/kensa (it's a file). Fall
		// through to /etc/kensa (or "").
		want := filepath.Join(tmp, "kensa")
		if got == want {
			t.Errorf("file-at-path should not be picked; got %q", got)
		}
	})
}
