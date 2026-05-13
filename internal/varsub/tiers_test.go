// Tests for the Phase 3.6 multi-tier variable resolution
// (LoadHost, LoadGroups, LoadConfDir, ResolveTiers).
package varsub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeYAML(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadHost_EmptyConfigDir(t *testing.T) {
	got, err := LoadHost("", "host1")
	if err != nil || got != nil {
		t.Errorf("empty configDir should return nil; got %v, err %v", got, err)
	}
}

func TestLoadHost_EmptyHostname(t *testing.T) {
	got, err := LoadHost(t.TempDir(), "")
	if err != nil || got != nil {
		t.Errorf("empty hostname should return nil; got %v, err %v", got, err)
	}
}

func TestLoadHost_MissingFile(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadHost(dir, "no-such-host")
	if err != nil || got != nil {
		t.Errorf("missing host file should return nil; got %v, err %v", got, err)
	}
}

func TestLoadHost_BasicScalars(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "hosts", "web-01.yml"), `variables:
  pam_faillock_deny: 5
  banner: "this host"
`)
	got, err := LoadHost(dir, "web-01")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got["pam_faillock_deny"] != "5" || got["banner"] != "this host" {
		t.Errorf("got %v", got)
	}
}

func TestLoadGroups_NoGroups(t *testing.T) {
	got, err := LoadGroups(t.TempDir(), nil)
	if err != nil || got != nil {
		t.Errorf("no groups should return nil; got %v, err %v", got, err)
	}
}

func TestLoadGroups_LaterWins(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "groups", "base.yml"), `variables:
  pam_faillock_deny: 3
  banner: "base"
`)
	writeYAML(t, filepath.Join(dir, "groups", "prod.yml"), `variables:
  pam_faillock_deny: 5
  prod_only: "yes"
`)
	got, err := LoadGroups(dir, []string{"base", "prod"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// prod wins over base on pam_faillock_deny.
	if got["pam_faillock_deny"] != "5" {
		t.Errorf("later group should win; got pam_faillock_deny=%s", got["pam_faillock_deny"])
	}
	if got["banner"] != "base" {
		t.Errorf("base banner preserved; got %v", got["banner"])
	}
	if got["prod_only"] != "yes" {
		t.Errorf("prod_only added; got %v", got["prod_only"])
	}
}

func TestLoadGroups_MissingFileSkipped(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "groups", "real.yml"), `variables:
  x: "1"
`)
	got, err := LoadGroups(dir, []string{"missing", "real", "alsoMissing"})
	if err != nil {
		t.Fatalf("missing groups should be skipped, not error; got %v", err)
	}
	if got["x"] != "1" {
		t.Errorf("real group's content should still load; got %v", got)
	}
}

func TestLoadConfDir_EmptyConfigDir(t *testing.T) {
	got, err := LoadConfDir("")
	if err != nil || got != nil {
		t.Errorf("empty configDir should return nil; got %v, err %v", got, err)
	}
}

func TestLoadConfDir_MissingDir(t *testing.T) {
	got, err := LoadConfDir(t.TempDir())
	if err != nil || got != nil {
		t.Errorf("missing conf.d should return nil; got %v, err %v", got, err)
	}
}

func TestLoadConfDir_AlphabeticalOverride(t *testing.T) {
	dir := t.TempDir()
	// 10-base.yml is read first; 99-org.yml second; 99-org wins.
	writeYAML(t, filepath.Join(dir, "conf.d", "10-base.yml"), `variables:
  x: "from-base"
`)
	writeYAML(t, filepath.Join(dir, "conf.d", "99-org.yml"), `variables:
  x: "from-org"
`)
	writeYAML(t, filepath.Join(dir, "conf.d", "50-mid.yml"), `variables:
  y: "from-mid"
`)
	got, err := LoadConfDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got["x"] != "from-org" {
		t.Errorf("99-org should win for x; got %v", got["x"])
	}
	if got["y"] != "from-mid" {
		t.Errorf("50-mid contributed y; got %v", got["y"])
	}
}

func TestLoadConfDir_NonYAMLSkipped(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "conf.d", "real.yml"), `variables:
  x: "1"
`)
	// A README.md or .swp file in conf.d/ shouldn't cause a parse error.
	if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conf.d", "README.md"), []byte("# notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfDir(dir)
	if err != nil {
		t.Fatalf("non-YAML should be skipped: %v", err)
	}
	if got["x"] != "1" {
		t.Errorf("real.yml contents missing; got %v", got)
	}
}

func TestResolveTiers_FullChain(t *testing.T) {
	// Stand up all five sources and verify the priority chain.
	// Lowest → highest:
	//   defaults.yml        — sets a, b, c, d, e (all "from-defaults")
	//   conf.d/10-base.yml  — overrides b → "from-confd"
	//   conf.d/99-late.yml  — overrides c → "from-confd-late"
	//   groups/base.yml     — overrides c → "from-group" (loses to confd-late? NO — groups > conf.d)
	//   groups/prod.yml     — overrides d → "from-group"
	//   hosts/web-01.yml    — overrides e → "from-host"
	//   CLI                 — overrides a → "from-cli" (always wins)
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "defaults.yml"), `variables:
  a: "from-defaults"
  b: "from-defaults"
  c: "from-defaults"
  d: "from-defaults"
  e: "from-defaults"
  f: "from-defaults"
`)
	writeYAML(t, filepath.Join(dir, "conf.d", "10-base.yml"), `variables:
  b: "from-confd"
`)
	writeYAML(t, filepath.Join(dir, "conf.d", "99-late.yml"), `variables:
  c: "from-confd-late"
`)
	writeYAML(t, filepath.Join(dir, "groups", "base.yml"), `variables:
  c: "from-group"
`)
	writeYAML(t, filepath.Join(dir, "groups", "prod.yml"), `variables:
  d: "from-group"
`)
	writeYAML(t, filepath.Join(dir, "hosts", "web-01.yml"), `variables:
  e: "from-host"
`)
	cli := Variables{"a": "from-cli"}
	got, err := ResolveTiers(dir, "web-01", []string{"base", "prod"}, cli)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	tests := []struct {
		key  string
		want string
	}{
		{"a", "from-cli"},      // CLI wins over defaults
		{"b", "from-confd"},    // conf.d 10-base wins over defaults
		{"c", "from-group"},    // groups beat conf.d 99-late
		{"d", "from-group"},    // groups beat defaults
		{"e", "from-host"},     // host file beats everything below CLI
		{"f", "from-defaults"}, // unmodified
	}
	for _, tc := range tests {
		if got[tc.key] != tc.want {
			t.Errorf("key %q: got %q, want %q", tc.key, got[tc.key], tc.want)
		}
	}
}

func TestResolveTiers_EmptyConfigDirCLIOnly(t *testing.T) {
	got, err := ResolveTiers("", "host1", nil, Variables{"x": "1"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got["x"] != "1" {
		t.Errorf("CLI-only should still produce x=1; got %v", got)
	}
}

func TestResolveTiers_MalformedHostFileErrors(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "hosts", "bad.yml"), "not: valid: yaml: stuff:")
	_, err := ResolveTiers(dir, "bad", nil, nil)
	if err == nil {
		t.Fatal("malformed host file should error")
	}
	if !strings.Contains(err.Error(), "bad.yml") {
		t.Errorf("error should name path: %v", err)
	}
}

func TestResolveTiers_InvalidVarKeyInHostFile(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "hosts", "h.yml"), `variables:
  has-dash: 5
`)
	_, err := ResolveTiers(dir, "h", nil, nil)
	if err == nil {
		t.Fatal("invalid key in host file should error")
	}
	if !strings.Contains(err.Error(), "has-dash") {
		t.Errorf("error should name offending key: %v", err)
	}
}

// TestResolveTiers_InvalidVarKeyInGroupFile locks that the
// shared loadVariablesFile helper applies validVarName to
// group files, not just host/defaults files. Catches the
// asymmetry AC-13 worries about.
func TestResolveTiers_InvalidVarKeyInGroupFile(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "groups", "g.yml"), `variables:
  has-dash: 5
`)
	_, err := ResolveTiers(dir, "h", []string{"g"}, nil)
	if err == nil {
		t.Fatal("invalid key in group file should error")
	}
	if !strings.Contains(err.Error(), "has-dash") {
		t.Errorf("error should name offending key: %v", err)
	}
}

// TestResolveTiers_InvalidVarKeyInConfDFile locks the same
// vocabulary check for conf.d/*.yml.
func TestResolveTiers_InvalidVarKeyInConfDFile(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "conf.d", "10-bad.yml"), `variables:
  has-dash: 5
`)
	_, err := ResolveTiers(dir, "", nil, nil)
	if err == nil {
		t.Fatal("invalid key in conf.d file should error")
	}
	if !strings.Contains(err.Error(), "has-dash") {
		t.Errorf("error should name offending key: %v", err)
	}
}

// TestResolveTiers_MalformedGroupFileErrors mirrors the host-
// file malformed test for groups. Any tier source that's
// present-but-malformed surfaces with the path in the message.
func TestResolveTiers_MalformedGroupFileErrors(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, filepath.Join(dir, "groups", "bad.yml"), "not: valid: yaml: stuff:")
	_, err := ResolveTiers(dir, "", []string{"bad"}, nil)
	if err == nil {
		t.Fatal("malformed group file should error")
	}
	if !strings.Contains(err.Error(), "bad.yml") {
		t.Errorf("error should name path: %v", err)
	}
}
