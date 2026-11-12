package kensa

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// writeCorpus lays out a small corpus in a temp directory. Each key of files
// is a slash-separated relative path, and its value is the content.
func writeCorpus(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func describe(t *testing.T, dir string) Corpus {
	t.Helper()
	c, err := DescribeCorpus(dir, nil)
	if err != nil {
		t.Fatalf("DescribeCorpus(%s): %v", dir, err)
	}
	fc, err := DescribeCorpusFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("DescribeCorpusFS(%s): %v", dir, err)
	}
	// The two forms must report the same identity for the same corpus.
	if c != fc {
		t.Fatalf("directory and file-tree forms disagree:\n dir %+v\n fs  %+v", c, fc)
	}
	return c
}

var baseCorpus = map[string]string{
	"access-control/a.yml": "id: a\n",
	"audit/b.yml":          "id: b\n",
}

func withFiles(extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range baseCorpus {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// TestDescribeCorpus covers the corpus identity contract, through both the
// directory and the file-tree form.
//
// @spec pkg-corpus-identity
func TestDescribeCorpus(t *testing.T) {
	t.Run("pkg-corpus-identity/AC-01", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-01
		// A packaged corpus carries the marker and reports it as declared.
		c := describe(t, writeCorpus(t, withFiles(map[string]string{".corpus-version": "0.13.0\n"})))
		if c.Source != SourceDeclared || c.Version != "0.13.0" || c.Digest == "" {
			t.Errorf("packaged corpus: got %+v, want declared 0.13.0 with a digest", c)
		}
		// The repository corpus is what the package installs; its marker is
		// VERSION.
		want, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
		if err != nil {
			t.Fatal(err)
		}
		repo := describe(t, corpusDir(t))
		if repo.Source != SourceDeclared || repo.Version != strings.TrimSpace(string(want)) {
			t.Errorf("repository corpus: got %+v, want declared %s", repo, strings.TrimSpace(string(want)))
		}
	})

	t.Run("pkg-corpus-identity/AC-02", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-02
		for _, marker := range []string{"", "  \n"} {
			files := baseCorpus
			if marker != "" {
				files = withFiles(map[string]string{".corpus-version": marker})
			}
			c := describe(t, writeCorpus(t, files))
			if c.Source != SourceComputed || c.Version != "" || !strings.HasPrefix(c.Digest, "sha256:") {
				t.Errorf("marker %q: got %+v, want computed, empty version, sha256 digest", marker, c)
			}
		}
	})

	t.Run("pkg-corpus-identity/AC-03", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-03
		dir := writeCorpus(t, baseCorpus)
		c, err := DescribeCorpus("", []string{filepath.Join(dir, "audit", "b.yml")})
		if err != nil {
			t.Fatalf("DescribeCorpus with paths only: %v", err)
		}
		if c != (Corpus{Source: SourceNone}) {
			t.Errorf("paths with no directory: got %+v, want only Source none", c)
		}
	})

	t.Run("pkg-corpus-identity/AC-12", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-12
		// The identity covers the directory only. A rule path passed beside
		// it is loaded by LoadRules but left out of the result, so the two
		// calls below load different rule sets and report one identity.
		dir := writeCorpus(t, map[string]string{"audit/plain-rule.yml": plainRule})
		extra := writeRule(t, t.TempDir(), "extra-rule.yml",
			strings.Replace(plainRule, "id: plain-rule", "id: extra-rule", 1))
		dirOnly, err := LoadRules(dir, nil, nil)
		if err != nil {
			t.Fatalf("LoadRules(dir): %v", err)
		}
		mixed, err := LoadRules(dir, []string{extra}, nil)
		if err != nil {
			t.Fatalf("LoadRules(dir, extra): %v", err)
		}
		if len(dirOnly) != 1 || len(mixed) != 2 {
			t.Fatalf("loaded %d and %d rules, want 1 and 2", len(dirOnly), len(mixed))
		}
		without, err := DescribeCorpus(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		with, err := DescribeCorpus(dir, []string{extra})
		if err != nil {
			t.Fatal(err)
		}
		if with != without {
			t.Errorf("extra path changed the directory identity:\n without %+v\n with    %+v", without, with)
		}
	})

	t.Run("pkg-corpus-identity/AC-14", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-14
		// A walk that finds no rule files is an error, even with a marker
		// present. LoadRules refuses the same directory alone, and loads the
		// paths when they are passed; the identity covers the directory only,
		// so it still refuses.
		empty := writeCorpus(t, map[string]string{".corpus-version": "0.13.0\n"})
		extra := writeRule(t, t.TempDir(), "plain-rule.yml", plainRule)
		for _, paths := range [][]string{nil, {extra}} {
			if c, err := DescribeCorpus(empty, paths); err == nil {
				t.Errorf("marker-only directory, paths %v: got %+v, want an error", paths, c)
			}
		}
		if _, err := LoadRules(empty, nil, nil); err == nil {
			t.Error("LoadRules accepted a marker-only directory")
		}
		if got, err := LoadRules(empty, []string{extra}, nil); err != nil || len(got) != 1 {
			t.Errorf("LoadRules(marker-only dir, extra path): %d rules, err %v; want the 1 path rule", len(got), err)
		}
		if c, err := DescribeCorpusFS(os.DirFS(empty)); err == nil {
			t.Errorf("marker-only tree: got %+v, want an error", c)
		}
	})

	t.Run("pkg-corpus-identity/AC-15", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-15
		// A symlinked root given without a trailing slash is not walked, by
		// LoadRules or by DescribeCorpus, so both refuse it. os.DirFS follows
		// the link, so the file-tree form describes the corpus, and it agrees
		// with the directory form given the trailing slash.
		target := writeCorpus(t, withFiles(map[string]string{".corpus-version": "0.13.0\n"}))
		link := filepath.Join(t.TempDir(), "rules")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink: %v", err)
		}
		if c, err := DescribeCorpus(link, nil); err == nil {
			t.Errorf("symlinked root: got %+v, want an error", c)
		}
		if _, err := LoadRules(link, nil, nil); err == nil {
			t.Error("LoadRules walked a symlinked root; the directory form must then describe it too")
		}
		slash, err := DescribeCorpus(link+string(filepath.Separator), nil)
		if err != nil {
			t.Fatalf("symlinked root with a trailing slash: %v", err)
		}
		tree, err := DescribeCorpusFS(os.DirFS(link))
		if err != nil {
			t.Fatalf("file-tree form over the link: %v", err)
		}
		if slash != tree || slash != describe(t, target) {
			t.Errorf("forms disagree:\n dir/ %+v\n fs   %+v", slash, tree)
		}
	})

	t.Run("pkg-corpus-identity/AC-04", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-04
		dir := writeCorpus(t, baseCorpus)
		first := describe(t, dir)
		if again := describe(t, dir); again.Digest != first.Digest {
			t.Fatalf("digest moved on an unchanged corpus: %s then %s", first.Digest, again.Digest)
		}
		if err := os.WriteFile(filepath.Join(dir, "audit", "b.yml"), []byte("id: b\ntitle: changed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if changed := describe(t, dir); changed.Digest == first.Digest {
			t.Error("digest did not change when a rule file's content changed")
		}
		// Swapping content between two files changes it too: the content is
		// bound to its path.
		swapped := describe(t, writeCorpus(t, map[string]string{
			"access-control/a.yml": "id: b\n",
			"audit/b.yml":          "id: a\n",
		}))
		if swapped.Digest == describe(t, writeCorpus(t, baseCorpus)).Digest {
			t.Error("digest did not change when two files swapped content")
		}
	})

	t.Run("pkg-corpus-identity/AC-05", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-05
		base := describe(t, writeCorpus(t, baseCorpus)).Digest
		renamed := describe(t, writeCorpus(t, map[string]string{
			"access-control/a2.yml": "id: a\n",
			"audit/b.yml":           "id: b\n",
		})).Digest
		moved := describe(t, writeCorpus(t, map[string]string{
			"system/a.yml": "id: a\n",
			"audit/b.yml":  "id: b\n",
		})).Digest
		if renamed == base {
			t.Error("digest did not change when a rule file was renamed")
		}
		if moved == base {
			t.Error("digest did not change when a rule file moved to another category")
		}
	})

	t.Run("pkg-corpus-identity/AC-06", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-06
		base := describe(t, writeCorpus(t, baseCorpus)).Digest
		for name, extra := range map[string]map[string]string{
			"marker":            {".corpus-version": "0.13.0\n"},
			"other marker":      {".corpus-version": "9.9.9\n"},
			"readme":            {"README.md": "# corpus\n"},
			"go source":         {"embed.go": "package rules\n"},
			"non-rule in topic": {"audit/notes.txt": "x\n"},
		} {
			if got := describe(t, writeCorpus(t, withFiles(extra))).Digest; got != base {
				t.Errorf("%s: digest changed from %s to %s", name, base, got)
			}
		}
	})

	t.Run("pkg-corpus-identity/AC-10", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-10
		// Corpus identity lives on pkg/kensa. The scan result in the frozen
		// api/ keeps exactly the fields it had.
		want := []string{"HostID", "Transactions", "Outcomes", "Capabilities", "Platform"}
		rt := reflect.TypeOf(api.ScanResult{})
		var got []string
		for i := 0; i < rt.NumField(); i++ {
			got = append(got, rt.Field(i).Name)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("api.ScanResult fields = %v, want %v", got, want)
		}
	})

	t.Run("pkg-corpus-identity/AC-11", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-11
		// describe fails the test when the two forms disagree; run it over a
		// declared, a computed and the repository corpus.
		describe(t, writeCorpus(t, withFiles(map[string]string{".corpus-version": "1.2.3\n"})))
		describe(t, writeCorpus(t, baseCorpus))
		describe(t, corpusDir(t))
		if _, err := DescribeCorpusFS(nil); err == nil {
			t.Error("DescribeCorpusFS(nil) returned no error")
		}
	})
}
