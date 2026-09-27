package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

// ymlManifest maps every *.yml path under fsys, at any depth, to the sha256
// of its content. It walks recursively on purpose, matching the directory
// loaders, so a file the embed pattern misses shows up as missing.
func ymlManifest(fsys fs.FS) (map[string]string, error) {
	out := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".yml") {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[p] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}

// layoutProblems reports rule files that break the corpus layout: every rule
// must be a regular file exactly one level down (<topic>/<id>.yml), and no
// testdata directory may exist, because the embed pattern and the tarball
// select that depth and a fixture there would ship as a rule.
func layoutProblems(fsys fs.FS) ([]string, error) {
	var problems []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				problems = append(problems, "testdata directory in the corpus: "+p)
			}
			return nil
		}
		if !strings.HasSuffix(p, ".yml") {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			problems = append(problems, "rule file is a symlink: "+p)
		}
		if strings.Count(p, "/") != 1 {
			problems = append(problems, "rule file not at <topic>/<id>.yml: "+p)
		}
		return nil
	})
	sort.Strings(problems)
	return problems, err
}

// compareTrees reports every rule file that is missing from, extra in, or
// different in embedded compared with disk.
func compareTrees(disk, embedded fs.FS) error {
	want, err := ymlManifest(disk)
	if err != nil {
		return fmt.Errorf("disk manifest: %w", err)
	}
	got, err := ymlManifest(embedded)
	if err != nil {
		return fmt.Errorf("embedded manifest: %w", err)
	}
	var problems []string
	for p, sum := range want {
		switch g, ok := got[p]; {
		case !ok:
			problems = append(problems, "missing from embed: "+p)
		case g != sum:
			problems = append(problems, "content differs: "+p)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			problems = append(problems, "embedded but not on disk: "+p)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%d problem(s):\n%s", len(problems), strings.Join(problems, "\n"))
	}
	return nil
}

func TestEmbeddedMatchesDisk(t *testing.T) {
	t.Run("rule-embedded-corpus/AC-01", func(t *testing.T) {
		// @spec rule-embedded-corpus
		// @ac AC-01
		// The test runs with this package's directory as its working
		// directory, which is the corpus root.
		if err := compareTrees(os.DirFS("."), FS()); err != nil {
			t.Fatal(err)
		}
		problems, err := layoutProblems(os.DirFS("."))
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) > 0 {
			t.Fatalf("corpus layout:\n%s", strings.Join(problems, "\n"))
		}
		m, err := ymlManifest(FS())
		if err != nil {
			t.Fatal(err)
		}
		if len(m) == 0 {
			t.Fatal("embedded corpus is empty")
		}
	})
}

func TestCompareTreesDetectsMissedFile(t *testing.T) {
	t.Run("rule-embedded-corpus/AC-02", func(t *testing.T) {
		// @spec rule-embedded-corpus
		// @ac AC-02
		disk := fstest.MapFS{
			"audit/a.yml":        {Data: []byte("id: a\n")},
			"audit/deep/b.yml":   {Data: []byte("id: b\n")},
			"audit/README.md":    {Data: []byte("not a rule\n")},
			"system/c.yml":       {Data: []byte("id: c\n")},
			"system/changed.yml": {Data: []byte("id: changed\n")},
		}
		// Shaped like the one-level embed pattern: the deeper file is absent,
		// and one file's content differs.
		embedded := fstest.MapFS{
			"audit/a.yml":        {Data: []byte("id: a\n")},
			"system/c.yml":       {Data: []byte("id: c\n")},
			"system/changed.yml": {Data: []byte("id: edited\n")},
		}
		err := compareTrees(disk, embedded)
		if err == nil {
			t.Fatal("compareTrees accepted a tree missing a rule file")
		}
		for _, want := range []string{
			"missing from embed: audit/deep/b.yml",
			"content differs: system/changed.yml",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not report %q:\n%v", want, err)
			}
		}
		if strings.Contains(err.Error(), "README.md") {
			t.Errorf("a non-rule file was reported:\n%v", err)
		}
		if err := compareTrees(embedded, embedded); err != nil {
			t.Errorf("identical trees reported a problem: %v", err)
		}

		// The layout check names each kind of misplaced file.
		bad := fstest.MapFS{
			"audit/ok.yml":         {Data: []byte("id: ok\n")},
			"top.yml":              {Data: []byte("id: top\n")},
			"audit/deep/x.yml":     {Data: []byte("id: x\n")},
			"audit/link.yml":       {Data: []byte("audit/ok.yml"), Mode: fs.ModeSymlink},
			"testdata/fixture.yml": {Data: []byte("id: f\n")},
		}
		problems, err := layoutProblems(bad)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"rule file not at <topic>/<id>.yml: top.yml",
			"rule file not at <topic>/<id>.yml: audit/deep/x.yml",
			"rule file is a symlink: audit/link.yml",
			"testdata directory in the corpus: testdata",
		} {
			found := false
			for _, p := range problems {
				found = found || p == want
			}
			if !found {
				t.Errorf("layout check did not report %q; got %v", want, problems)
			}
		}
		if len(problems) != 4 {
			t.Errorf("layout check reported %d problems, want 4: %v", len(problems), problems)
		}
	})
}

// TestStandaloneBinariesDoNotEmbedCorpus keeps the corpus out of every
// binary the Kensa module builds. Those binaries read the corpus at run time,
// so it can be updated without a binary release.
func TestStandaloneBinariesDoNotEmbedCorpus(t *testing.T) {
	t.Run("rule-embedded-corpus/AC-04", func(t *testing.T) {
		// @spec rule-embedded-corpus
		// @ac AC-04
		const self = "github.com/Hanalyx/kensa/rules"
		out, err := exec.Command("go", "list", "-deps", "-f",
			"{{.ImportPath}}", "github.com/Hanalyx/kensa/cmd/...",
			"github.com/Hanalyx/kensa/pkg/...").CombinedOutput()
		if err != nil {
			t.Fatalf("go list: %v\n%s", err, out)
		}
		deps := strings.Fields(string(out))
		if len(deps) == 0 {
			t.Fatal("go list returned no packages")
		}
		for _, d := range deps {
			if d == self {
				t.Fatalf("%s is linked by a cmd/ or pkg/ package; the standalone binaries must not embed the corpus", self)
			}
		}
	})
}

// TestStagedPackageCorpus runs the script that stages the kensa-rules package
// contents and checks it carries the corpus and nothing else: the same rule
// files as disk, the corpus README, no Go source, directories 0755 and files
// 0644.
func TestStagedPackageCorpus(t *testing.T) {
	t.Run("rule-embedded-corpus/AC-03", func(t *testing.T) {
		// @spec rule-embedded-corpus
		// @ac AC-03
		dest := t.TempDir() + "/stage"
		cmd := exec.Command("sh", "scripts/stage-corpus.sh", dest)
		cmd.Dir = ".."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("stage-corpus.sh: %v\n%s", err, out)
		}
		if err := compareTrees(os.DirFS("."), os.DirFS(dest)); err != nil {
			t.Fatalf("staged corpus differs from disk: %v", err)
		}
		if _, err := os.Stat(dest + "/README.md"); err != nil {
			t.Fatalf("corpus README not staged: %v", err)
		}
		err := fs.WalkDir(os.DirFS(dest), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			mode := info.Mode().Perm()
			switch {
			case d.IsDir():
				if mode != 0o755 {
					t.Errorf("%s: directory mode %o, want 755", p, mode)
				}
			case strings.HasSuffix(p, ".yml") || p == "README.md":
				if mode != 0o644 {
					t.Errorf("%s: file mode %o, want 644", p, mode)
				}
			default:
				t.Errorf("non-corpus file staged: %s", p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
