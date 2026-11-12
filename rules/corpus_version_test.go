package rules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/pkg/kensa"
)

func repoVersion(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// TestCorpusVersionMarker covers where the corpus version marker travels: the
// embedded corpus, the staged package contents, and the gate that keeps it
// equal to VERSION.
//
// @spec pkg-corpus-identity
func TestCorpusVersionMarker(t *testing.T) {
	t.Run("pkg-corpus-identity/AC-07", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-07
		// The staged tree is what both the rpm and the deb install at
		// /usr/share/kensa/rules (nfpm type: tree). The built artifacts are
		// checked separately against a release snapshot.
		dest := t.TempDir() + "/stage"
		cmd := exec.Command("sh", "scripts/stage-corpus.sh", dest)
		cmd.Dir = ".."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("stage-corpus.sh: %v\n%s", err, out)
		}
		got, err := os.ReadFile(filepath.Join(dest, ".corpus-version"))
		if err != nil {
			t.Fatalf("staged package carries no marker: %v", err)
		}
		if strings.TrimSpace(string(got)) != repoVersion(t) {
			t.Errorf("staged marker %q, want VERSION %q", strings.TrimSpace(string(got)), repoVersion(t))
		}
		c, err := kensa.DescribeCorpus(dest, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Source != kensa.SourceDeclared || c.Version != repoVersion(t) {
			t.Errorf("staged corpus: got %+v, want declared %s", c, repoVersion(t))
		}
	})

	t.Run("pkg-corpus-identity/AC-08", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-08
		// A consumer that embeds the corpus gets the marker. A pattern skips
		// dot files, so this fails if the marker loses its explicit embed
		// entry. scripts/check-module-consumer.sh checks the same through a
		// real module download.
		c, err := kensa.DescribeCorpusFS(FS())
		if err != nil {
			t.Fatal(err)
		}
		if c.Source != kensa.SourceDeclared || c.Version != repoVersion(t) {
			t.Errorf("embedded corpus: got %+v, want declared %s", c, repoVersion(t))
		}
		// Embedding changes nothing about which rules are digested.
		disk, err := kensa.DescribeCorpus(".", nil)
		if err != nil {
			t.Fatal(err)
		}
		if disk.Digest != c.Digest {
			t.Errorf("embedded digest %s differs from disk %s", c.Digest, disk.Digest)
		}
	})

	t.Run("pkg-corpus-identity/AC-09", func(t *testing.T) {
		// @spec pkg-corpus-identity
		// @ac AC-09
		script, err := filepath.Abs(filepath.Join("..", "scripts", "check-corpus-version.sh"))
		if err != nil {
			t.Fatal(err)
		}
		run := func(version, marker string) error {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "rules"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte(version+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if marker != "-" {
				if err := os.WriteFile(filepath.Join(root, "rules", ".corpus-version"), []byte(marker+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			return exec.Command("sh", script, root).Run()
		}
		if err := run("0.14.0", "0.14.0"); err != nil {
			t.Errorf("equal marker failed the gate: %v", err)
		}
		for name, c := range map[string][2]string{
			"VERSION bumped, marker not": {"0.14.0", "0.13.0"},
			"marker bumped, VERSION not": {"0.13.0", "0.14.0"},
			"marker missing":             {"0.14.0", "-"},
		} {
			if err := run(c[0], c[1]); err == nil {
				t.Errorf("%s: the gate passed", name)
			}
		}
		// The committed tree passes.
		if out, err := exec.Command("sh", script, "..").CombinedOutput(); err != nil {
			t.Errorf("the committed marker fails the gate: %v\n%s", err, out)
		}
	})
}
