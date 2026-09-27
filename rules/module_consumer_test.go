package rules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestModuleConsumerCheck builds a program that requires this commit's Kensa
// module the way a real consumer resolves it, and checks what it embeds. See
// scripts/check-module-consumer.sh for what is checked and how the build is
// isolated from this checkout. It needs git, zip and the Go toolchain, and it
// takes several seconds, so -short skips it; CI runs it in full. It also skips
// when the module is not a git checkout of itself, such as a source tarball
// or a copy in a module cache, because the check builds from the commit.
func TestModuleConsumerCheck(t *testing.T) {
	t.Run("rule-embedded-corpus/AC-05", func(t *testing.T) {
		// @spec rule-embedded-corpus
		// @ac AC-05
		if testing.Short() {
			t.Skip("-short: module consumer check skipped")
		}
		// A missing tool fails the test. Skipping instead would let the
		// required check disappear from CI without anyone noticing.
		for _, tool := range []string{"git", "zip", "go", "bash"} {
			if _, err := exec.LookPath(tool); err != nil {
				t.Fatalf("%s is required for the module consumer check: %v", tool, err)
			}
		}
		root, err := filepath.Abs("..")
		if err != nil {
			t.Fatal(err)
		}
		// Skip only when the module is plainly not a checkout of itself. Any
		// other git failure, such as a safe.directory refusal, fails. GIT_DIR
		// and GIT_WORK_TREE are cleared for this probe so a stray value cannot
		// make a real checkout look like no checkout; the script itself still
		// sees them and fails if they are broken.
		var stderr strings.Builder
		rev := exec.Command("git", "-C", root, "rev-parse", "--show-toplevel")
		rev.Env = withoutGitLocation(os.Environ())
		rev.Stderr = &stderr
		top, err := rev.Output()
		switch {
		case err != nil && strings.Contains(stderr.String(), "not a git repository"):
			t.Skipf("module root %s is not in a git checkout; the check builds from a commit", root)
		case err != nil:
			t.Fatalf("git rev-parse in %s: %v\n%s", root, err, stderr.String())
		case filepath.Clean(strings.TrimSpace(string(top))) != filepath.Clean(root):
			t.Skipf("module root %s is inside another checkout (%s); the check builds from a commit of this module",
				root, strings.TrimSpace(string(top)))
		}
		cmd := exec.Command("bash", "scripts/check-module-consumer.sh")
		cmd.Dir = ".."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("module consumer check failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "check-module-consumer: PASS") {
			t.Fatalf("module consumer check did not report PASS:\n%s", out)
		}
		t.Log(strings.TrimSpace(string(out)[strings.LastIndex(string(out), "check-module-consumer: PASS"):]))
	})
}

// withoutGitLocation drops GIT_DIR and GIT_WORK_TREE from env.
func withoutGitLocation(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_DIR=") || strings.HasPrefix(kv, "GIT_WORK_TREE=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
