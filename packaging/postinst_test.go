// Package packaging contains tests for the packaging/ scripts wired
// into the kensa rpm and deb via .goreleaser.yaml's
// nfpms[].scripts.postinstall. Tests shell out to /bin/sh + the script
// under test with RULES_DIR set to controlled mock paths so the same
// script that ships in production rpm/deb is what's exercised here.
package packaging

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// postinstPath resolves the on-disk path to packaging/postinst.sh
// relative to this test file. Lets `go test ./packaging/...` find the
// script regardless of cwd.
func postinstPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	p := filepath.Join(filepath.Dir(thisFile), "postinst.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("postinst.sh not found at %s: %v", p, err)
	}
	return p
}

// runPostinst executes postinst.sh under /bin/sh with RULES_DIR set
// and returns (stdout, stderr, exitCode).
func runPostinst(t *testing.T, rulesDir string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("/bin/sh", postinstPath(t))
	cmd.Env = append(os.Environ(), "RULES_DIR="+rulesDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("run postinst: %v", err)
		}
	}
	return stdout.String(), stderr.String(), exit
}

// @spec packaging-postinst-warning
// @ac AC-01
func TestPostinst_SilentWhenCorpusPresent(t *testing.T) {
	t.Run("packaging-postinst-warning/AC-01", func(t *testing.T) {})

	dir := t.TempDir()
	// Any file counts — C-01 says "at least one file", not "at least
	// one .yml file" — so we can verify the looser contract.
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, exit := runPostinst(t, dir)
	if exit != 0 {
		t.Errorf("expected exit 0, got %d", exit)
	}
	if stdout != "" {
		t.Errorf("expected no stdout, got %q", stdout)
	}
	if stderr != "" {
		t.Errorf("expected no stderr, got %q", stderr)
	}
}

// @spec packaging-postinst-warning
// @ac AC-02
func TestPostinst_WarnsOnEmptyCorpus(t *testing.T) {
	t.Run("packaging-postinst-warning/AC-02", func(t *testing.T) {})

	dir := t.TempDir() // empty by default

	_, stderr, exit := runPostinst(t, dir)
	if exit != 0 {
		t.Errorf("expected exit 0 (corpus is soft requirement), got %d", exit)
	}
	for _, sub := range []string{"kensa-rules", "--rules-dir", "/usr/share/kensa/rules"} {
		if !strings.Contains(stderr, sub) {
			t.Errorf("warning must mention %q; stderr=%q", sub, stderr)
		}
	}
}

// @spec packaging-postinst-warning
// @ac AC-03
func TestPostinst_WarnsOnMissingCorpus(t *testing.T) {
	t.Run("packaging-postinst-warning/AC-03", func(t *testing.T) {})

	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, stderr, exit := runPostinst(t, missing)
	if exit != 0 {
		t.Errorf("expected exit 0 (corpus is soft requirement), got %d", exit)
	}
	for _, sub := range []string{"kensa-rules", "--rules-dir", "/usr/share/kensa/rules"} {
		if !strings.Contains(stderr, sub) {
			t.Errorf("warning must mention %q; stderr=%q", sub, stderr)
		}
	}
}

// @spec packaging-postinst-warning
// @ac AC-04
func TestPostinst_NoNetworkTools(t *testing.T) {
	t.Run("packaging-postinst-warning/AC-04", func(t *testing.T) {})

	// AC-04 is a source-level check: the script must not REFERENCE
	// network-fetching tools at any line. Grep on word boundaries to
	// avoid matching innocuous substrings (e.g. "discourages" vs
	// "curl"). The deny list mirrors the C-03 enumeration.
	deny := []string{"curl", "wget", "nc", "ssh", "git", "dnf", "apt"}

	body, err := os.ReadFile(postinstPath(t))
	if err != nil {
		t.Fatal(err)
	}

	// Strip comments before searching — we DO mention "dnf install
	// kensa-rules" and "apt install kensa-rules" in the warning text
	// (operator instructions, not script invocations) and in the
	// comment block (explaining the Recommends rationale).
	var stripped bytes.Buffer
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		// Skip pure comment lines.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Skip heredoc body — the warning text quotes "dnf install
		// kensa-rules" and "apt install kensa-rules" intentionally.
		if strings.HasPrefix(trimmed, "dnf install") ||
			strings.HasPrefix(trimmed, "apt install") ||
			strings.HasPrefix(trimmed, "kensa check") {
			continue
		}
		stripped.WriteString(line + "\n")
	}

	src := stripped.String()
	for _, tool := range deny {
		// Word-boundary check: surrounded by space/newline/quote.
		// The tool must appear as the FIRST token of a command, not
		// embedded inside another word.
		patterns := []string{
			"\n" + tool + " ",
			"\n" + tool + "\n",
			" " + tool + " ",
			"|" + tool + " ",
			"|" + tool + "\n",
			"&" + tool + " ",
			"$(" + tool + " ",
			"`" + tool + " ",
		}
		for _, pat := range patterns {
			if strings.Contains(src, pat) {
				t.Errorf("postinst.sh invokes network tool %q (matched %q) — violates C-03", tool, pat)
			}
		}
	}
}
