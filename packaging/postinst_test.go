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
	// GROUPADD_CMD=true makes the service-handler group block a no-op:
	// whatever the host's /etc/group says, the "groupadd" it shells out
	// to is /bin/true, so it never mutates anything and never writes to
	// stderr. That keeps these rules-corpus tests isolated from group
	// provisioning (and keeps stderr clean for the AC-01 silent-path
	// assertion). The dedicated group tests below drive that block
	// directly via GROUP_FILE.
	return runPostinstEnv(t, []string{"RULES_DIR=" + rulesDir, "GROUPADD_CMD=true"})
}

// runPostinstEnv executes postinst.sh under /bin/sh with a fully
// specified extra-env slice (appended to os.Environ) and returns
// (stdout, stderr, exitCode). Used by the group-provisioning tests to
// inject GROUP_FILE / GROUPADD_CMD stubs.
func runPostinstEnv(t *testing.T, extra []string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("/bin/sh", postinstPath(t))
	cmd.Env = append(os.Environ(), extra...)
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

// sudoersPath resolves packaging/sudoers-kensa-systemd-helper relative
// to this test file.
func sudoersPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "sudoers-kensa-systemd-helper")
}

// writeStub writes an executable /bin/sh stub with the given body and
// returns its absolute path.
func writeStub(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// populatedRulesDir returns a temp dir holding one marker file, so the
// rules-corpus branch of postinst stays silent and the group tests can
// isolate the provisioning behavior.
func populatedRulesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "marker"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
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
// @spec packaging-sudoers-helper
// @ac AC-06
func TestPostinst_NoNetworkTools(t *testing.T) {
	t.Run("packaging-postinst-warning/AC-04", func(t *testing.T) {})
	// Same source-level no-network assertion satisfies the
	// packaging-sudoers-helper AC-06 obligation (maintainer scripts
	// touch no network) — the group block this PR adds introduces no
	// network tool.
	t.Run("packaging-sudoers-helper/AC-06", func(t *testing.T) {})

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

// expectedSudoersRule is the single rule the package must ship. Kept as
// one constant so the content test and the goreleaser-wiring test agree.
const expectedSudoersRule = "%kensa ALL=(root) NOPASSWD: /usr/libexec/kensa-systemd-helper"

// @spec packaging-sudoers-helper
// @ac AC-01
// @spec agent-systemd-helper
// @ac AC-09
func TestSudoersFragment_ContentAndWiring(t *testing.T) {
	t.Run("packaging-sudoers-helper/AC-01", func(t *testing.T) {})
	t.Run("agent-systemd-helper/AC-09", func(t *testing.T) {})

	body, err := os.ReadFile(sudoersPath(t))
	if err != nil {
		t.Fatalf("sudoers fragment not found: %v", err)
	}

	// Exactly one runnable (non-comment, non-blank) line, and it is the
	// expected rule — nothing else is granted.
	var runnable []string
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		runnable = append(runnable, trimmed)
	}
	if len(runnable) != 1 {
		t.Fatalf("expected exactly one runnable sudoers line, got %d: %q", len(runnable), runnable)
	}
	if runnable[0] != expectedSudoersRule {
		t.Errorf("sudoers rule = %q, want %q", runnable[0], expectedSudoersRule)
	}

	// AC-09: the package actually wires the fragment to the canonical
	// path at the mandatory mode. Assert the goreleaser nfpm contents
	// reference both the dst path and mode 0440.
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(thisFile))
	gr, err := os.ReadFile(filepath.Join(repoRoot, ".goreleaser.yaml"))
	if err != nil {
		t.Fatalf("read .goreleaser.yaml: %v", err)
	}
	grs := string(gr)
	for _, want := range []string{
		"/etc/sudoers.d/kensa-systemd-helper",
		"./packaging/sudoers-kensa-systemd-helper",
		"mode: 0440",
	} {
		if !strings.Contains(grs, want) {
			t.Errorf(".goreleaser.yaml must wire the sudoers fragment: missing %q", want)
		}
	}
}

// @spec packaging-sudoers-helper
// @ac AC-02
func TestSudoersFragment_VisudoSyntax(t *testing.T) {
	t.Run("packaging-sudoers-helper/AC-02", func(t *testing.T) {})

	visudo, err := exec.LookPath("visudo")
	if err != nil {
		t.Skip("visudo not available; skipping syntax check")
	}
	// `visudo -c -f <file>` parses the file and reports OK/errors. It
	// validates syntax independent of ownership; an unknown group is not
	// a syntax error. Run on a 0440 copy so a mode warning can't muddy
	// the result.
	tmp := filepath.Join(t.TempDir(), "sudoers")
	body, err := os.ReadFile(sudoersPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, body, 0o440); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(visudo, "-c", "-f", tmp).CombinedOutput()
	if err != nil {
		t.Fatalf("visudo -c rejected the fragment: %v\n%s", err, out)
	}
}

// @spec packaging-sudoers-helper
// @ac AC-03
func TestPostinst_CreatesKensaGroupWhenAbsent(t *testing.T) {
	t.Run("packaging-sudoers-helper/AC-03", func(t *testing.T) {})

	stubDir := t.TempDir()
	log := filepath.Join(t.TempDir(), "groupadd.log")
	// Group "absent": a group file with no kensa line. Local-file check,
	// NOT getent — see the postinst comment on the nsswitch threat.
	groupFile := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(groupFile, []byte("root:x:0:\ndaemon:x:1:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	groupadd := writeStub(t, stubDir, "groupadd", "printf '%s\\n' \"$*\" >> "+log)

	_, stderr, exit := runPostinstEnv(t, []string{
		"RULES_DIR=" + populatedRulesDir(t),
		"GROUP_FILE=" + groupFile,
		"GROUPADD_CMD=" + groupadd,
	})
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%q", exit, stderr)
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("groupadd was not invoked when the group was absent: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected groupadd invoked exactly once, got %d invocations: %q", len(lines), lines)
	}
	if lines[0] != "--system kensa" {
		t.Errorf("groupadd args = %q, want %q", lines[0], "--system kensa")
	}
}

// @spec packaging-sudoers-helper
// @ac AC-07
func TestPostinst_IgnoresRemoteOnlyGroup(t *testing.T) {
	t.Run("packaging-sudoers-helper/AC-07", func(t *testing.T) {})

	// The local /etc/group has NO kensa line — simulating a host where
	// "kensa" exists only in a directory service (LDAP/NIS/SSSD), which
	// `getent` would have matched but a local-file check must not. The
	// guard MUST still create the local group so the privilege boundary
	// doesn't silently defer to the remote group's membership.
	stubDir := t.TempDir()
	log := filepath.Join(t.TempDir(), "groupadd.log")
	groupFile := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(groupFile, []byte("root:x:0:\nsudo:x:27:alice\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	groupadd := writeStub(t, stubDir, "groupadd", "printf '%s\\n' \"$*\" >> "+log)

	_, stderr, exit := runPostinstEnv(t, []string{
		"RULES_DIR=" + populatedRulesDir(t),
		"GROUP_FILE=" + groupFile,
		"GROUPADD_CMD=" + groupadd,
	})
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%q", exit, stderr)
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("guard must create the LOCAL group even when a same-named remote group could exist: %v", err)
	}
	if strings.TrimSpace(string(got)) != "--system kensa" {
		t.Errorf("groupadd args = %q, want %q", strings.TrimSpace(string(got)), "--system kensa")
	}
}

// @spec packaging-sudoers-helper
// @ac AC-04
func TestPostinst_GroupCreationIdempotent(t *testing.T) {
	t.Run("packaging-sudoers-helper/AC-04", func(t *testing.T) {})

	stubDir := t.TempDir()
	log := filepath.Join(t.TempDir(), "groupadd.log")
	// Group "present": a local group file that already has a kensa line.
	groupFile := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(groupFile, []byte("root:x:0:\nkensa:x:999:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	groupadd := writeStub(t, stubDir, "groupadd", "printf '%s\\n' \"$*\" >> "+log)

	_, stderr, exit := runPostinstEnv(t, []string{
		"RULES_DIR=" + populatedRulesDir(t),
		"GROUP_FILE=" + groupFile,
		"GROUPADD_CMD=" + groupadd,
	})
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%q", exit, stderr)
	}
	if b, err := os.ReadFile(log); err == nil && strings.TrimSpace(string(b)) != "" {
		t.Errorf("groupadd must not run when the group is already present; invoked with %q", string(b))
	}
}

// @spec packaging-sudoers-helper
// @ac AC-05
func TestPostinst_NeverAddsUserToGroup(t *testing.T) {
	t.Run("packaging-sudoers-helper/AC-05", func(t *testing.T) {})

	body, err := os.ReadFile(postinstPath(t))
	if err != nil {
		t.Fatal(err)
	}
	// Strip comment lines — the rationale comment legitimately spells out
	// the `usermod -aG kensa <user>` an admin runs by hand. The assertion
	// is about what the script EXECUTES, not what it documents.
	var stripped strings.Builder
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		stripped.WriteString(line + "\n")
	}
	src := stripped.String()
	for _, bad := range []string{"usermod", "gpasswd", "adduser", "-aG"} {
		if strings.Contains(src, bad) {
			t.Errorf("postinst executes %q — install must never add a user to the kensa group (C-04)", bad)
		}
	}
}
