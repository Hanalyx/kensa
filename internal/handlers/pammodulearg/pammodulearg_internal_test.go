package pammodulearg

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// existingMode preserves a non-0644 PAM file's mode (so the agent path neither
// widens a hardened include on apply nor on rollback), and falls back to
// pamFileMode for an absent file.
//
// @spec handler-pam-module-arg
// @ac AC-05
func TestExistingMode_PreservesNon0644(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-05", func(t *testing.T) {})
	dir := t.TempDir()
	f := filepath.Join(dir, "system-auth")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := existingMode(f); got.Perm() != 0o600 {
		t.Errorf("existingMode(0600 file) = %o, want 0600", got.Perm())
	}
	if got := existingMode(filepath.Join(dir, "nope")); got != pamFileMode {
		t.Errorf("existingMode(absent) = %o, want fallback %o", got, pamFileMode)
	}
}

// A single quote in a rule-derived field must not break out of the shell
// quoting in the generated sed program (SSH-shell fallback hardening). Verified
// by actually executing each generated command through /bin/sh and asserting
// the injected `touch <sentinel>` never runs.
//
// @spec handler-pam-module-arg
// @ac AC-03
func TestSedPrograms_SingleQuoteSafe(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-03", func(t *testing.T) {})
	dir := t.TempDir()
	target := filepath.Join(dir, "pam")
	sentinel := filepath.Join(dir, "pwned")
	// Payload tries to close the shell quote and run touch <sentinel>.
	evil := `x'; touch ` + sentinel + `; '`

	cmds := []string{
		buildEnsureAppendCmd(target, "", `pam_unix\.so`, shellEscapeForSed(evil)),
		buildRemoveCmd(target, "", `pam_unix\.so`, evil, false),
		buildRemoveCmd(target, "", `pam_unix\.so`, evil, true),
	}
	for _, cmd := range cmds {
		if err := os.WriteFile(target, []byte("password pam_unix.so\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = exec.Command("/bin/sh", "-c", cmd).Run() // sed may exit non-zero; we only care about side effects
		if _, err := os.Stat(sentinel); err == nil {
			t.Fatalf("INJECTION: sentinel created — single-quote breakout in: %s", cmd)
		}
	}
}
