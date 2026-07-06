package dconfset

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestRestoreFileShellCmd_BytePerfect_FormatChars is the round-5 panel regression
// for the printf format-operand bug: the shell restore command must pass the
// captured content as printf's ARGUMENT (`printf '%s' <content>`), NOT as its
// FORMAT string (`printf <content>`). With the buggy form, content containing a
// `%` or `\` is interpreted as printf conversions/escapes and silently truncated
// or mangled — defeating byte-perfect rollback while still reporting success.
// (Live-proven: `net.core.foo=1 # 50% margin, path C:\newdir` restored 43→19 bytes.)
// sysctl_set's persist restore uses the identical idiom (grep-verified).
func TestRestoreFileShellCmd_BytePerfect_FormatChars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "00-security")
	// Adversarial content: printf directives (%s %d %), a backslash escape, a
	// trailing newline — all of which the buggy format-operand form corrupts.
	content := "[org/gnome/desktop]\nvalue=50% done, path C:\\newdir\nx=%s%d\n"

	cmd := restoreFileShellCmd(path, content, true)
	if out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput(); err != nil {
		t.Fatalf("restore command failed: %v (output: %s)", err, out)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(got) != content {
		t.Errorf("restore NOT byte-perfect:\n got  %q (%d bytes)\n want %q (%d bytes)",
			got, len(got), content, len(content))
	}
}
