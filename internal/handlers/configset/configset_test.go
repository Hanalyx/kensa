package configset_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent/transport/local"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/handlers/configset"
)

// @spec handler-config-set
// @ac AC-01
func TestApply_AC01_SetsKeyEqualsValue(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"file":      "/etc/selinux/config",
		"key":       "SELINUX",
		"value":     "enforcing",
		"separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	// The apply pipeline should contain the target line SELINUX=enforcing.
	if !strings.Contains(tp.Runs[0], "SELINUX=enforcing") {
		t.Errorf("expected SELINUX=enforcing in cmd; got %q", tp.Runs[0])
	}
}

// @spec handler-config-set
// @ac AC-02
func TestApply_AC02_SpacedEqualsSign(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"file":      "/etc/login.defs",
		"key":       "PASS_MAX_DAYS",
		"value":     "90",
		"separator": " = ",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "PASS_MAX_DAYS = 90") {
		t.Errorf("expected PASS_MAX_DAYS = 90 in cmd; got %q", tp.Runs[0])
	}
}

// @spec handler-config-set
// @ac AC-03
func TestApply_AC03_SpaceSeparator(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"file":      "/etc/ssh/sshd_config",
		"key":       "PermitRootLogin",
		"value":     "no",
		"separator": " ",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "PermitRootLogin no") {
		t.Errorf("expected 'PermitRootLogin no' in cmd; got %q", tp.Runs[0])
	}
}

// @spec handler-config-set
// @ac AC-04
func TestApply_AC04_IsIdempotent(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	params := api.Params{"file": "/etc/selinux/config", "key": "SELINUX", "value": "enforcing"}
	for i := 0; i < 3; i++ {
		res, err := h.Apply(context.Background(), tp, params, nil)
		if err != nil || !res.Success {
			t.Fatalf("invocation %d: err=%v success=%v", i+1, err, res.Success)
		}
	}
}

// @spec handler-config-set
// @ac AC-05
func TestCapture_AC05_RecordsExistingLine(t *testing.T) {
	tp := engine.NewFakeTransport()
	// The capture command is a multi-part pipeline; we program the result
	// by matching the key pattern the handler will send.
	pattern := "^[[:space:]]*SELINUX[[:space:]=]"
	path := "/etc/selinux/config"

	// The capture one-liner tests existence, grep, and returns the match.
	// We use a wildcard approach: FakeTransport returns the result for
	// the exact command the handler generates.
	cmd := buildCaptureCmd(path, pattern)
	tp.Results[cmd] = &api.CommandResult{Stdout: "SELINUX=disabled\n"}

	h := configset.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"file": path, "key": "SELINUX", "value": "enforcing",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["line_existed"] != true {
		t.Errorf("line_existed=%v, want true", pre.Data["line_existed"])
	}
	if pre.Data["prior_line"] != "SELINUX=disabled" {
		t.Errorf("prior_line=%q, want SELINUX=disabled", pre.Data["prior_line"])
	}
}

// @spec handler-config-set
// @ac AC-06
func TestCapture_AC06_RecordsAbsentKey(t *testing.T) {
	tp := engine.NewFakeTransport()
	pattern := "^[[:space:]]*NEWKEY[[:space:]=]"
	path := "/etc/config"
	cmd := buildCaptureCmd(path, pattern)
	tp.Results[cmd] = &api.CommandResult{Stdout: "__KENSA_ABSENT__\n"}

	h := configset.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"file": path, "key": "NEWKEY", "value": "yes",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if pre.Data["line_existed"] != false {
		t.Errorf("line_existed=%v, want false", pre.Data["line_existed"])
	}
}

// @spec handler-config-set
// @ac AC-07
func TestCapture_AC07_NonExistentFileReturnsErrCaptureIncomplete(t *testing.T) {
	tp := engine.NewFakeTransport()
	pattern := "^[[:space:]]*KEY[[:space:]=]"
	path := "/no/such/file"
	cmd := buildCaptureCmd(path, pattern)
	tp.Results[cmd] = &api.CommandResult{Stdout: "__KENSA_NOFILE__\n"}

	h := configset.New()
	_, err := h.Capture(context.Background(), tp, api.Params{
		"file": path, "key": "KEY", "value": "v",
	})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Errorf("got %v, want ErrCaptureIncomplete", err)
	}
}

// @spec handler-config-set
// @ac AC-08
func TestRollback_AC08_RestoresPriorLine(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"file":         "/etc/selinux/config",
			"key":          "SELINUX",
			"separator":    "=",
			"line_existed": true,
			"prior_line":   "SELINUX=disabled",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "sed -i") {
		t.Errorf("expected sed -i in rollback; got %q", cmd)
	}
	if !strings.Contains(cmd, "SELINUX=disabled") {
		t.Errorf("expected prior_line in rollback sed; got %q", cmd)
	}
}

// @spec handler-config-set
// @ac AC-09
func TestRollback_AC09_RemovesAppendedLine(t *testing.T) {
	tp := engine.NewFakeTransport()
	h := configset.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"file":         "/etc/config",
			"key":          "NEWKEY",
			"separator":    "=",
			"line_existed": false,
			"prior_line":   "",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// Rollback removes the line; the command should be a sed -i delete.
	if len(tp.Runs) != 1 {
		t.Fatalf("got %d Run calls, want 1", len(tp.Runs))
	}
	if !strings.Contains(tp.Runs[0], "/d") {
		t.Errorf("expected sed delete expression; got %q", tp.Runs[0])
	}
}

func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	var _ api.CombinedHandler = configset.New()
}

// buildCaptureCmd reconstructs the exact capture command the handler
// emits for a given file and grep pattern so tests can program responses.
func buildCaptureCmd(file, pattern string) string {
	qFile := "'" + strings.ReplaceAll(file, "'", `'\''`) + "'"
	qPat := "'" + strings.ReplaceAll(pattern, "'", `'\''`) + "'"
	return fmt.Sprintf(
		`if [ ! -e %[1]s ]; then printf '__KENSA_NOFILE__\n'; elif grep -qE %[2]s %[1]s 2>/dev/null; then grep -Em1 %[2]s %[1]s; else printf '__KENSA_ABSENT__\n'; fi`,
		qFile, qPat,
	)
}

// ─── P-004 migration behavioral-parity tests ─────────────────────────────
//
// Per FMA Q1: the Go regex MUST match sed's
// ^[[:space:]]*KEY[[:space:]=] semantics exactly. The fixture
// cases below cover the FMA-identified concerns: trailing-
// newline, CRLF, dotted keys (regex metachars), multiple
// matches, active-vs-commented detection, no-match-then-append.

// TestAgentApply_KeyAbsent_AppendsAtEnd locks the no-match
// branch: when the key doesn't exist, append the line.
func TestAgentApply_KeyAbsent_AppendsAtEnd(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	original := "# comment\nOtherKey=foo\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "MaxAuthTries", "value": "3", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should succeed; got: %s", res.Detail)
	}
	got, _ := os.ReadFile(target)
	want := "# comment\nOtherKey=foo\nMaxAuthTries=3\n"
	if string(got) != want {
		t.Errorf("content mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentApply_ActiveKey_Replaces locks the active-line
// replace branch.
func TestAgentApply_ActiveKey_Replaces(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	original := "MaxAuthTries=6\nOtherKey=foo\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	_, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "MaxAuthTries", "value": "3", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(target)
	want := "MaxAuthTries=3\nOtherKey=foo\n"
	if string(got) != want {
		t.Errorf("content mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentApply_CommentedKey_NoChange_AppendsActive locks
// FMA Q1.e: commented `#MaxAuthTries` lines are NOT replaced.
// Apply appends an active line instead (no-match path).
func TestAgentApply_CommentedKey_NoChange_AppendsActive(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	original := "#MaxAuthTries=6\nOtherKey=foo\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	_, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "MaxAuthTries", "value": "3", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(target)
	want := "#MaxAuthTries=6\nOtherKey=foo\nMaxAuthTries=3\n"
	if string(got) != want {
		t.Errorf("commented line should be preserved + active line appended:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentApply_LeadingWhitespace_StillMatches locks the
// `^[[:space:]]*KEY[[:space:]=]` leading-whitespace tolerance:
// indented active lines are still treated as active.
func TestAgentApply_LeadingWhitespace_StillMatches(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	original := "    MaxAuthTries=6\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	_, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "MaxAuthTries", "value": "3", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(target)
	want := "MaxAuthTries=3\n"
	if string(got) != want {
		t.Errorf("indented line should be replaced (loses indentation):\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentApply_MultipleMatches_AllReplaced locks FMA Q1.d:
// sed replaces every matching line; Go path must match.
func TestAgentApply_MultipleMatches_AllReplaced(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	original := "MaxAuthTries=6\n# comment\nMaxAuthTries=3\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	_, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "MaxAuthTries", "value": "1", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(target)
	want := "MaxAuthTries=1\n# comment\nMaxAuthTries=1\n"
	if string(got) != want {
		t.Errorf("all matching lines should be replaced:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentApply_KeyWithDot_LiteralMatch locks FMA Q1.f: a
// key with `.` (regex metachar) is matched literally via
// regexp.QuoteMeta — should NOT match a similar-but-different
// key.
func TestAgentApply_KeyWithDot_LiteralMatch(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	original := "net.ipv4.ip_forward=0\nnetXipv4Xip_forward=1\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	_, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "net.ipv4.ip_forward", "value": "1", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(target)
	// First line replaced; second line NOT (literal . match).
	want := "net.ipv4.ip_forward=1\nnetXipv4Xip_forward=1\n"
	if string(got) != want {
		t.Errorf("dotted key should match literally:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentApply_NoTrailingNewline locks FMA Q1.b: a file
// without a trailing newline gets a newline before the
// appended line so the new line is on its own line.
func TestAgentApply_NoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	original := "OtherKey=foo" // no \n
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	_, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "NewKey", "value": "bar", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(target)
	want := "OtherKey=foo\nNewKey=bar\n"
	if string(got) != want {
		t.Errorf("no-trailing-newline:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentApply_EmptyFile_AppendsLine locks the empty-file
// edge case.
func TestAgentApply_EmptyFile_AppendsLine(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "empty.conf")
	if err := os.WriteFile(target, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	_, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "X", "value": "1", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "X=1\n" {
		t.Errorf("empty-file append: got %q, want %q", got, "X=1\n")
	}
}

// TestAgentRollback_RestoresPriorLine: line_existed=true →
// the current key line is replaced with the captured prior line.
func TestAgentRollback_RestoresPriorLine(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	current := "MaxAuthTries=1\nOther=x\n"
	if err := os.WriteFile(target, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	pre := &api.PreState{
		Data: map[string]interface{}{
			"file":         target,
			"key":          "MaxAuthTries",
			"separator":    "=",
			"line_existed": true,
			"prior_line":   "MaxAuthTries=6",
		},
	}
	tr := local.New()
	h := configset.New()
	res, err := h.Rollback(context.Background(), tr, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Rollback should succeed; got: %s", res.Detail)
	}
	got, _ := os.ReadFile(target)
	want := "MaxAuthTries=6\nOther=x\n"
	if string(got) != want {
		t.Errorf("rollback restore:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentApply_PreservesSetgid locks the fix/phase-2-rework
// F-004 fix: when the target file has setgid (or setuid /
// sticky) bits set, AtomicReplace preserves them. The
// pre-rework code used info.Mode().Perm() which silently
// stripped to the 9 perm bits.
func TestAgentApply_PreservesSetgid(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "setgid.conf")
	if err := os.WriteFile(target, []byte("k=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Add setgid bit. Note: `os.Chmod(target, 0o2644)` does
	// NOT work — Go's FileMode encodes setgid at bit 22, not
	// 0o2000, so an octal literal alone has no effect. Must
	// use os.ModeSetgid explicitly.
	if err := os.Chmod(target, 0o644|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	// Verify the chmod actually stuck (would fail if the
	// filesystem strips setgid — kensa doesn't claim to work
	// on filesystems that strip special bits).
	if pre, _ := os.Stat(target); pre.Mode()&os.ModeSetgid == 0 {
		t.Skip("filesystem strips setgid bit; skipping")
	}

	tr := local.New()
	h := configset.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"file":      target,
		"key":       "k",
		"value":     "2",
		"separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should succeed; got: %s", res.Detail)
	}
	info, _ := os.Stat(target)
	if info.Mode()&os.ModeSetgid == 0 {
		t.Errorf("setgid bit dropped: got Go FileMode=%v (perm=%o, setgid=%v), want setgid retained",
			info.Mode(), info.Mode().Perm(), info.Mode()&os.ModeSetgid != 0)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("perm bits drifted: got %o, want 0644", info.Mode().Perm())
	}
}

// TestAgentApply_CRLF_BehavioralParity locks the F-005
// regex char-class fix: the activeLineRegex used to use
// `[[:space:]]` which in Go matches `\t\n\v\f\r ` (6 chars)
// while sed -E with LC_ALL=C matches only `\t ` (2 chars).
// Files with CRLF endings diverged silently. Spelling the
// class `[\t ]` makes the Go regex byte-equivalent to sed.
func TestAgentApply_CRLF_BehavioralParity(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "crlf.conf")
	// CRLF-line-ending file: `\r` must NOT be treated as
	// whitespace by activeLineRegex.
	if err := os.WriteFile(target, []byte("KEY=old\r\nOther=x\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := local.New()
	h := configset.New()
	res, err := h.Apply(context.Background(), tr, api.Params{
		"file": target, "key": "KEY", "value": "new", "separator": "=",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Apply should succeed; got: %s", res.Detail)
	}
	got, _ := os.ReadFile(target)
	// `KEY=old\r` line gets replaced with `KEY=new`; CR is
	// consumed by `.*` so it's not preserved (matches sed
	// behavior on CRLF files under -E). The Other line is
	// preserved byte-for-byte including its CR.
	want := "KEY=new\nOther=x\r\n"
	if string(got) != want {
		t.Errorf("CRLF parity:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestAgentRollback_RemovesAppendedLine: line_existed=false →
// the line Apply appended is removed.
func TestAgentRollback_RemovesAppendedLine(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")
	current := "Other=x\nMaxAuthTries=3\n"
	if err := os.WriteFile(target, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	pre := &api.PreState{
		Data: map[string]interface{}{
			"file":         target,
			"key":          "MaxAuthTries",
			"separator":    "=",
			"line_existed": false,
			"prior_line":   "",
		},
	}
	tr := local.New()
	h := configset.New()
	res, err := h.Rollback(context.Background(), tr, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Rollback should succeed; got: %s", res.Detail)
	}
	got, _ := os.ReadFile(target)
	want := "Other=x\n"
	if string(got) != want {
		t.Errorf("rollback remove:\n  got:  %q\n  want: %q", got, want)
	}
}
