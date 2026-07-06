package shellcapture

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestDecodeContent_ByteExact proves the decoder recovers EXACT bytes — including
// a trailing newline, which the old raw-cat capture lost to transport trimming
// (#247) — and tolerates base64 line-wrapping plus a trimmed trailing newline.
func TestDecodeContent_ByteExact(t *testing.T) {
	cases := map[string]string{
		"trailing newline":      "ORIGINAL_PRISTINE_CONTENT\n",
		"no trailing newline":   "no-newline",
		"empty file":            "",
		"multi-line + trailing": "a=1\nb=2\n",
		"crlf preserved":        "x\r\ny\r\n",
		"blank lines":           "\n\n\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			// Encode as the target would, then simulate what actually arrives:
			// (a) wrapped at 76 cols (GNU default), (b) transport trims the final \n.
			enc := base64.StdEncoding.EncodeToString([]byte(content))
			wrapped := wrap76(enc) + "\n"               // base64 wraps and adds a trailing \n
			arrived := strings.TrimRight(wrapped, "\n") // transport trims trailing newline

			got, err := DecodeContent(arrived)
			if err != nil {
				t.Fatalf("DecodeContent: %v", err)
			}
			if got != content {
				t.Errorf("byte-exact round-trip FAILED\n got  %q\n want %q", got, content)
			}
		})
	}
}

func TestDecodeContent_SingleLineNoWrap(t *testing.T) {
	// A short file base64s to a single line (no wrapping); trailing \n trimmed.
	content := "ORIGINAL_PRISTINE_CONTENT\n"
	enc := base64.StdEncoding.EncodeToString([]byte(content)) // e.g. "...K"
	got, err := DecodeContent(enc)                            // no trailing newline at all
	if err != nil {
		t.Fatalf("DecodeContent: %v", err)
	}
	if got != content {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestContentReadCmd(t *testing.T) {
	if got := ContentReadCmd("'/etc/foo'"); got != "base64 '/etc/foo'" {
		t.Errorf("ContentReadCmd = %q", got)
	}
}

// wrap76 inserts a newline every 76 characters, mimicking GNU base64 output, to
// prove the decoder strips wrapping whitespace.
func wrap76(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 76 {
		end := i + 76
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// TestExistenceReadCmd_FailSafeIfForm locks the fail-safe contract at the helper
// level (protecting all callers, not just the one handler with a regression test):
// ExistenceReadCmd MUST emit the `if…then…else…fi` form, NOT the destructive
// `test X && base64 X || printf S` short-circuit. With the short-circuit, a base64
// FAILURE on an existing file prints the absent sentinel with exit 0 — masking the
// failure so a caller records the file ABSENT and rollback DELETES it (the round-2
// destructive regression). The if-form propagates base64's non-zero exit instead.
func TestExistenceReadCmd_FailSafeIfForm(t *testing.T) {
	got := ExistenceReadCmd("-e", "'/etc/x'", "__KENSA_ABSENT__")
	want := "if [ -e '/etc/x' ]; then base64 '/etc/x'; else printf '%s' '__KENSA_ABSENT__'; fi"
	if got != want {
		t.Errorf("ExistenceReadCmd = %q, want %q", got, want)
	}
	if strings.Contains(got, "&&") || strings.Contains(got, "|| printf") {
		t.Errorf("ExistenceReadCmd must NOT use the fail-open `&& … || printf` short-circuit "+
			"(base64 failure would print the sentinel with exit 0, masking a read failure as "+
			"ABSENT → destructive rollback delete): %q", got)
	}
	// The -f flag variant (dconf_set) must also be the if-form.
	if f := ExistenceReadCmd("-f", "'/p'", "S"); f != "if [ -f '/p' ]; then base64 '/p'; else printf '%s' 'S'; fi" {
		t.Errorf("-f variant = %q", f)
	}
}
