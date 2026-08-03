package prestate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/redact"
)

// TestTextElidesFileShapedValues locks the disclosure guarantee at its
// source: whatever a handler passes through Text, a file body does not
// survive it.
//
// @spec pkg-prestate-describe
// @ac AC-08
func TestTextElidesFileShapedValues(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-08")

	body := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	got := Text(body)
	if strings.Contains(got, "root") || strings.Contains(got, "\n") {
		t.Errorf("Text leaked a multi-line body: %q", got)
	}
	if !strings.HasPrefix(got, "<") || !strings.HasSuffix(got, ">") {
		t.Errorf("Text(%q) = %q, want a size marker", body, got)
	}

	long := strings.Repeat("a", maxInline+1)
	if out := Text(long); strings.Contains(out, "aaaa") {
		t.Errorf("Text leaked a long single-line value: %q", out)
	}

	// A short single-line value is the thing operators actually want to
	// read, and must survive verbatim.
	if got := Text("PASS_MAX_DAYS 99999"); got != "PASS_MAX_DAYS 99999" {
		t.Errorf("Text mangled a short config line: %q", got)
	}
	if got := Text(""); got != Empty {
		t.Errorf("Text(\"\") = %q, want %q", got, Empty)
	}
}

// TestTextStripsControlChars covers the terminal/HTML injection path: a
// captured line comes off a remote host and lands in a log line and a UI
// row.
//
// @spec pkg-prestate-describe
// @ac AC-08
func TestTextStripsControlChars(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-08")

	got := Text("umask \x1b[31m0027\x07")
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("Text kept control characters: %q", got)
	}
	if !strings.Contains(got, "umask") {
		t.Errorf("Text dropped the printable content: %q", got)
	}
}

// TestIntAcceptsWidenedTypes covers the type-widening trap: the same
// captured integer arrives as int from a live capture, int64 across the
// agent wire, and float64 or json.Number from a JSON round-trip.
//
// @spec pkg-prestate-describe
// @ac AC-08
func TestIntAcceptsWidenedTypes(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-08")

	for name, v := range map[string]interface{}{
		"int":         int(7),
		"int64":       int64(7),
		"float64":     float64(7),
		"json.Number": json.Number("7"),
	} {
		got, ok := Int(map[string]interface{}{"n": v}, "n")
		if !ok || got != 7 {
			t.Errorf("Int(%s) = (%d, %v), want (7, true)", name, got, ok)
		}
	}

	// A numeric string is NOT coerced: a handler that encodes an integer as
	// a string did so deliberately (the wire layer requires it above 2^53).
	if _, ok := Int(map[string]interface{}{"n": "7"}, "n"); ok {
		t.Error("Int coerced a string; it must report absence instead")
	}
	if _, ok := Int(nil, "missing"); ok {
		t.Error("Int on a nil map must report absence")
	}
}

// TestAccessorsAreTotal asserts no accessor panics on a nil map, a missing
// key, or a wrong-typed value — the three shapes historical Data actually
// produces.
//
// @spec pkg-prestate-describe
// @ac AC-03
func TestAccessorsAreTotal(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-03")

	for _, d := range []map[string]interface{}{
		nil,
		{},
		{"k": nil},
		{"k": 12.5},
		{"k": []interface{}{1, 2}},
		{"k": map[string]interface{}{"a": 1}},
		{"k": struct{ A string }{"x"}},
	} {
		String(d, "k")
		Bool(d, "k")
		Int(d, "k")
		Count(d, "k")
		Size(d, "k")
		Value("k", d["k"])
	}
}

// TestValueRedactsByFieldName locks redaction at the shared renderer, so a
// handler cannot leak a credential by rendering a field it did not think
// about.
//
// @spec pkg-prestate-describe
// @ac AC-04
func TestValueRedactsByFieldName(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-04")

	if got := Value("password", "hunter2"); got != redact.Placeholder {
		t.Errorf("Value(password) = %q, want %q", got, redact.Placeholder)
	}
	if got := Value("prior_line", "PASS_MAX_DAYS 99999"); got != "PASS_MAX_DAYS 99999" {
		t.Errorf("Value redacted a non-credential field: %q", got)
	}
}

// TestValueNeverFormatsUnknownTypes guards the hole a %v fallback would
// open: a named string type or a nested struct carrying captured content.
//
// @spec pkg-prestate-describe
// @ac AC-02
func TestValueNeverFormatsUnknownTypes(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-02")

	type captured struct{ Content string }
	got := Value("k", captured{Content: "root:x:0:0:root:/root:/bin/bash"})
	if strings.Contains(got, "root") {
		t.Errorf("Value formatted an unknown type and leaked its content: %q", got)
	}
}

// TestGenericRedactsSensitiveFields covers the fallback path a mechanism
// with no describer takes.
//
// @spec pkg-prestate-describe
// @ac AC-04
func TestGenericRedactsSensitiveFields(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-04")

	got := Generic(&api.PreState{
		Mechanism:  "some_mechanism",
		Capturable: true,
		Data: map[string]interface{}{
			"user_password": "hunter2",
			"path":          "/etc/x",
		},
	})
	if strings.Contains(got, "hunter2") {
		t.Errorf("Generic leaked a credential: %q", got)
	}
	if !strings.Contains(got, "/etc/x") {
		t.Errorf("Generic dropped a safe field: %q", got)
	}
}

// TestGenericBoundsWideCaptures keeps the fallback renderable for a
// mechanism with many keys.
//
// @spec pkg-prestate-describe
// @ac AC-03
func TestGenericBoundsWideCaptures(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-03")

	data := map[string]interface{}{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		data[k] = k
	}
	got := Generic(&api.PreState{Mechanism: "m", Capturable: true, Data: data})
	if !strings.Contains(got, "+2 more") {
		t.Errorf("Generic did not summarize the overflow: %q", got)
	}
}

// TestTruncateCapsTheLine keeps a composed summary inside one UI row.
//
// @spec pkg-prestate-describe
// @ac AC-03
func TestTruncateCapsTheLine(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-03")

	got := Truncate(strings.Repeat("x", maxLine*2))
	if len([]rune(got)) > maxLine+len([]rune(ellipsis)) {
		t.Errorf("Truncate returned %d runes, want <= %d", len([]rune(got)), maxLine+1)
	}
}

// TestJoinDropsEmptyParts is what lets a describer compose optional fields
// without emitting a dangling separator when one was not captured.
//
// @spec pkg-prestate-describe
// @ac AC-03
func TestJoinDropsEmptyParts(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-03")

	if got := Join("a", "", "  ", "b"); got != "a, b" {
		t.Errorf("Join = %q, want %q", got, "a, b")
	}
}

// TestByteSizeUnits keeps the size marker readable across magnitudes.
//
// @spec pkg-prestate-describe
// @ac AC-08
func TestByteSizeUnits(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-08")

	for _, tc := range []struct {
		n    int
		want string
	}{
		{0, "0 B"},
		{412, "412 B"},
		{2048, "2.0 KiB"},
		{3 * 1024 * 1024, "3.0 MiB"},
	} {
		if got := ByteSize(tc.n); got != tc.want {
			t.Errorf("ByteSize(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// TestLineRedactsCredentialsInsideCapturedLines is the regression for a live
// credential leak: an adversarial review of this package running against a
// fleet host rendered
//
//	BindPassword secret-hunter2-abc, in /tmp/kensa-verify/scratch.conf
//
// The Data key was `prior_line`, which is not sensitive, so neither the
// evidence sanitizer nor length elision touched it — the credential was inside
// the value, named by the config file's own key.
//
// The two cases that must BOTH hold are the point. Redacting the credential is
// easy on its own; a bare substring match on "pass" does it, and also destroys
// PASS_MAX_DAYS, which is the single line this feature was requested to render.
//
// @spec pkg-prestate-describe
// @ac AC-01
func TestLineRedactsCredentialsInsideCapturedLines(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-01")

	// Every credential below is fabricated for this table. They are the point
	// of the test: it asserts they do NOT survive rendering.
	for _, tc := range []struct {
		name, in, want string
	}{
		{"the live leak", "BindPassword secret-hunter2-abc", "BindPassword <redacted>"}, // pragma: allowlist secret
		{"the headline example survives", "PASS_MAX_DAYS 99999", "PASS_MAX_DAYS 99999"},
		{"tab-separated headline example", "PASS_MAX_DAYS\t99999", "PASS_MAX_DAYS 99999"},
		{"credential word not final: a policy flag", "password_policy_required yes", "password_policy_required yes"},
		{"suffix form", "user_password hunter2", "user_password <redacted>"},
		{"camelCase", "apiKey abc123", "apiKey <redacted>"},
		{"short form", "rootpw hunter2", "rootpw <redacted>"},
		{"k=v", "auth_token=abc123", "auth_token=<redacted>"},
		{"fstab cifs: only the secret option",
			"//srv/share /mnt cifs username=u,password=SECRET,vers=3.0 0 0", // pragma: allowlist secret
			"//srv/share /mnt cifs username=u,password=<redacted>,vers=3.0 0 0"},
		{"ordinary fstab untouched", "/dev/sda1 / ext4 defaults,nosuid 0 0", "/dev/sda1 / ext4 defaults,nosuid 0 0"},
		{"sysctl tuple untouched", "net.ipv4.tcp_rmem 4096 131072 33554432", "net.ipv4.tcp_rmem 4096 131072 33554432"},
	} {
		if got := Line(tc.in); got != tc.want {
			t.Errorf("%s:\n  Line(%q)\n   = %q\n  want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestSanitizeKeepsFieldSeparators: TAB is a field separator, not a corrupted
// byte. Mapping it to '.' rendered /etc/login.defs as "PASS_MAX_DAYS.99999",
// an fstab swap line as "/swap.img.none.swap.sw.0.0", and net.ipv4.tcp_rmem as
// "4096.131072.33554432", which reads as a dotted quad.
//
// @spec pkg-prestate-describe
// @ac AC-08
func TestSanitizeKeepsFieldSeparators(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-08")

	if got := Text("PASS_MAX_DAYS\t99999"); got != "PASS_MAX_DAYS 99999" {
		t.Errorf("tab should render as a space, got %q", got)
	}
	if got := Text("has\x00a\x1bcontrol"); got != "has.a.control" {
		t.Errorf("genuine control bytes should still render as '.', got %q", got)
	}
}

// TestGenericSanitizesKeysAndMechanism: the sweep for "everything reaching the
// rendered line is sanitized" originally covered values only. Data keys and the
// mechanism string are concatenated in raw, and both come from a stored
// pre-state that the package doc promises to tolerate when foreign, corrupted
// or written by an older Kensa. An escape sequence there lands in a UI row, and
// a newline breaks the one-line invariant the consumer's phase list assumes.
//
// @spec pkg-prestate-describe
// @ac AC-08
func TestGenericSanitizesKeysAndMechanism(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-08")

	got := Generic(&api.PreState{
		Mechanism: "evil\x1b[31mmech\n",
		Data:      map[string]interface{}{"bad\nkey\x1b[0m": "v"},
	})
	if strings.ContainsAny(got, "\n\r\x1b") {
		t.Errorf("control characters or newlines survived into the rendered line: %q", got)
	}
}

// TestGenericNeverEmitsAFileBodyAtAnyLength closes the gap between what the
// public artifacts promise and what the fallback did.
//
// The godoc, spec C-01 and the operator guide all state that no describer and
// no fallback emits a captured file body AT ANY LENGTH. Length elision alone
// did not deliver that: a short, single-line body is under the inline limit, so
// Generic rendered it verbatim. The existing multi-line poison value proved
// only half the claim.
//
// The fallback is reached in exactly the case the package advertises — a
// mechanism absent from the reading binary's registry, such as an older
// consumer reading a newer record — so it is the path least able to rely on
// handler discipline.
//
// @spec pkg-prestate-describe
// @ac AC-02
func TestGenericNeverEmitsAFileBodyAtAnyLength(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-02")

	// Short enough that length elision does not fire.
	body := "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin"

	for _, key := range []string{"content", "prior_content", "files_content", "files_snapshot"} {
		got := Generic(&api.PreState{
			Mechanism: "file_content",
			Data:      map[string]interface{}{key: body},
		})
		if strings.Contains(got, body) {
			t.Errorf("key %q leaked a captured file body into the fallback: %q", key, got)
		}
		if !strings.Contains(got, key+"=<") {
			t.Errorf("key %q should render a size marker, got %q", key, got)
		}
	}

	// A key that does NOT name content still renders, or the fallback would be
	// useless.
	got := Generic(&api.PreState{Mechanism: "file_content",
		Data: map[string]interface{}{"path": "/etc/login.defs"}})
	if !strings.Contains(got, "/etc/login.defs") {
		t.Errorf("over-elided a non-content key: %q", got)
	}
}
