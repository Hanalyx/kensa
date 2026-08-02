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
