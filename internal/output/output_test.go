package output

import (
	"errors"
	"strings"
	"testing"
)

func TestParse_Valid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Spec
	}{
		{"format only", "json", Spec{Format: "json", Path: ""}},
		{"format with relative path", "json:report.json", Spec{Format: "json", Path: "report.json"}},
		{"format with absolute path", "oscal:/var/log/x.json", Spec{Format: "oscal", Path: "/var/log/x.json"}},
		{"path with dots", "csv:./out/results.csv", Spec{Format: "csv", Path: "./out/results.csv"}},
		{"path with second colon", "evidence:reports/2026-05-08:run.json", Spec{Format: "evidence", Path: "reports/2026-05-08:run.json"}},
		{"uppercase format normalizes", "JSON", Spec{Format: "json", Path: ""}},
		{"mixed case format normalizes", "JsoNl:foo.jsonl", Spec{Format: "jsonl", Path: "foo.jsonl"}},
		{"jsonl format", "jsonl", Spec{Format: "jsonl", Path: ""}},
		{"text format", "text", Spec{Format: "text", Path: ""}},
		{"csv format", "csv:r.csv", Spec{Format: "csv", Path: "r.csv"}},
		{"pdf format with path", "pdf:/tmp/report.pdf", Spec{Format: "pdf", Path: "/tmp/report.pdf"}},
		{"evidence format", "evidence", Spec{Format: "evidence", Path: ""}},
		{"oscal format", "oscal", Spec{Format: "oscal", Path: ""}},
		{"markdown format", "markdown:plan.md", Spec{Format: "markdown", Path: "plan.md"}},
		{"unix dash means stdout", "json:-", Spec{Format: "json", Path: ""}},
		{"unix dash with text", "text:-", Spec{Format: "text", Path: ""}},
		{"unix dash with oscal", "oscal:-", Spec{Format: "oscal", Path: ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParse_EmptyFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"colon only", ":"},
		{"colon with path", ":foo.json"},
		{"colon with absolute path", ":/var/log/foo.json"},
		{"two colons (empty format wins)", "::"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.input)
			if !errors.Is(err, ErrEmptyFormat) {
				t.Errorf("Parse(%q) error = %v, want ErrEmptyFormat", tc.input, err)
			}
		})
	}
}

func TestParse_EmptyPath(t *testing.T) {
	_, err := Parse("json:")
	if !errors.Is(err, ErrEmptyPath) {
		t.Errorf("Parse(\"json:\") error = %v, want ErrEmptyPath", err)
	}
}

func TestParse_PathRequired(t *testing.T) {
	// pdf without a path must be rejected at parse time so a binary
	// blob never reaches the operator's terminal.
	tests := []struct {
		name  string
		input string
	}{
		{"pdf bare", "pdf"},
		{"PDF uppercase bare", "PDF"},
		{"pdf with dash means stdout, also rejected", "pdf:-"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.input)
			if !errors.Is(err, ErrPathRequired) {
				t.Errorf("Parse(%q) error = %v, want ErrPathRequired", tc.input, err)
			}
		})
	}
}

func TestParse_PathRequired_StillRequiresAFormat(t *testing.T) {
	// Sanity: ErrPathRequired only fires AFTER format validation,
	// so unknown formats still get ErrUnknownFormat regardless of path.
	_, err := Parse("xml")
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("Parse(\"xml\") should still return ErrUnknownFormat, got %v", err)
	}
}

func TestParse_UnknownFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"unknown bare", "yaml"},
		{"unknown with path", "xml:foo.xml"},
		{"typo near known", "jsn"},
		{"common html typo", "html:report.html"},
		{"upper unknown", "XML"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.input)
			if !errors.Is(err, ErrUnknownFormat) {
				t.Errorf("Parse(%q) error = %v, want ErrUnknownFormat", tc.input, err)
			}
			// Sanity: error message must include the offending input
			// in the operator's original case so they see what they typed.
			if err != nil {
				badName := strings.SplitN(tc.input, ":", 2)[0]
				if !strings.Contains(err.Error(), badName) {
					t.Errorf("Parse(%q) error %q does not echo the original case-preserved bad name %q", tc.input, err.Error(), badName)
				}
			}
		})
	}
}

func TestParse_UnknownFormat_PreservesOperatorCase(t *testing.T) {
	// Locked behavior: the error message must echo the operator's
	// original (uppercase) input, not the lowercased lookup form.
	_, err := Parse("XML")
	if err == nil {
		t.Fatal("Parse(\"XML\") should have errored")
	}
	if !strings.Contains(err.Error(), `"XML"`) {
		t.Errorf("error %q does not contain operator's original case \"XML\"", err.Error())
	}
}

func TestParse_NoWhitespaceTrimming(t *testing.T) {
	// Locked policy: Parse does not trim whitespace. A trailing space
	// in the path is preserved verbatim. This is documented in Parse's
	// doc comment; the test exists so future refactors don't silently
	// add trimming that operators may have come to depend on (or vice
	// versa, that the lack of trimming doesn't accidentally start
	// rejecting whitespace).
	tests := []struct {
		name  string
		input string
		want  Spec
	}{
		{"trailing space in path", "json:foo ", Spec{Format: "json", Path: "foo "}},
		{"leading space in path", "json: foo", Spec{Format: "json", Path: " foo"}},
		{"tab in path", "json:foo\tbar", Spec{Format: "json", Path: "foo\tbar"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v (no-trim policy says path whitespace is valid)", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}

	// Whitespace in the format component yields ErrUnknownFormat
	// (because " json" is not a registered format); this is also
	// part of the no-trim policy.
	if _, err := Parse(" json"); !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("Parse(\" json\") error = %v, want ErrUnknownFormat (whitespace not trimmed)", err)
	}
}

func TestParseAll_Valid(t *testing.T) {
	values := []string{"json", "csv:r.csv", "oscal:assessment.json"}
	specs, err := ParseAll(values)
	if err != nil {
		t.Fatalf("ParseAll error: %v", err)
	}
	if len(specs) != 3 {
		t.Fatalf("ParseAll returned %d specs, want 3", len(specs))
	}
	want := []Spec{
		{Format: "json", Path: ""},
		{Format: "csv", Path: "r.csv"},
		{Format: "oscal", Path: "assessment.json"},
	}
	for i := range want {
		if specs[i] != want[i] {
			t.Errorf("specs[%d] = %+v, want %+v", i, specs[i], want[i])
		}
	}
}

func TestParseAll_PreservesOrder(t *testing.T) {
	// Operator's argv order matters for fan-out determinism (C-019).
	values := []string{"oscal", "json", "csv", "text"}
	specs, err := ParseAll(values)
	if err != nil {
		t.Fatalf("ParseAll error: %v", err)
	}
	for i, v := range values {
		if specs[i].Format != v {
			t.Errorf("specs[%d].Format = %q, want %q (order regression)", i, specs[i].Format, v)
		}
	}
}

func TestParseAll_EmptySlice(t *testing.T) {
	specs, err := ParseAll(nil)
	if err != nil {
		t.Fatalf("ParseAll(nil) error: %v", err)
	}
	if len(specs) != 0 {
		t.Errorf("ParseAll(nil) returned %d specs, want 0", len(specs))
	}
	specs, err = ParseAll([]string{})
	if err != nil {
		t.Fatalf("ParseAll([]) error: %v", err)
	}
	if len(specs) != 0 {
		t.Errorf("ParseAll([]) returned %d specs, want 0", len(specs))
	}
}

func TestParseAll_ReportsIndex(t *testing.T) {
	// When an --output value is invalid, the error must tell the operator
	// which positional argument failed so they can fix the right one.
	values := []string{"json", "csv:r.csv", "yaml:bad.yaml", "oscal"}
	_, err := ParseAll(values)
	if err == nil {
		t.Fatal("ParseAll should have returned an error")
	}
	if !strings.Contains(err.Error(), "output[2]") {
		t.Errorf("ParseAll error %q does not name the bad index (want output[2])", err.Error())
	}
	if !errors.Is(err, ErrUnknownFormat) {
		t.Errorf("ParseAll error chain does not contain ErrUnknownFormat: %v", err)
	}
}

func TestParseAll_FailsFastOnFirstError(t *testing.T) {
	// Confirm we report the *first* bad value, not the last; consistent
	// with operator expectation that argv is parsed left-to-right.
	values := []string{"json", "yaml:first.yaml", "xml:second.xml"}
	_, err := ParseAll(values)
	if err == nil {
		t.Fatal("ParseAll should have returned an error")
	}
	if !strings.Contains(err.Error(), "output[1]") {
		t.Errorf("ParseAll error should report output[1] first: got %q", err.Error())
	}
	if strings.Contains(err.Error(), "output[2]") {
		t.Errorf("ParseAll should not have reached output[2]: got %q", err.Error())
	}
}

func TestSpec_String(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{"no path", Spec{Format: "json"}, "json"},
		{"with path", Spec{Format: "csv", Path: "r.csv"}, "csv:r.csv"},
		{"absolute path", Spec{Format: "oscal", Path: "/tmp/x.json"}, "oscal:/tmp/x.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.spec.String(); got != tc.want {
				t.Errorf("Spec.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSpec_StringRoundTrip(t *testing.T) {
	// Every Spec produced by Parse must round-trip back to itself.
	// Excludes "json:-" because that normalizes to "json" (Path is
	// emptied), which is the intended behavior.
	inputs := []string{
		"json",
		"jsonl",
		"csv:r.csv",
		"pdf:/tmp/report.pdf",
		"oscal:/var/log/x.json",
		"text",
		"evidence:env.json",
		"markdown:plan.md",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			spec, err := Parse(in)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", in, err)
			}
			if got := spec.String(); got != in {
				t.Errorf("round trip: Parse(%q).String() = %q", in, got)
			}
		})
	}
}

func TestIsKnownFormat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"json yes", "json", true},
		{"text yes", "text", true},
		{"jsonl yes", "jsonl", true},
		{"csv yes", "csv", true},
		{"pdf yes", "pdf", true},
		{"evidence yes", "evidence", true},
		{"oscal yes", "oscal", true},
		{"markdown yes", "markdown", true},
		{"upper case yes", "JSON", true},
		{"mixed case yes", "JsOn", true},
		{"yaml no", "yaml", false},
		{"xml no", "xml", false},
		{"empty no", "", false},
		{"with colon no", "json:foo", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsKnownFormat(tc.in); got != tc.want {
				t.Errorf("IsKnownFormat(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestKnownFormats_StableOrder(t *testing.T) {
	// Order matters for help-text consistency. Lock the order here so a
	// future refactor that switches the registry to a map iteration breaks
	// loudly rather than silently.
	got := KnownFormats()
	want := []string{"text", "json", "jsonl", "csv", "pdf", "evidence", "oscal", "markdown"}
	if len(got) != len(want) {
		t.Fatalf("KnownFormats() length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("KnownFormats()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestKnownFormats_ReturnsCopy(t *testing.T) {
	// Mutating the returned slice must not corrupt the package's
	// internal source of truth.
	first := KnownFormats()
	first[0] = "MUTATED"
	second := KnownFormats()
	if second[0] == "MUTATED" {
		t.Errorf("KnownFormats() returned mutable reference to internal slice")
	}
}

func TestKnownFormats_AllAreParseable(t *testing.T) {
	// Every name returned by KnownFormats must be accepted by Parse.
	// Catches drift in the order-slice → registry direction.
	for _, name := range KnownFormats() {
		// pdf parsed bare returns ErrPathRequired, not ErrUnknownFormat;
		// validate the format-existence path via IsKnownFormat instead.
		if !IsKnownFormat(name) {
			t.Errorf("%q is in KnownFormats() but IsKnownFormat returns false", name)
		}
		// And confirm Parse accepts it (with a synthetic path for
		// path-required formats).
		input := name
		if FormatRequiresPath(name) {
			input = name + ":/tmp/x"
		}
		spec, err := Parse(input)
		if err != nil {
			t.Errorf("Parse(%q) failed for known format: %v", input, err)
			continue
		}
		if spec.Format != name {
			t.Errorf("Parse(%q).Format = %q, want %q", input, spec.Format, name)
		}
	}
}

func TestKnownFormats_RegistryAndOrderInSync(t *testing.T) {
	// Catches drift in BOTH directions: every map key must appear in
	// the order slice, and every slice entry must be a map key.
	if len(knownFormats) != len(knownFormatsOrder) {
		t.Errorf("knownFormats has %d entries; knownFormatsOrder has %d (drift)",
			len(knownFormats), len(knownFormatsOrder))
	}
	orderSet := make(map[string]struct{}, len(knownFormatsOrder))
	for _, f := range knownFormatsOrder {
		orderSet[f] = struct{}{}
	}
	for k := range knownFormats {
		if _, ok := orderSet[k]; !ok {
			t.Errorf("knownFormats key %q is missing from knownFormatsOrder", k)
		}
	}
	for _, f := range knownFormatsOrder {
		if _, ok := knownFormats[f]; !ok {
			t.Errorf("knownFormatsOrder entry %q is missing from knownFormats", f)
		}
	}
}

func TestFormatRequiresPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"pdf yes", "pdf", true},
		{"PDF case insensitive", "PDF", true},
		{"json no", "json", false},
		{"text no", "text", false},
		{"jsonl no", "jsonl", false},
		{"csv no", "csv", false},
		{"oscal no", "oscal", false},
		{"evidence no", "evidence", false},
		{"markdown no", "markdown", false},
		{"unknown no", "yaml", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatRequiresPath(tc.in); got != tc.want {
				t.Errorf("FormatRequiresPath(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
