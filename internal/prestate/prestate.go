// Package prestate renders a captured [api.PreState] as one
// operator-readable line for display surfaces (fleet UIs, plan previews,
// logs). It is a projection, never the evidence: the authoritative record
// is [api.PreState.Data] verbatim, and a summary that disagrees with Data
// is a bug in the summary.
//
// # No stability guarantee
//
// The rendered text is not a format contract. It is not semver-frozen, it
// is not parseable, and it may change in any release including a patch.
// Consumers that persist a summary should stamp it with the Kensa version
// that produced it so a corrected describer can be re-run over the rows it
// affected. Machine consumers read Data.
//
// # Disclosure
//
// Captured pre-state is operational data kept verbatim so rollback can
// restore it, and internal/redact deliberately does not scrub it. A summary
// is more exposed than Data: it is short enough to render inline in a list
// or a notification, where a collapsed JSON blob would not be. So the
// renderers here elide by construction rather than by caller discipline —
// [Text] replaces any multi-line or long string with a size marker, and
// [Value] redacts by field name. The guarantee this package holds:
//
//	no describer and no fallback emits a captured file body, at any length.
//
// A mechanism with no describer degrades to something safe and
// uninformative ([Generic]), never to something unsafe and detailed.
//
// # Totality
//
// Every accessor here is total. Data arrives from three sources that do not
// agree on Go types: a live capture (native types), the agent wire format
// (integers widen to int64, times to RFC3339Nano strings), and JSON decoded
// from the transaction log (numbers as float64 or json.Number). It may also
// have been written by an older Kensa whose handler recorded different keys.
// Accessors report absence rather than assuming a shape, and no accessor
// panics on a missing key, a nil map, or an unexpected type.
package prestate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/redact"
)

const (
	// maxInline is the longest single-line string rendered verbatim.
	// Above it a value becomes a size marker. Sized to fit a captured
	// config line or fstab entry, which is the value operators actually
	// want to read, while cutting off anything file-shaped.
	maxInline = 120
	// maxLine caps a whole rendered summary. A describer that composes
	// several fields cannot exceed a size a UI can show on one row.
	maxLine = 240
	// maxGenericFields is how many keys [Generic] renders before it
	// summarizes the remainder as a count. Keeps the fallback bounded for
	// a mechanism with a wide capture.
	maxGenericFields = 8
	// ellipsis marks a truncated line.
	ellipsis = "…"
)

// Empty is the rendering for a captured-but-empty string value. Spelled
// out because an empty summary field and an absent one mean different
// things: "the file existed and was empty" is not "there was no file".
const Empty = "<empty>"

// None is the rendering for a nil value.
const None = "<none>"

// String returns the string at key. The second result is false when the
// key is absent or holds a non-string.
func String(d map[string]interface{}, key string) (string, bool) {
	v, ok := d[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Field returns the string at key rendered for display, or fallback when
// the key is absent, holds a non-string, or is blank.
//
// This is the accessor a describer should reach for. Reading a field with
// [String] and concatenating it directly is what lets an unexpected value
// reach a summary intact; Field routes every value through [Text], so the
// elision guarantee holds for fields a handler considers trusted as much as
// for the ones it does not. Which fields are "obviously short" is exactly
// the judgment call this package exists to remove.
func Field(d map[string]interface{}, key, fallback string) string {
	s, ok := String(d, key)
	if !ok || strings.TrimSpace(s) == "" {
		return fallback
	}
	return Text(strings.TrimSpace(s))
}

// Bool returns the bool at key. The second result is false when the key is
// absent or holds a non-bool.
func Bool(d map[string]interface{}, key string) (bool, bool) {
	v, ok := d[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// Int returns the integer at key, accepting every numeric encoding Data can
// carry: native ints, the int64 the wire format widens them to, and the
// float64 or json.Number a JSON round-trip produces. A numeric string is
// NOT accepted — a handler that encodes an integer as a string (which the
// wire layer requires above 2^53) means it deliberately, and coercing it
// here would hide that.
func Int(d map[string]interface{}, key string) (int64, bool) {
	switch v := d[key].(type) {
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint8:
		return int64(v), true
	case uint16:
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint:
		if v <= 1<<63-1 {
			return int64(v), true
		}
	case uint64:
		if v <= 1<<63-1 {
			return int64(v), true
		}
	case float32:
		return int64(v), true
	case float64:
		return int64(v), true
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n, true
		}
	}
	return 0, false
}

// Count returns the number of elements at key for a slice or map value, in
// any of the concrete forms Data can carry it. The second result is false
// when the key is absent or holds neither.
func Count(d map[string]interface{}, key string) (int, bool) {
	switch v := d[key].(type) {
	case []interface{}:
		return len(v), true
	case []string:
		return len(v), true
	case map[string]interface{}:
		return len(v), true
	case map[string]string:
		return len(v), true
	}
	return 0, false
}

// Size returns a captured string's length as a human byte size, or the
// empty string when the key is absent or holds a non-string. Used by
// describers to say how much was captured without emitting any of it.
func Size(d map[string]interface{}, key string) string {
	s, ok := String(d, key)
	if !ok {
		return ""
	}
	return ByteSize(len(s))
}

// ByteSize renders n bytes as B, KiB, or MiB.
func ByteSize(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	}
}

// Value renders one captured value for display, redacting by field name and
// eliding by shape. It is the only rendering path a describer or the
// fallback should use for a value it did not itself constrain.
func Value(key string, v interface{}) string {
	if redact.IsSensitive(key) {
		return redact.Placeholder
	}
	return renderValue(v)
}

func renderValue(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return None
	case string:
		return Text(t)
	case bool:
		return strconv.FormatBool(t)
	case json.Number:
		return t.String()
	case float64:
		return renderFloat(t)
	case float32:
		return renderFloat(float64(t))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", t)
	case []interface{}:
		return fmt.Sprintf("<%d items>", len(t))
	case []string:
		return fmt.Sprintf("<%d items>", len(t))
	case map[string]interface{}:
		return fmt.Sprintf("<%d entries>", len(t))
	case map[string]string:
		return fmt.Sprintf("<%d entries>", len(t))
	default:
		// An unknown type is never formatted with %v: a nested struct or a
		// named string type could carry a captured file body, and the whole
		// point of this package is that such a body cannot reach a summary
		// by accident.
		return "<value>"
	}
}

func renderFloat(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// Text renders a captured string for display. A multi-line or long string
// is replaced by its size — this is what keeps file bodies out of summaries
// no matter which handler captured them under which key. Control characters
// are stripped so a captured line cannot corrupt a terminal or an HTML row.
func Text(s string) string {
	if s == "" {
		return Empty
	}
	if strings.ContainsAny(s, "\n\r") || utf8.RuneCountInString(s) > maxInline {
		return "<" + ByteSize(len(s)) + ">"
	}
	return sanitize(s)
}

// sanitize replaces control characters with a dot. Captured state comes off
// a remote host and lands in a UI row and a log line; escape sequences in
// that path are somebody else's vulnerability.
func sanitize(s string) string {
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return '.'
		}
		return r
	}, s)
}

func isControl(r rune) bool {
	return r != ' ' && (unicode.IsControl(r) || !unicode.IsPrint(r))
}

// Join assembles a summary from parts, dropping empties, and caps the
// result. Describers build their line through Join so a missing field
// collapses cleanly instead of leaving a dangling separator.
func Join(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			kept = append(kept, p)
		}
	}
	return Truncate(strings.Join(kept, ", "))
}

// Truncate caps s at the maximum summary length.
func Truncate(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= maxLine {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:maxLine])) + ellipsis
}

// Generic renders a pre-state whose mechanism has no describer: every field
// name, with values elided per [Value]. It is deliberately uninformative
// where a value cannot be shown safely — a mechanism whose describer is
// missing degrades to a safe line, never to a raw dump of what was
// captured.
func Generic(pre *api.PreState) string {
	if pre == nil {
		return ""
	}
	if len(pre.Data) == 0 {
		return prefix(pre.Mechanism, "no captured state")
	}
	keys := make([]string, 0, len(pre.Data))
	for k := range pre.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	shown := keys
	var omitted int
	if len(shown) > maxGenericFields {
		omitted = len(shown) - maxGenericFields
		shown = shown[:maxGenericFields]
	}
	parts := make([]string, 0, len(shown)+1)
	for _, k := range shown {
		parts = append(parts, k+"="+Value(k, pre.Data[k]))
	}
	if omitted > 0 {
		parts = append(parts, fmt.Sprintf("+%d more", omitted))
	}
	return prefix(pre.Mechanism, strings.Join(parts, ", "))
}

func prefix(mechanism, body string) string {
	if mechanism == "" {
		return Truncate(body)
	}
	return Truncate(mechanism + ": " + body)
}
