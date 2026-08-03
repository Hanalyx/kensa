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

// LineField is [Field] for a value that is a configuration line: it returns
// fallback when the key is absent or blank, and otherwise renders through
// [Line] rather than [Text], so credential-bearing values are redacted.
func LineField(d map[string]interface{}, key, fallback string) string {
	s, ok := String(d, key)
	if !ok || strings.TrimSpace(s) == "" {
		return fallback
	}
	return Line(s)
}

// Line renders a captured configuration line for display, redacting any value
// whose adjacent key names a credential.
//
// This exists because [Value] cannot help here and neither can the evidence
// sanitizer it delegates to. A captured line arrives under a Data key like
// `prior_line`, which is not itself sensitive; the credential is INSIDE the
// value, named by the config file's own key. Live example from a fleet host:
//
//	prior_line = "BindPassword secret-hunter2-abc"
//
// [redact.IsSensitive] does not catch that, and it is not meant to. Its doc is
// explicit: it matches a field name exactly or on a `_<name>` suffix but never
// on a prefix, so that a flag like `password_policy_required` survives, and it
// "deliberately does NOT touch ... free-text fields, where a name gives no
// signal". `BindPassword` matches none of its rules.
//
// So the matching here is deliberately WIDER than the evidence sanitizer's,
// because the trade-off is inverted. redact protects data that must survive
// verbatim for rollback to work, where a false positive destroys a restore. A
// display summary is thrown away after it is read, so a false positive costs
// one operator one glance at the raw capture, while a false negative puts a
// credential in a UI row and a persisted database column. Over-redacting is
// the cheap error; this errs that way on purpose.
//
// Both line shapes are handled: `Key Value` (config files) and `k=v` inside a
// comma-separated field (fstab mount options, where cifs carries
// `password=` and `credentials=`).
func Line(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return Empty
	}
	fields := strings.Fields(s)

	// `Key Value` — a config-file line whose first token names the setting.
	if len(fields) >= 2 && sensitiveToken(fields[0]) {
		return Text(fields[0] + " " + redact.Placeholder)
	}

	for i, f := range fields {
		if !strings.Contains(f, "=") {
			continue
		}
		// A field may hold several comma-separated k=v options (fstab).
		opts := strings.Split(f, ",")
		for j, opt := range opts {
			k, _, found := strings.Cut(opt, "=")
			if found && sensitiveToken(k) {
				opts[j] = k + "=" + redact.Placeholder
			}
		}
		fields[i] = strings.Join(opts, ",")
	}
	return Text(strings.Join(fields, " "))
}

// credentialWords name a credential when they appear as the FINAL component of
// a config key. Final-component matching extends [redact.IsSensitive]'s
// `_<name>` suffix rule to camelCase and to a few more words, and it is what
// keeps the widening safe:
//
//	BindPassword             -> Bind|Password        -> redacted
//	user_password            -> user|password        -> redacted
//	PASS_MAX_DAYS            -> PASS|MAX|DAYS        -> kept  (the headline case)
//	password_policy_required -> password|…|required  -> kept  (a policy flag)
//
// A bare substring test fails both of the last two: "pass" is inside
// PASS_MAX_DAYS, so the one line this whole feature exists to render would come
// back "<redacted>".
var credentialWords = map[string]struct{}{
	"password": {}, "passwd": {}, "secret": {}, "token": {},
	"credential": {}, "credentials": {}, "apikey": {}, "privkey": {},
	"jwt": {}, "passphrase": {},
}

// sensitiveToken reports whether a key from inside a captured line names a
// credential. See [Line] for why this is wider than the evidence sanitizer.
func sensitiveToken(k string) bool {
	k = strings.Trim(strings.TrimSpace(k), "\"'#")
	if k == "" {
		return false
	}
	if redact.IsSensitive(k) {
		return true
	}
	lower := strings.ToLower(k)
	// Short forms that are whole tokens rather than components: rootpw, bindpw.
	if strings.HasSuffix(lower, "pw") && len(lower) > 2 {
		return true
	}
	parts := splitComponents(k)
	if len(parts) == 0 {
		return false
	}
	_, ok := credentialWords[strings.ToLower(parts[len(parts)-1])]
	return ok
}

// splitComponents breaks a key into its words on delimiters and camelCase
// boundaries: "BindPassword" -> [Bind Password], "auth_token" -> [auth token].
func splitComponents(k string) []string {
	var out []string
	cur := strings.Builder{}
	runes := []rune(k)
	for i, r := range runes {
		if r == '_' || r == '-' || r == '.' || r == ' ' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		// camelCase boundary: lower/digit followed by upper.
		if i > 0 && unicode.IsUpper(r) && !unicode.IsUpper(runes[i-1]) && cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
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
	if !strings.ContainsFunc(s, needsSanitizing) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isHorizontalSpace(r) {
			// Horizontal whitespace becomes a SPACE, not the '.' used for
			// genuine control bytes. Mapping TAB to '.' corrupted the very
			// lines this package exists to render: /etc/login.defs is
			// tab-separated, so the feature's own headline example came out as
			// "PASS_MAX_DAYS.99999"; an fstab line as
			// "/swap.img.none.swap.sw.0.0"; and net.ipv4.tcp_rmem as
			// "4096.131072.33554432", which reads as a dotted quad. A tab is
			// not a corrupted byte, it is a field separator, and the operator
			// needs to see it as one.
			return ' '
		}
		if isControl(r) {
			return '.'
		}
		return r
	}, s)
}

// isHorizontalSpace reports whether r is whitespace that separates fields on a
// single line. Vertical whitespace is deliberately excluded: a value
// containing it is multi-line and [Text] elides it before sanitizing ever runs.
func isHorizontalSpace(r rune) bool {
	return r == '\t' || r == '\v' || r == '\f'
}

// needsSanitizing reports whether s contains anything sanitize would rewrite.
func needsSanitizing(r rune) bool {
	return isHorizontalSpace(r) || isControl(r)
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
		// The KEY is sanitized too, not only the value. Data keys come off a
		// foreign, corrupted or older-Kensa pre-state -- exactly the input the
		// package doc promises to tolerate -- so a key carrying an escape
		// sequence or a newline would break the one-line invariant that the
		// consumer's phase list depends on, and land an ESC in a UI row.
		parts = append(parts, sanitize(k)+"="+Value(k, pre.Data[k]))
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
	// Mechanism is sanitized for the same reason as the Data keys: it arrives
	// from the stored pre-state rather than from the registry, so a corrupted
	// or hostile record can put control bytes in it.
	return Truncate(sanitize(mechanism) + ": " + body)
}
