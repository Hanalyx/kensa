// Package valueguard hardens rule/variable values before they reach a
// root-run write. Rule YAML and every --var tier are root-trusted input
// (docs/test_docs/security.md limit #3), so a dangerous value must become a
// clean validation error at the handler boundary rather than config corruption
// or content injection on the target host (limit #13).
//
// Two guards, matching the two mechanisms:
//   - NoControlChars: a value destined for a single config-file line must not
//     contain control characters — a newline injects extra lines (extra
//     keys/directives) into the persisted file (#13b).
//   - GrubParamValue: a kernel-parameter value is spliced into the root-run
//     bootloader edit (grub sed / grubby), so it is restricted to a
//     conservative charset that cannot corrupt that edit (#13a).
package valueguard

import (
	"fmt"
	"sort"
)

// NoControlCharsIn applies NoControlChars to each named field (label → value)
// and returns the first violation, checked in a deterministic (sorted-label)
// order so the error is stable. Lets a handler harden all of its
// config-line-bound params in one call.
func NoControlCharsIn(fields map[string]string) error {
	labels := make([]string, 0, len(fields))
	for l := range fields {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		if err := NoControlChars(l, fields[l]); err != nil {
			return err
		}
	}
	return nil
}

// NoControlChars rejects value if it contains any control character (newline,
// carriage return, NUL, ...). Iterates bytes, not runes: a control character is
// a single byte, and this is precisely the injection surface. field names the
// parameter for the error message. Legitimate config values (numbers, on/off,
// paths, package names) never contain control characters; multi-line content
// (e.g. an audit-rule body) is NOT passed through this guard.
func NoControlChars(field, value string) error {
	for i := 0; i < len(value); i++ {
		if b := value[i]; b < 0x20 || b == 0x7f {
			return fmt.Errorf("%s: value contains a control character (0x%02x at byte %d); a newline or control character would inject extra lines into the config file this rule writes", field, b, i)
		}
	}
	return nil
}

// grubValueAllowed reports whether b is allowed in a kernel-parameter VALUE.
// Real values are numbers, on/off/none-style tokens, device paths, and console
// specs — all within [A-Za-z0-9._,:=/+-]. Spaces, quotes, and sed/shell
// specials (| & \ etc.) are excluded so the value cannot corrupt the root-run
// grub edit.
func grubValueAllowed(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '.', ',', ':', '=', '/', '+', '-', '_':
		return true
	}
	return false
}

// GrubParamValue restricts a kernel-parameter value to the conservative charset
// grubValueAllowed defines, so a regex/sed-special or newline value is rejected
// with a clean error instead of corrupting the root-run bootloader edit (#13a).
func GrubParamValue(value string) error {
	for i := 0; i < len(value); i++ {
		if !grubValueAllowed(value[i]) {
			return fmt.Errorf("grub_parameter_set: value %q contains disallowed character %q at byte %d; kernel-parameter values are restricted to [A-Za-z0-9._,:=/+-] so they cannot corrupt the root-run bootloader edit", value, string(value[i]), i)
		}
	}
	return nil
}
