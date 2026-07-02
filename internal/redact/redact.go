// Package redact scrubs credential values out of data that leaves the
// engine as durable evidence — the signed evidence envelope and the
// transaction log's envelope record. A value is redacted when the FIELD
// NAME that holds it denotes a credential (password, token, ssh_key,
// …), not by inspecting the value itself.
//
// Scope and safety: this is a name-based audit sanitizer, not a secret
// scanner. It protects structured state whose keys signal sensitivity
// (a captured config map with a "password" key, an envelope sub-object
// named "api_key"). It deliberately does NOT touch operational pre-state
// used for rollback — that data must survive verbatim so restoration
// works — nor free-text fields, where a name gives no signal.
//
// The package lives on its own (not under store or evidence) so both the
// signer and the store can call it without an import cycle or a
// backwards evidence→store dependency.
package redact

import "strings"

// Placeholder is the string substituted for a redacted value.
const Placeholder = "<redacted>"

// sensitiveNames are field names whose value is a credential. Matching
// is case-insensitive and also fires on a `_<name>` suffix (so
// `user_password` and `db_token` redact) but NOT on a prefix, so a
// config flag like `password_policy_required` is left alone.
var sensitiveNames = map[string]struct{}{
	"password":    {},
	"passwd":      {},
	"pass":        {},
	"ssh_key":     {},
	"ssh_private": {},
	"api_key":     {},
	"apikey":      {},
	"token":       {},
	"secret":      {},
	"license_jwt": {},
	"jwt":         {},
	"auth_token":  {},
}

// IsSensitive reports whether a field name denotes a credential value.
func IsSensitive(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if _, ok := sensitiveNames[n]; ok {
		return true
	}
	for s := range sensitiveNames {
		if strings.HasSuffix(n, "_"+s) {
			return true
		}
	}
	return false
}

// Value returns Placeholder when field is sensitive, otherwise the value
// unchanged.
func Value(field string, value any) any {
	if IsSensitive(field) {
		return Placeholder
	}
	return value
}

// Tree walks m in place, replacing every value stored under a sensitive
// key with Placeholder, recursing into nested maps and into maps inside
// slices. It returns m for call-site convenience. A nil map is returned
// unchanged.
func Tree(m map[string]any) map[string]any {
	for k, v := range m {
		if IsSensitive(k) {
			m[k] = Placeholder
			continue
		}
		switch child := v.(type) {
		case map[string]any:
			Tree(child)
		case []any:
			for _, e := range child {
				if em, ok := e.(map[string]any); ok {
					Tree(em)
				}
			}
		}
	}
	return m
}
