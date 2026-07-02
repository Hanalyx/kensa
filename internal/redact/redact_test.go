package redact

import (
	"reflect"
	"testing"
)

// TestValue_NameMatching covers exact, suffix, and prefix-collision
// name matching plus case-insensitivity.
//
// @spec store-redaction
// @ac AC-01
// @ac AC-02
func TestValue_NameMatching(t *testing.T) {
	t.Run("store-redaction/AC-01", func(t *testing.T) {
		cases := []struct {
			field   string
			want    bool // true = redacted
			comment string
		}{
			{"password", true, "exact"},
			{"token", true, "exact"},
			{"ssh_key", true, "exact"},
			{"auth_token", true, "exact"},
			{"user_password", true, "_suffix"},
			{"db_token", true, "_suffix"},
			{"password_policy_required", false, "prefix collision must NOT redact"},
			{"tokenizer", false, "substring must NOT redact"},
			{"mode", false, "unrelated"},
			{"owner", false, "unrelated"},
		}
		for _, c := range cases {
			got := Value(c.field, "sekret")
			redacted := got == Placeholder
			if redacted != c.want {
				t.Errorf("Value(%q): redacted=%v, want %v (%s)", c.field, redacted, c.want, c.comment)
			}
			if !c.want && got != "sekret" {
				t.Errorf("Value(%q): non-sensitive value altered to %v", c.field, got)
			}
		}
	})

	t.Run("store-redaction/AC-02", func(t *testing.T) {
		for _, f := range []string{"PassWord", "API_KEY", "Secret", "Ssh_Key", "AUTH_TOKEN"} {
			if Value(f, "x") != Placeholder {
				t.Errorf("Value(%q) not redacted; matching must be case-insensitive", f)
			}
		}
	})
}

// TestTree_NestedRedaction covers recursion into sub-maps and into maps
// inside slices.
//
// @spec store-redaction
// @ac AC-03
func TestTree_NestedRedaction(t *testing.T) {
	t.Log("// @spec store-redaction")
	t.Log("// @ac AC-03")

	in := map[string]any{
		"path": "/etc/app.conf",
		"creds": map[string]any{
			"api_key":  "AKIA-real", // pragma: allowlist secret
			"endpoint": "https://x",
		},
		"users": []any{
			map[string]any{"name": "svc", "password": "hunter2"}, // pragma: allowlist secret
			map[string]any{"name": "ops", "role": "admin"},
		},
		"password_policy_required": true,
	}
	Tree(in)

	creds := in["creds"].(map[string]any)
	if creds["api_key"] != Placeholder { // pragma: allowlist secret
		t.Errorf("nested api_key not redacted: %v", creds["api_key"])
	}
	if creds["endpoint"] != "https://x" {
		t.Errorf("non-sensitive endpoint altered: %v", creds["endpoint"])
	}
	u0 := in["users"].([]any)[0].(map[string]any)
	if u0["password"] != Placeholder { // pragma: allowlist secret
		t.Errorf("password in slice map not redacted: %v", u0["password"])
	}
	if u0["name"] != "svc" {
		t.Errorf("non-sensitive name altered: %v", u0["name"])
	}
	if in["password_policy_required"] != true { // pragma: allowlist secret
		t.Errorf("prefix-collision flag wrongly redacted: %v", in["password_policy_required"])
	}
	if in["path"] != "/etc/app.conf" {
		t.Errorf("non-sensitive path altered: %v", in["path"])
	}
}

// TestTree_NilSafe confirms a nil map is handled.
//
// @spec store-redaction
// @ac AC-03
func TestTree_NilSafe(t *testing.T) {
	t.Log("// @spec store-redaction")
	t.Log("// @ac AC-03")
	var m map[string]any
	if got := Tree(m); !reflect.DeepEqual(got, m) {
		t.Errorf("Tree(nil) = %v, want nil", got)
	}
}
