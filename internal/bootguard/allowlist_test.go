package bootguard_test

import (
	"testing"

	"github.com/Hanalyx/kensa/internal/bootguard"
)

// @spec bootguard-allowlist
// @ac AC-01
func TestCheckParamArmable_AllowsCorpusParamsRefusesOthers(t *testing.T) {
	t.Run("bootguard-allowlist/AC-01", func(t *testing.T) {})
	for _, k := range []string{
		"audit", "audit_backlog_limit", "init_on_alloc", "page_poison",
		"pti", "slub_debug", "vsyscall", "systemd.confirm_spawn",
	} {
		if err := bootguard.CheckParamArmable(k); err != nil {
			t.Errorf("CheckParamArmable(%q) = %v; want nil (corpus param)", k, err)
		}
	}
	for _, k := range []string{"root", "init", "console", "foobar", "rd.break"} {
		err := bootguard.CheckParamArmable(k)
		if err == nil {
			t.Errorf("CheckParamArmable(%q) = nil; want refusal (not on allowlist)", k)
			continue
		}
		if got := err.Error(); !containsAll(got, k, "allowlist") {
			t.Errorf("refusal for %q should name the key and the allowlist; got %q", k, got)
		}
	}
}

// @spec bootguard-allowlist
// @ac AC-02
func TestCheckParamArmable_RefusesEmpty(t *testing.T) {
	t.Run("bootguard-allowlist/AC-02", func(t *testing.T) {})
	for _, k := range []string{"", "   "} {
		if err := bootguard.CheckParamArmable(k); err == nil {
			t.Errorf("CheckParamArmable(%q) = nil; want error for empty key", k)
		}
	}
}

// @spec bootguard-allowlist
// @ac AC-03
func TestAllowedParams_CoversCorpusExcludesDangerous(t *testing.T) {
	t.Run("bootguard-allowlist/AC-03", func(t *testing.T) {})
	want := []string{
		"audit", "audit_backlog_limit", "init_on_alloc", "page_poison",
		"pti", "slub_debug", "vsyscall", "systemd.confirm_spawn",
	}
	for _, k := range want {
		if !bootguard.ParamAllowed(k) {
			t.Errorf("allowlist missing corpus key %q", k)
		}
	}
	for _, k := range []string{"root", "init"} {
		if bootguard.ParamAllowed(k) {
			t.Errorf("allowlist must NOT contain boot-device/init key %q", k)
		}
	}
	if len(bootguard.AllowedParams()) != len(want) {
		t.Errorf("AllowedParams() size = %d; want %d (the curated corpus set)", len(bootguard.AllowedParams()), len(want))
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
