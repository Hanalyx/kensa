// Tests for the embedded built-in defaults tier.
package varsub

import (
	"testing"
)

func TestBuiltInDefaults_Parses(t *testing.T) {
	got, err := BuiltInDefaults()
	if err != nil {
		t.Fatalf("embedded defaults must parse cleanly: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("embedded defaults must produce a non-empty Variables map")
	}
}

// TestBuiltInDefaults_CoversCorpusVars locks the contract that
// the embedded defaults define every variable referenced by
// `{{ var }}` templates in the production rule corpus. If a new
// templated rule lands without a matching default, this test
// must be updated deliberately.
func TestBuiltInDefaults_CoversCorpusVars(t *testing.T) {
	got, err := BuiltInDefaults()
	if err != nil {
		t.Fatal(err)
	}
	// The list mirrors the templated-rule survey at the time of
	// the embedded-defaults deliverable. Drift means either a
	// new rule introduced a var that needs a default, OR a rule
	// stopped using a var. Both are deliberate decisions; either
	// way, update this list.
	expected := []string{
		"pam_pwquality_minlen",
		"pam_pwquality_minclass",
		"pam_pwquality_difok",
		"pam_pwquality_maxrepeat",
		"pam_pwquality_maxclassrepeat",
		"pam_pwquality_dcredit",
		"pam_pwquality_ucredit",
		"pam_pwquality_lcredit",
		"pam_pwquality_ocredit",
		"pam_faillock_deny",
		"pam_faillock_fail_interval",
		"pam_faillock_unlock_time",
		"login_defs_pass_max_days",
		"login_defs_pass_min_days",
		"login_defs_pass_warn_age",
		"login_defs_umask",
		"shadow_crypt_min_rounds",
		"password_remember",
		"banner_text",
		"rsyslog_remote_server",
		"chrony_ntp_pool",
		"ssh_client_alive_interval",
		"ssh_client_alive_count_max",
		"ssh_max_auth_tries",
		"ssh_max_sessions",
		"ssh_login_grace_time",
		"ssh_approved_ciphers",
		"ssh_approved_kex",
		"ssh_approved_macs",
	}
	for _, key := range expected {
		if _, ok := got[key]; !ok {
			t.Errorf("embedded defaults missing %q (used by templated rules)", key)
		}
	}
}

func TestBuiltInDefaults_Cached(t *testing.T) {
	// Two consecutive calls must return the same map (cache hit).
	a, err := BuiltInDefaults()
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuiltInDefaults()
	if err != nil {
		t.Fatal(err)
	}
	// Sanity check: BuiltInDefaults must never return a nil map
	// (an empty map is acceptable; nil would break range loops
	// in callers).
	if a == nil || b == nil {
		t.Fatal("nil map")
	}
	// Sanity: both have the same content.
	for k, v := range a {
		if b[k] != v {
			t.Errorf("cache divergence at key %q: %q vs %q", k, v, b[k])
		}
	}
}

func TestResolveTiers_EmbeddedAsFloor(t *testing.T) {
	// With no configDir and no CLI overrides, the embedded
	// defaults flow through ResolveTiers as the only source.
	got, err := ResolveTiers("", "", nil, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got["pam_faillock_deny"] != "3" {
		t.Errorf("embedded pam_faillock_deny=3 should appear; got %q", got["pam_faillock_deny"])
	}
}

func TestResolveTiers_OperatorOverridesEmbedded(t *testing.T) {
	// CLI override beats embedded.
	got, err := ResolveTiers("", "", nil, Variables{"pam_faillock_deny": "99"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got["pam_faillock_deny"] != "99" {
		t.Errorf("CLI should win over embedded; got %q", got["pam_faillock_deny"])
	}
	// Untouched embedded keys still present.
	if got["ssh_client_alive_interval"] != "900" {
		t.Errorf("embedded ssh_client_alive_interval=900 should pass through; got %q", got["ssh_client_alive_interval"])
	}
}
