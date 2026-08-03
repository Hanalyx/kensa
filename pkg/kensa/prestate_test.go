package kensa

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/handler"
)

// fileBody is the shape a summary must never contain: multi-line captured
// content. Every line of it is searched for in the poisoning test, so a
// describer that renders any captured string verbatim fails.
const fileBody = "root:x:0:0:root:/root:/bin/bash\n" +
	"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
	"sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin\n"

// capture is one mechanism's realistic pre-state plus what its summary must
// and must not say. The Data maps mirror what each handler's Capture
// actually records, so this table is also the readable inventory of those
// layouts — and, via TestEveryCapturableHandlerDescribesPreState, a new
// capturable mechanism cannot ship without an entry here.
type capture struct {
	// name distinguishes two entries for one mechanism (file_permissions
	// captures two different shapes).
	name string
	data map[string]interface{}
	// want are substrings the rendered line must contain.
	want []string
	// deny are substrings it must not.
	deny []string
}

var captures = map[string][]capture{
	"apt_absent": {{
		data: map[string]interface{}{"name": "telnet", "pkg_installed": true, "prior_version": "0.17-44"},
		want: []string{"telnet installed", "0.17-44"},
	}},
	"apt_present": {{
		data: map[string]interface{}{"name": "auditd", "pkg_installed": false, "prior_version": ""},
		want: []string{"auditd not installed"},
	}},
	"package_absent": {{
		data: map[string]interface{}{"name": "rsh-server", "pkg_installed": true, "prior_version": "0.17-89"},
		want: []string{"rsh-server installed", "0.17-89"},
	}},
	"package_present": {{
		data: map[string]interface{}{"name": "aide", "pkg_installed": false, "prior_version": ""},
		want: []string{"aide not installed"},
	}},
	"audit_rule_set": {{
		name: "immutable host with a pending line",
		data: map[string]interface{}{
			"path":             "/etc/audit/rules.d/99-kensa.rules",
			"file_existed":     true,
			"prior_content":    "-w /etc/passwd -p wa -k identity\n",
			"file_added_lines": []interface{}{"-w /etc/group -p wa -k identity"},
			"immutable_staged": true,
		},
		want: []string{"/etc/audit/rules.d/99-kensa.rules present", "1 rule line(s) not yet in the file", "immutable", "staged for reboot"},
		deny: []string{"/etc/passwd -p wa"},
	}},
	"authselect_feature_enable": {{
		data: map[string]interface{}{"feature": "with-faillock", "prior_output": "sssd\nwith-mkhomedir\n"},
		want: []string{"feature with-faillock", "authselect profile captured"},
		deny: []string{"with-mkhomedir"},
	}},
	"config_append": {{
		data: map[string]interface{}{
			"path": "/etc/issue", "line": "Authorized use only", "was_present": false,
			"prior_content": "old banner\n", "file_existed": true,
		},
		want: []string{"/etc/issue", "line not present"},
	}},
	"config_set": {{
		name: "the line an operator asked for",
		data: map[string]interface{}{
			"file": "/etc/login.defs", "key": "PASS_MAX_DAYS", "separator": " ",
			"line_existed": true, "prior_line": "PASS_MAX_DAYS 99999",
		},
		want: []string{"PASS_MAX_DAYS 99999", "in /etc/login.defs"},
	}, {
		name: "key not set",
		data: map[string]interface{}{
			"file": "/etc/login.defs", "key": "PASS_MIN_DAYS", "separator": " ",
			"line_existed": false, "prior_line": "",
		},
		want: []string{"PASS_MIN_DAYS not set", "in /etc/login.defs"},
	}},
	"config_set_dropin": {{
		data: map[string]interface{}{
			"path": "/etc/security/pwquality.conf.d/50-kensa.conf", "file_existed": false,
			"prior_content": "", "created_dirs": "/etc/security/pwquality.conf.d\n",
		},
		want: []string{"/etc/security/pwquality.conf.d/50-kensa.conf absent", "1 parent dir(s) to create"},
	}},
	"cron_job": {{
		data: map[string]interface{}{
			"path": "/etc/cron.daily/aide", "file_existed": true, "prior_content": "#!/bin/sh\naide --check\n",
		},
		want: []string{"/etc/cron.daily/aide present"},
		deny: []string{"aide --check"},
	}},
	"crypto_policy_set": {{
		data: map[string]interface{}{"prior_policy": "DEFAULT"},
		want: []string{"crypto policy DEFAULT"},
	}},
	"dconf_set": {{
		data: map[string]interface{}{
			"file_path": "/etc/dconf/db/local.d/00-screensaver", "prior_content": "", "file_existed": false,
			"lock_path": "/etc/dconf/db/local.d/locks/00-screensaver", "lock_content": "", "lock_existed": false,
			"profile_path": "/etc/dconf/profile/user", "profile_existed": true,
			"db_dir": "/etc/dconf/db/local.d", "created_dirs": "",
		},
		want: []string{"/etc/dconf/db/local.d/00-screensaver absent", "lock absent", "profile present"},
	}},
	"file_absent": {{
		data: map[string]interface{}{
			"path": "/etc/rsh.conf", "file_existed": true, "content": fileBody,
			"mode": "0644", "owner": "root", "group": "root", "selinux": "",
		},
		want: []string{"/etc/rsh.conf present", "0644 root:root"},
	}},
	"file_content": {{
		data: map[string]interface{}{
			"path": "/etc/ssh/sshd_config.d/50-kensa.conf", "file_existed": false, "content": "",
			"mode": "", "owner": "", "group": "", "selinux": "",
		},
		want: []string{"/etc/ssh/sshd_config.d/50-kensa.conf absent"},
	}},
	"file_permissions": {{
		name: "single target",
		data: map[string]interface{}{
			"path": "/etc/shadow", "owner": "root", "uid": "0", "group": "root",
			"gid": "0", "mode": "0000", "selinux_context": "?",
		},
		want: []string{"/etc/shadow", "0000 root:root"},
	}, {
		name: "find-based selection",
		data: map[string]interface{}{
			"find_based": true,
			"files": []interface{}{
				map[string]interface{}{"path": "/etc/a", "mode": "0644", "owner": "root", "uid": "0", "group": "root", "gid": "0"},
				map[string]interface{}{"path": "/etc/b", "mode": "0600", "owner": "root", "uid": "0", "group": "root", "gid": "0"},
			},
		},
		want: []string{"2 file(s) matched"},
		deny: []string{"/etc/a"},
	}},
	"kernel_module_disable": {{
		data: map[string]interface{}{
			"module": "usb-storage", "path": "/etc/modprobe.d/usb-storage.conf",
			"file_existed": false, "prior_content": "", "was_loaded": true,
		},
		want: []string{"usb-storage loaded", "/etc/modprobe.d/usb-storage.conf absent"},
	}},
	"mount_option_set": {{
		data: map[string]interface{}{
			"mount_point": "/tmp", "option": "nosuid",
			"prior_line": "tmpfs /tmp tmpfs defaults 0 0",
		},
		want: []string{"/tmp", "tmpfs /tmp tmpfs defaults 0 0"},
	}},
	"pam_module_arg": {{
		data: map[string]interface{}{
			"module": "pam_faillock.so",
			"files_content": map[string]interface{}{
				"/etc/pam.d/system-auth":   fileBody,
				"/etc/pam.d/password-auth": fileBody,
			},
			"files_existed": map[string]interface{}{
				"/etc/pam.d/system-auth":   true,
				"/etc/pam.d/password-auth": true,
			},
		},
		want: []string{"pam_faillock.so", "2 PAM file(s)", "2 present"},
	}},
	"pam_module_configure": {{
		data: map[string]interface{}{
			"service": "sshd", "path": "/etc/pam.d/sshd", "prior_content": fileBody,
		},
		want: []string{"sshd stack /etc/pam.d/sshd"},
	}},
	"selinux_boolean_set": {{
		data: map[string]interface{}{"boolean": "httpd_can_network_connect", "prior_value": "off"},
		want: []string{"httpd_can_network_connect off"},
	}},
	"service_disabled": {{
		data: map[string]interface{}{"name": "rsyncd", "prior_enabled": "enabled", "prior_active": "active"},
		want: []string{"rsyncd", "enabled", "active"},
	}},
	"service_enabled": {{
		data: map[string]interface{}{"name": "auditd", "prior_enabled": "disabled", "prior_active": "inactive"},
		want: []string{"auditd", "disabled", "inactive"},
	}},
	"service_masked": {{
		data: map[string]interface{}{"name": "ctrl-alt-del.target", "prior_enabled": "", "prior_active": "inactive"},
		want: []string{"ctrl-alt-del.target", "unit file state unknown", "inactive"},
	}},
	"sysctl_set": {{
		data: map[string]interface{}{
			"key": "net.ipv4.ip_forward", "persist_file": "/etc/sysctl.d/60-kensa.conf",
			"runtime_value": "1", "persist_file_content": "", "persist_file_existed": false,
		},
		want: []string{"net.ipv4.ip_forward = 1", "/etc/sysctl.d/60-kensa.conf absent"},
	}},
}

// TestPreStateFieldsUnchanged guards the reason this projection derives a
// summary on read instead of storing one on api.PreState.
//
// PreState sits inside EvidenceEnvelope.PreStateBundle, and the evidence
// signer canonicalizes by marshaling the struct to JSON. The api.PreState type
// carries no json tags, so a new exported field appears in the canonical
// bytes under its Go name — changing the bytes for every envelope
// re-canonicalized at verification time, including envelopes signed before
// the field existed. Their signatures would stop verifying, and a
// cross-language verifier would have to add the field in lockstep or reject
// authentic evidence.
//
// If this test fails, the field being added is not free: it needs the
// signature-compatibility question answered first.
//
// @spec pkg-prestate-describe
// @ac AC-09
func TestPreStateFieldsUnchanged(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-09")

	want := []string{"StepIndex", "Mechanism", "Capturable", "Data", "CapturedAt"}
	typ := reflect.TypeOf(api.PreState{})

	var got []string
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("api.PreState fields changed\n  got:  %v\n  want: %v\n"+
			"a field added here alters the evidence signer's canonical bytes and "+
			"invalidates signatures over already written envelopes", got, want)
	}
}

// capturableMechanisms lists every registered mechanism that reports
// Capturable. Registration comes from importing pkg/kensa alone, which is
// how an external consumer gets it.
func capturableMechanisms(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, name := range handler.Default().Names() {
		h, ok := handler.Default().Get(name)
		if !ok {
			t.Fatalf("registry reported %q but cannot resolve it", name)
		}
		if h.Capturable() {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		t.Fatal("no capturable handlers registered — the pkg/kensa handler bundle is not linked")
	}
	return out
}

// TestEveryCapturableHandlerDescribesPreState is the drift guard. A new
// capturable mechanism that ships without a describer would silently render
// as the generic fallback in every consumer's UI — visible to nobody
// reviewing the handler. It must also carry a fixture below, so its summary
// is reviewed rather than merely present.
//
// @spec pkg-prestate-describe
// @ac AC-01
func TestEveryCapturableHandlerDescribesPreState(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-01")

	for _, mech := range capturableMechanisms(t) {
		h, _ := handler.Default().Get(mech)
		if _, ok := h.(handler.PreStateDescriber); !ok {
			t.Errorf("capturable mechanism %q does not implement handler.PreStateDescriber: "+
				"its captured pre-state would render as the generic fallback for every consumer", mech)
		}
		if _, ok := captures[mech]; !ok {
			t.Errorf("capturable mechanism %q has no fixture in prestate_test.go: "+
				"add one so its summary is reviewed and its totality covered", mech)
		}
	}
}

// TestDescribePreStatePerMechanism locks the operator-facing line each
// mechanism produces from realistic capture data.
//
// @spec pkg-prestate-describe
// @ac AC-07
func TestDescribePreStatePerMechanism(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-07")

	for mech, cases := range captures {
		for _, tc := range cases {
			name := mech
			if tc.name != "" {
				name = mech + "/" + tc.name
			}
			t.Run(name, func(t *testing.T) {
				got := DescribePreState(api.PreState{
					Mechanism: mech, Capturable: true, Data: tc.data,
				})
				if got == "" {
					t.Fatal("rendered an empty summary")
				}
				if strings.HasPrefix(got, mech+": ") {
					t.Fatalf("fell back to the generic rendering: %q", got)
				}
				for _, want := range tc.want {
					if !strings.Contains(got, want) {
						t.Errorf("summary %q does not contain %q", got, want)
					}
				}
				for _, deny := range tc.deny {
					if strings.Contains(got, deny) {
						t.Errorf("summary %q leaked %q", got, deny)
					}
				}
			})
		}
	}
}

// TestDescribePreStateNeverEmitsFileBodies is the disclosure guarantee,
// enforced per mechanism rather than trusted per handler: every string
// value in a realistic capture is replaced with a multi-line file body, and
// no line of it may appear in the rendered summary. This is what makes the
// promise "no describer and no fallback emits a captured file body" a test
// rather than a claim.
//
// @spec pkg-prestate-describe
// @ac AC-02
func TestDescribePreStateNeverEmitsFileBodies(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-02")

	for mech, cases := range captures {
		t.Run(mech, func(t *testing.T) {
			for _, tc := range cases {
				poisoned := make(map[string]interface{}, len(tc.data))
				for k, v := range tc.data {
					if _, isString := v.(string); isString {
						poisoned[k] = fileBody
						continue
					}
					poisoned[k] = v
				}
				got := DescribePreState(api.PreState{
					Mechanism: mech, Capturable: true, Data: poisoned,
				})
				for _, line := range strings.Split(strings.TrimSpace(fileBody), "\n") {
					if strings.Contains(got, line) {
						t.Errorf("summary leaked a captured file body line\n  line:    %q\n  summary: %q", line, got)
					}
				}
			}
		})
	}
}

// TestDescribePreStateIsTotal feeds every capturable mechanism the shapes
// historical and round-tripped Data actually produces: absent keys, wrong
// types, and the int64/float64 widening the agent wire and a JSON round-trip
// introduce. The describer is called DIRECTLY rather than through
// DescribePreState, so the registry's panic recovery cannot mask a defect
// the test exists to find.
//
// @spec pkg-prestate-describe
// @ac AC-03
func TestDescribePreStateIsTotal(t *testing.T) {
	t.Log("// @spec pkg-prestate-describe")
	t.Log("// @ac AC-03")

	hostile := []struct {
		name string
		data map[string]interface{}
	}{
		{"nil data", nil},
		{"empty data", map[string]interface{}{}},
		{"unrelated keys", map[string]interface{}{"unexpected": "value"}},
	}

	for _, mech := range capturableMechanisms(t) {
		h, _ := handler.Default().Get(mech)
		d, ok := h.(handler.PreStateDescriber)
		if !ok {
			continue // reported by TestEveryCapturableHandlerDescribesPreState
		}

		cases := hostile
		// Re-type every field of the realistic capture: the same keys the
		// handler reads, holding what it does not expect.
		for _, tc := range captures[mech] {
			for _, wrong := range []interface{}{nil, float64(12.5), int64(7), []interface{}{1}, map[string]interface{}{"a": 1}} {
				retyped := make(map[string]interface{}, len(tc.data))
				for k := range tc.data {
					retyped[k] = wrong
				}
				cases = append(cases, struct {
					name string
					data map[string]interface{}
				}{"retyped fields", retyped})
			}
		}

		for _, tc := range cases {
			t.Run(mech+"/"+tc.name, func(t *testing.T) {
				pre := &api.PreState{Mechanism: mech, Capturable: true, Data: tc.data}
				// A panic here fails the test rather than degrading, which
				// is the point: totality is the describer's obligation.
				summary := d.DescribePreState(pre)
				if strings.TrimSpace(summary) == "" {
					t.Errorf("describer returned an empty line; it would degrade to the generic fallback")
				}
				if got := DescribePreState(*pre); got == "" {
					t.Errorf("DescribePreState returned an empty line for a capturable step")
				}
			})
		}
	}
}
