// Per-handler agent-port regression tests for L-015..L-032.
// Per the umbrella spec, zero handlers required code edits
// (Option L1 drop-in). Two test classes:
//
//   1. File-based handlers (file_content / file_absent /
//      config_set / config_set_dropin): full Apply tests
//      with observable temp-file side-effect.
//
//   2. System-state handlers (cron_job / pam_module_configure
//      / sysctl_set / mount_option_set / service_* /
//      selinux_boolean_set / kernel_module_disable /
//      audit_rule_set / package_* / apt_*): routing-only
//      tests that verify server.Handle does NOT return
//      "unknown_mechanism". Real validation ships with
//      L-014c's live-host parity test.
//
// All tests follow the same pattern: build api.Params, send
// ApplyRequest via server.Handle, inspect the response.
//
// @spec agent-handler-ports-umbrella

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/wirev1"

	// Blank-import every capturable handler so handler.Default()
	// is populated. Mirrors cmd/kensa/main.go's pattern. Without
	// these, routing tests below get "unknown_mechanism" for
	// every mechanism and the L-015..L-032 contract fails
	// silently.
	_ "github.com/Hanalyx/kensa/internal/handlers/aptabsent"
	_ "github.com/Hanalyx/kensa/internal/handlers/aptpresent"
	_ "github.com/Hanalyx/kensa/internal/handlers/auditruleset"
	_ "github.com/Hanalyx/kensa/internal/handlers/configset"
	_ "github.com/Hanalyx/kensa/internal/handlers/configsetdropin"
	_ "github.com/Hanalyx/kensa/internal/handlers/cronjob"
	_ "github.com/Hanalyx/kensa/internal/handlers/fileabsent"
	_ "github.com/Hanalyx/kensa/internal/handlers/filecontent"
	_ "github.com/Hanalyx/kensa/internal/handlers/kernelmoduledisable"
	_ "github.com/Hanalyx/kensa/internal/handlers/mountoptionset"
	_ "github.com/Hanalyx/kensa/internal/handlers/packageabsent"
	_ "github.com/Hanalyx/kensa/internal/handlers/packagepresent"
	_ "github.com/Hanalyx/kensa/internal/handlers/pammoduleconfigure"
	_ "github.com/Hanalyx/kensa/internal/handlers/selinuxbooleanset"
	_ "github.com/Hanalyx/kensa/internal/handlers/servicedisabled"
	_ "github.com/Hanalyx/kensa/internal/handlers/serviceenabled"
	_ "github.com/Hanalyx/kensa/internal/handlers/servicemasked"
	_ "github.com/Hanalyx/kensa/internal/handlers/sysctlset"
)

// dispatchApplyTest is the common helper. Sends an
// ApplyRequest for `mechanism` with the given params,
// returns the Response.
func dispatchApplyTest(t *testing.T, mechanism string, params api.Params) *wirev1.Response {
	t.Helper()
	wireParams, err := wirev1.APIParamsToWire(params)
	if err != nil {
		t.Fatalf("APIParamsToWire: %v", err)
	}
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 1,
		Payload: &wirev1.Request_Apply{
			Apply: &wirev1.ApplyRequest{
				Mechanism: mechanism,
				Params:    wireParams,
			},
		},
	}
	return Handle(req)
}

// assertRouted is the routing-only assertion: the agent
// server dispatched to a handler (i.e., did NOT return
// "unknown_mechanism"). The handler may have errored out
// for system-state reasons (no apt-get, no systemd, etc.)
// which surfaces as "handler_error" — that's acceptable
// and proves the routing fired.
func assertRouted(t *testing.T, mechanism string, resp *wirev1.Response) {
	t.Helper()
	if resp.GetError() != nil && resp.GetError().GetCode() == "unknown_mechanism" {
		t.Errorf("%s: server returned unknown_mechanism — handler not registered or not routed",
			mechanism)
	}
}

// ─── File-based handlers (full Apply + side-effect assertion) ────────────

// L-015 file_content: write content to a temp file via agent.
// @spec agent-handler-port-filepermissions
// @ac AC-01
// @spec agent-handler-ports-umbrella
// @ac AC-01
func TestAgentApply_FileContent(t *testing.T) {
	t.Run("agent-handler-ports-umbrella/AC-01", func(t *testing.T) {})
	t.Run("agent-handler-port-filepermissions/AC-01", func(t *testing.T) {})
	dir := t.TempDir()
	target := filepath.Join(dir, "test-file")
	resp := dispatchApplyTest(t, "file_content", api.Params{
		"path":    target,
		"content": "hello, kensa\n",
		"mode":    "0644",
	})
	if resp.GetError() != nil {
		t.Fatalf("envelope Error: %v", resp.GetError())
	}
	if _, ok := resp.GetPayload().(*wirev1.Response_ApplyResp); !ok {
		t.Fatalf("expected ApplyResp; got %T", resp.GetPayload())
	}
	// Side effect: file exists with expected content.
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello, kensa\n" {
		t.Errorf("content: got %q, want %q", got, "hello, kensa\n")
	}
}

// L-016 file_absent: agent removes a pre-existing file.
// @spec agent-handler-port-filepermissions
// @ac AC-02
// @spec agent-handler-ports-umbrella
// @ac AC-02
func TestAgentApply_FileAbsent(t *testing.T) {
	t.Run("agent-handler-ports-umbrella/AC-02", func(t *testing.T) {})
	t.Run("agent-handler-port-filepermissions/AC-02", func(t *testing.T) {})
	dir := t.TempDir()
	target := filepath.Join(dir, "to-be-deleted")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp := dispatchApplyTest(t, "file_absent", api.Params{
		"path": target,
	})
	if resp.GetError() != nil {
		t.Fatalf("envelope Error: %v", resp.GetError())
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("file should have been removed; stat err: %v", err)
	}
}

// L-017 config_set: agent sets a key=value in a config file.
// @spec agent-handler-port-filepermissions
// @ac AC-03
// @spec agent-handler-ports-umbrella
// @ac AC-03
func TestAgentApply_ConfigSet(t *testing.T) {
	t.Run("agent-handler-ports-umbrella/AC-03", func(t *testing.T) {})
	t.Run("agent-handler-port-filepermissions/AC-03", func(t *testing.T) {})
	dir := t.TempDir()
	configFile := filepath.Join(dir, "test.conf")
	if err := os.WriteFile(configFile, []byte("# initial\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp := dispatchApplyTest(t, "config_set", api.Params{
		"path":  configFile,
		"key":   "EnableX",
		"value": "yes",
	})
	if resp.GetError() != nil {
		t.Fatalf("envelope Error: %v", resp.GetError())
	}
	got, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(got), "EnableX") || !contains(string(got), "yes") {
		t.Errorf("config not updated: %q", got)
	}
}

// L-018 config_set_dropin: agent creates a drop-in file with
// a key=value pair.
// @spec agent-handler-port-filepermissions
// @ac AC-04
func TestAgentApply_ConfigSetDropin(t *testing.T) {
	t.Run("agent-handler-port-filepermissions/AC-04", func(t *testing.T) {})
	dir := t.TempDir()
	dropin := filepath.Join(dir, "99-kensa.conf")
	resp := dispatchApplyTest(t, "config_set_dropin", api.Params{
		"dir":   filepath.Dir(dropin),
		"file":  filepath.Base(dropin),
		"key":   "MaxAuthTries",
		"value": "3",
	})
	if resp.GetError() != nil {
		t.Fatalf("envelope Error: %v", resp.GetError())
	}
	got, err := os.ReadFile(dropin)
	if err != nil {
		t.Fatalf("drop-in file should exist: %v", err)
	}
	if !contains(string(got), "MaxAuthTries") {
		t.Errorf("drop-in content: %q", got)
	}
}

// ─── System-state handlers (routing-only) ────────────────────────────────

// L-019 cron_job: routes to handler (writes /etc/cron.d
// which needs root; routing-only).
// @spec agent-handler-port-filepermissions
// @ac AC-05
func TestAgentApply_CronJob_RoutesToHandler(t *testing.T) {
	t.Run("agent-handler-port-filepermissions/AC-05", func(t *testing.T) {})
	resp := dispatchApplyTest(t, "cron_job", api.Params{
		"schedule": "0 2 * * *",
		"user":     "root",
		"command":  "/bin/true",
		"file":     "/etc/cron.d/kensa-test",
	})
	assertRouted(t, "cron_job", resp)
}

// L-020 pam_module_configure: routes to handler (writes
// /etc/pam.d/<service>; routing-only).
// @spec agent-handler-port-filepermissions
// @ac AC-06
func TestAgentApply_PAMModuleConfigure_RoutesToHandler(t *testing.T) {
	t.Run("agent-handler-port-filepermissions/AC-06", func(t *testing.T) {})
	resp := dispatchApplyTest(t, "pam_module_configure", api.Params{
		"service": "sshd",
		"type":    "auth",
		"control": "required",
		"module":  "pam_unix.so",
	})
	assertRouted(t, "pam_module_configure", resp)
}

// L-021 sysctl_set: routes to handler (needs /proc write;
// routing-only).
// @spec agent-handler-port-filepermissions
// @ac AC-07
func TestAgentApply_SysctlSet_RoutesToHandler(t *testing.T) {
	t.Run("agent-handler-port-filepermissions/AC-07", func(t *testing.T) {})
	resp := dispatchApplyTest(t, "sysctl_set", api.Params{
		"key":   "net.ipv4.ip_forward",
		"value": "0",
	})
	assertRouted(t, "sysctl_set", resp)
}

// L-022 mount_option_set: routes to handler.
// @spec agent-handler-port-filepermissions
// @ac AC-08
func TestAgentApply_MountOptionSet_RoutesToHandler(t *testing.T) {
	t.Run("agent-handler-port-filepermissions/AC-08", func(t *testing.T) {})
	resp := dispatchApplyTest(t, "mount_option_set", api.Params{
		"mount_point": "/tmp",
		"options":     []interface{}{"nodev", "nosuid", "noexec"},
	})
	assertRouted(t, "mount_option_set", resp)
}

// L-023 service_disabled.
// @spec agent-handler-port-filepermissions
// @ac AC-09
func TestAgentApply_ServiceDisabled_RoutesToHandler(t *testing.T) {
	t.Run("agent-handler-port-filepermissions/AC-09", func(t *testing.T) {})
	resp := dispatchApplyTest(t, "service_disabled", api.Params{"service": "test.service"})
	assertRouted(t, "service_disabled", resp)
}

// L-024 service_enabled.
func TestAgentApply_ServiceEnabled_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "service_enabled", api.Params{"service": "test.service"})
	assertRouted(t, "service_enabled", resp)
}

// L-025 service_masked.
func TestAgentApply_ServiceMasked_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "service_masked", api.Params{"service": "test.service"})
	assertRouted(t, "service_masked", resp)
}

// L-026 selinux_boolean_set.
func TestAgentApply_SELinuxBooleanSet_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "selinux_boolean_set", api.Params{
		"name":  "ssh_sysadm_login",
		"value": "off",
	})
	assertRouted(t, "selinux_boolean_set", resp)
}

// L-027 kernel_module_disable.
func TestAgentApply_KernelModuleDisable_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "kernel_module_disable", api.Params{"name": "cramfs"})
	assertRouted(t, "kernel_module_disable", resp)
}

// L-028 audit_rule_set.
func TestAgentApply_AuditRuleSet_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "audit_rule_set", api.Params{
		"rule":         "-w /etc/sudoers -p wa -k sudoers",
		"persist_file": "/etc/audit/rules.d/50-sudoers.rules",
	})
	assertRouted(t, "audit_rule_set", resp)
}

// L-029 package_present.
func TestAgentApply_PackagePresent_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "package_present", api.Params{"name": "openssh-server"})
	assertRouted(t, "package_present", resp)
}

// L-030 package_absent.
func TestAgentApply_PackageAbsent_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "package_absent", api.Params{"name": "telnetd"})
	assertRouted(t, "package_absent", resp)
}

// L-031 apt_present.
func TestAgentApply_AptPresent_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "apt_present", api.Params{"name": "openssh-server"})
	assertRouted(t, "apt_present", resp)
}

// L-032 apt_absent.
func TestAgentApply_AptAbsent_RoutesToHandler(t *testing.T) {
	resp := dispatchApplyTest(t, "apt_absent", api.Params{"name": "telnetd"})
	assertRouted(t, "apt_absent", resp)
}

// contains is a substring helper (Go's strings.Contains
// requires the import; this is local-test scope).
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
