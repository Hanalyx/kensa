// Package detect runs SSH probes to determine which capabilities a
// remote host has. Capabilities gate which [api.Implementation] is
// selected from a rule's implementations list.
package detect

import (
	"context"
	"sort"

	"github.com/Hanalyx/kensa/api"
)

// probe is a single capability probe: a name and the shell command to
// run on the target host.
type probe struct {
	name string
	cmd  string
}

// probes is the canonical list of capability probes. Each probe runs
// via [api.Transport.Run]; exit code 0 means the capability is present.
var probes = []probe{
	{
		"sshd_config_d",
		`[ -d /etc/ssh/sshd_config.d ] && grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config`,
	},
	{
		"authselect",
		`command -v authselect >/dev/null 2>&1`,
	},
	{
		"crypto_policies",
		`command -v update-crypto-policies >/dev/null 2>&1`,
	},
	{
		"fips_mode",
		// RHEL: fips-mode-setup --check. Ubuntu Pro: same binary exists.
		// Universal fallback: /proc/sys/crypto/fips_enabled = 1.
		`fips-mode-setup --check 2>/dev/null | grep -q 'FIPS mode is enabled' || [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" = "1" ]`,
	},
	{
		"firewalld_nftables",
		`systemctl is-active firewalld >/dev/null 2>&1 && command -v nft >/dev/null 2>&1`,
	},
	{
		"pam_faillock",
		`[ -f /etc/security/faillock.conf ]`,
	},
	{
		"pam_pwquality",
		`[ -f /etc/security/pwquality.conf ]`,
	},
	{
		"grub_bls",
		`[ -d /boot/loader/entries ]`,
	},
	{
		"selinux",
		`getenforce 2>/dev/null | grep -q Enforcing`,
	},
	{
		"aide",
		`command -v aide >/dev/null 2>&1`,
	},
	{
		"fapolicyd",
		`systemctl list-unit-files fapolicyd.service 2>/dev/null | grep -q fapolicyd`,
	},
	{
		"usbguard",
		`systemctl list-unit-files usbguard.service 2>/dev/null | grep -q usbguard`,
	},
	{
		"systemd_resolved",
		`systemctl is-active systemd-resolved >/dev/null 2>&1`,
	},
	{
		"nftables",
		`command -v nft >/dev/null 2>&1`,
	},
	{
		"firewalld",
		`systemctl list-unit-files firewalld.service 2>/dev/null | grep -q firewalld`,
	},
	{
		"rsyslog",
		`systemctl list-unit-files rsyslog.service 2>/dev/null | grep -q rsyslog`,
	},
	{
		"journald",
		`systemctl is-active systemd-journald >/dev/null 2>&1`,
	},
	{
		"auditd",
		`systemctl is-active auditd >/dev/null 2>&1`,
	},
	{
		"cron",
		`systemctl list-unit-files crond.service cron.service 2>/dev/null | grep -qE '(crond|cron)\.service'`,
	},
	{
		"at",
		`command -v at >/dev/null 2>&1`,
	},
	{
		"coredump_systemd",
		`systemctl list-unit-files systemd-coredump.socket 2>/dev/null | grep -q coredump`,
	},
	{
		"sssd",
		`systemctl list-unit-files sssd.service 2>/dev/null | grep -q sssd`,
	},
	{
		"chronyd",
		`systemctl list-unit-files chronyd.service 2>/dev/null | grep -q chronyd`,
	},
	{
		"dnf_automatic",
		`systemctl list-unit-files dnf-automatic.timer 2>/dev/null | grep -q dnf-automatic`,
	},
	{
		"subscription_manager",
		`command -v subscription-manager >/dev/null 2>&1`,
	},

	// ── Ubuntu / Debian-specific probes ──────────────────────────────────

	// dpkg is the primary distro discriminator: present on all Debian-
	// family systems, absent on RHEL/EL. Rules gate Ubuntu implementations
	// on requires: [dpkg].
	{
		"dpkg",
		`command -v dpkg >/dev/null 2>&1`,
	},
	// apt gates package_present/package_absent Ubuntu implementations.
	{
		"apt",
		`command -v apt-get >/dev/null 2>&1`,
	},
	// apparmor is the Ubuntu equivalent of SELinux mandatory access control.
	// Detected independently of selinux so rules can require one or the other.
	{
		"apparmor",
		`aa-status 2>/dev/null | grep -q 'apparmor module is loaded'`,
	},
	// ufw is Ubuntu's front-end to nftables/iptables, analogous to firewalld.
	{
		"ufw",
		`systemctl list-unit-files ufw.service 2>/dev/null | grep -q ufw`,
	},
	// apt_unattended_upgrades is the Ubuntu equivalent of dnf_automatic.
	{
		"apt_unattended_upgrades",
		`dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'`,
	},
	// ubuntu_advantage detects Ubuntu Pro / Ubuntu Advantage tooling,
	// analogous to subscription_manager on RHEL.
	{
		"ubuntu_advantage",
		`command -v ua >/dev/null 2>&1 || command -v pro >/dev/null 2>&1`,
	},
	// systemd_dbus is true when (a) systemd is the init system,
	// (b) the system D-Bus socket exists, AND (c) the
	// kensa-systemd-helper binary is installed at the FHS path.
	// Phase 4 D-008. The probe runs as the SSH user (kensa-svc);
	// the helper does the actual privileged D-Bus call via sudo.
	// All three conditions must hold for the agent-mode D-Bus
	// path to be exercisable; if any is false, handlers fall
	// back to their direct-SSH shell-out path.
	{
		"systemd_dbus",
		`[ -S /run/dbus/system_bus_socket ] && [ -x /usr/libexec/kensa-systemd-helper ] && systemctl --version >/dev/null 2>&1`,
	},
}

// Detect runs all capability probes against the host reachable via
// transport and returns the resulting [api.CapabilitySet]. Each
// capability is true when its probe exits with code 0. Transport
// errors on individual probes are suppressed — the capability is
// marked false and detection continues with the remaining probes.
func Detect(ctx context.Context, transport api.Transport) (api.CapabilitySet, error) {
	caps := make(api.CapabilitySet, len(probes))
	for _, p := range probes {
		caps[p.name] = runProbe(ctx, transport, p.cmd)
	}
	return caps, nil
}

// runProbe executes one probe command and returns true when it exits
// with code 0. Any transport error is treated as a negative result so
// that a single failing probe cannot abort the overall detection run.
func runProbe(ctx context.Context, transport api.Transport, cmd string) bool {
	res, err := transport.Run(ctx, cmd)
	if err != nil {
		return false
	}
	return res.ExitCode == 0
}

// KnownCapabilities returns the set of capability names that Detect
// can probe for, sorted alphabetically. Used by the --capability /
// -C flag to validate operator-provided KEY=VALUE pairs against
// the canonical vocabulary.
func KnownCapabilities() []string {
	names := make([]string, 0, len(probes))
	for _, p := range probes {
		names = append(names, p.name)
	}
	sort.Strings(names)
	return names
}

// ApplyOverrides returns a copy of detected with every key in
// overrides set to the override value. Keys present in overrides
// but not in detected are still applied — operators may legitimately
// force a capability that wasn't probed (e.g., behind a fake
// transport in tests). Validation that the keys are in
// KnownCapabilities() is the caller's responsibility.
func ApplyOverrides(detected api.CapabilitySet, overrides api.CapabilitySet) api.CapabilitySet {
	if len(overrides) == 0 {
		return detected
	}
	out := make(api.CapabilitySet, len(detected)+len(overrides))
	for k, v := range detected {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}
