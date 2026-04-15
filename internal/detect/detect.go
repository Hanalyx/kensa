// Package detect runs SSH probes to determine which capabilities a
// remote host has. Capabilities gate which [api.Implementation] is
// selected from a rule's implementations list.
package detect

import (
	"context"

	"github.com/Hanalyx/kensa-go/api"
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
		`fips-mode-setup --check 2>/dev/null | grep -q 'FIPS mode is enabled'`,
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
