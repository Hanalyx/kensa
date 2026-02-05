"""Capability detection probes for remote hosts."""

from __future__ import annotations

from collections import namedtuple
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner.ssh import SSHSession


# ── Platform detection ─────────────────────────────────────────────────────

PlatformInfo = namedtuple("PlatformInfo", ["family", "version"])

RHEL_FAMILY = {"rhel", "centos", "rocky", "almalinux", "ol"}


def detect_platform(ssh: SSHSession) -> PlatformInfo | None:
    """Read /etc/os-release and return normalized (family, major_version).

    RHEL derivatives (rocky, alma, centos, ol) are normalized to family "rhel".
    Returns None if os-release cannot be read (caller should warn and skip filtering).
    """
    result = ssh.run("cat /etc/os-release")
    if result.exit_code != 0:
        return None

    fields: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip().strip('"')

    os_id = fields.get("ID", "").lower()
    ver_str = fields.get("VERSION_ID", "0")
    try:
        version = int(ver_str.split(".")[0])
    except (ValueError, IndexError):
        version = 0

    family = "rhel" if os_id in RHEL_FAMILY else os_id

    return PlatformInfo(family=family, version=version)

# Each probe: capability name -> shell command.
# Exit code 0 = capability present.
CAPABILITY_PROBES: dict[str, str] = {
    "sshd_config_d": (
        "test -d /etc/ssh/sshd_config.d && { "
        "grep -qi 'Include.*/etc/ssh/sshd_config.d' /etc/ssh/sshd_config 2>/dev/null || "
        "find /etc/ssh/sshd_config.d -name '*.conf' -print -quit 2>/dev/null | grep -q .; "
        "}"
    ),
    "authselect": "command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1",
    "authselect_sssd": "authselect current 2>/dev/null | grep -q sssd",
    "crypto_policies": "test -f /etc/crypto-policies/config && command -v update-crypto-policies >/dev/null 2>&1",
    "crypto_policy_modules": (
        "update-crypto-policies --show 2>/dev/null | grep -q ':' || "
        "test -d /usr/share/crypto-policies/policies/modules"
    ),
    "fips_mode": "fips-mode-setup --check 2>/dev/null | grep -qi 'is enabled'",
    "firewalld_nftables": (
        "systemctl is-active firewalld >/dev/null 2>&1 && "
        "firewall-cmd --get-default-zone >/dev/null 2>&1 && "
        "grep -q 'FirewallBackend=nftables' /etc/firewalld/firewalld.conf 2>/dev/null"
    ),
    "firewalld_iptables": (
        "systemctl is-active firewalld >/dev/null 2>&1 && "
        "grep -q 'FirewallBackend=iptables' /etc/firewalld/firewalld.conf 2>/dev/null"
    ),
    "systemd_resolved": "systemctl is-active systemd-resolved >/dev/null 2>&1",
    "pam_faillock": "test -f /etc/security/faillock.conf",
    "grub_bls": "test -d /boot/loader/entries && grep -q 'blscfg' /etc/default/grub 2>/dev/null",
    "grub_legacy": "test -f /boot/grub2/grub.cfg && ! test -d /boot/loader/entries",
    "journald_primary": "systemctl is-active systemd-journald >/dev/null 2>&1",
    "rsyslog_active": "systemctl is-active rsyslog >/dev/null 2>&1",
    "fapolicyd": "rpm -q fapolicyd >/dev/null 2>&1",
    "selinux": "command -v getenforce >/dev/null 2>&1 && [ \"$(getenforce 2>/dev/null)\" != 'Disabled' ]",
    "aide": "rpm -q aide >/dev/null 2>&1",
    "tpm2": "test -c /dev/tpmrm0 || test -c /dev/tpm0",
    "usbguard": "rpm -q usbguard >/dev/null 2>&1",
    "dnf_automatic": "rpm -q dnf-automatic >/dev/null 2>&1",
    "gdm": "rpm -q gdm >/dev/null 2>&1",
    "tmux": "command -v tmux >/dev/null 2>&1",
}


def detect_capabilities(ssh: SSHSession, *, verbose: bool = False) -> dict[str, bool]:
    """Run all capability probes and return results."""
    caps = {}
    for name, cmd in CAPABILITY_PROBES.items():
        result = ssh.run(cmd)
        caps[name] = result.ok
        if verbose and not result.ok:
            import sys
            print(f"    [probe] {name}: exit={result.exit_code} stderr={result.stderr!r}", file=sys.stderr)
    return caps
