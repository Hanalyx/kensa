#!/usr/bin/env python3
"""Generate missing CIS RHEL 9 rule YAML files (development tool).

Reads the CIS RHEL 9 mapping, identifies rules referenced but not yet
created, and generates canonical rule YAML files from pattern-based
specifications.

Usage:
    python scripts/generate_cis_rules.py          # Generate all missing rules
    python scripts/generate_cis_rules.py --dry-run # Show what would be created
"""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"
MAPPING_PATH = PROJECT_ROOT / "mappings" / "cis" / "rhel9_v2.0.0.yaml"


# ═══════════════════════════════════════════════════════════════════════════
#  Rule Specifications — organized by pattern type
# ═══════════════════════════════════════════════════════════════════════════

# ── Sysctl rules: (key_value_pairs) ──────────────────────────────────────
# Each entry: rule_id -> [(sysctl_key, expected_value), ...]

SYSCTL_SPECS: dict[str, list[tuple[str, str]]] = {
    "sysctl-ip-forward-disabled": [
        ("net.ipv4.ip_forward", "0"),
        ("net.ipv6.conf.all.forwarding", "0"),
    ],
    "sysctl-send-redirects-disabled": [
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
    ],
    "sysctl-ignore-bogus-icmp": [
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ],
    "sysctl-ignore-broadcast-icmp": [
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ],
    "sysctl-icmp-redirects-disabled": [
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        ("net.ipv6.conf.all.accept_redirects", "0"),
        ("net.ipv6.conf.default.accept_redirects", "0"),
    ],
    "sysctl-secure-redirects-disabled": [
        ("net.ipv4.conf.all.secure_redirects", "0"),
        ("net.ipv4.conf.default.secure_redirects", "0"),
    ],
    "sysctl-rp-filter": [
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.default.rp_filter", "1"),
    ],
    "sysctl-source-route-disabled": [
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.conf.default.accept_source_route", "0"),
        ("net.ipv6.conf.all.accept_source_route", "0"),
        ("net.ipv6.conf.default.accept_source_route", "0"),
    ],
    "sysctl-log-martians": [
        ("net.ipv4.conf.all.log_martians", "1"),
        ("net.ipv4.conf.default.log_martians", "1"),
    ],
    "sysctl-tcp-syncookies": [
        ("net.ipv4.tcp_syncookies", "1"),
    ],
    "sysctl-ipv6-ra-disabled": [
        ("net.ipv6.conf.all.accept_ra", "0"),
        ("net.ipv6.conf.default.accept_ra", "0"),
    ],
}

# ── Service disable rules: service_name ──────────────────────────────────

SERVICE_DISABLE_SPECS: dict[str, str] = {
    "service-disable-avahi": "avahi-daemon",
    "service-disable-dnsmasq": "dnsmasq",
    "service-disable-dovecot": "dovecot",
    "service-disable-rsyncd": "rsyncd",
    "service-disable-smb": "smb",
    "service-disable-xinetd": "xinetd",
    "service-disable-ypserv": "ypserv",
}

# ── File permission rules: (path, owner, group, mode) ───────────────────

FILE_PERM_SPECS: dict[str, tuple[str, str, str, str]] = {
    "etc-passwd-permissions": ("/etc/passwd", "root", "root", "0644"),
    "etc-passwd-backup-permissions": ("/etc/passwd-", "root", "root", "0644"),
    "etc-group-permissions": ("/etc/group", "root", "root", "0644"),
    "etc-group-backup-permissions": ("/etc/group-", "root", "root", "0644"),
    "etc-shadow-permissions": ("/etc/shadow", "root", "root", "0000"),
    "etc-shadow-backup-permissions": ("/etc/shadow-", "root", "root", "0000"),
    "etc-gshadow-permissions": ("/etc/gshadow", "root", "root", "0000"),
    "etc-gshadow-backup-permissions": ("/etc/gshadow-", "root", "root", "0000"),
    "sshd-config-permissions": ("/etc/ssh/sshd_config", "root", "root", "0600"),
}

# ── Cron permission rules: (path, owner, group, mode) ───────────────────

CRON_PERM_SPECS: dict[str, tuple[str, str, str, str]] = {
    "crontab-permissions": ("/etc/crontab", "root", "root", "0600"),
    "cron-hourly-permissions": ("/etc/cron.hourly", "root", "root", "0700"),
    "cron-daily-permissions": ("/etc/cron.daily", "root", "root", "0700"),
    "cron-weekly-permissions": ("/etc/cron.weekly", "root", "root", "0700"),
    "cron-monthly-permissions": ("/etc/cron.monthly", "root", "root", "0700"),
    "cron-d-permissions": ("/etc/cron.d", "root", "root", "0700"),
}

# ── Audit log/config/tools permission rules: (paths, owner, group, mode) ─

AUDIT_PERM_SPECS: dict[str, dict] = {
    "audit-log-owner": {
        "desc": "Audit log files must be owned by root to prevent unauthorized modification.",
        "run_check": 'find "$(dirname "$(awk -F= \'/^log_file/{print $2}\' /etc/audit/auditd.conf | tr -d \' \')")" -type f ! -user root 2>/dev/null | head -1',
        "run_fix": 'find "$(dirname "$(awk -F= \'/^log_file/{print $2}\' /etc/audit/auditd.conf | tr -d \' \')")" -type f -exec chown root {} +',
    },
    "audit-log-group": {
        "desc": "Audit log files must be group-owned by root or adm to prevent unauthorized access.",
        "run_check": 'find "$(dirname "$(awk -F= \'/^log_file/{print $2}\' /etc/audit/auditd.conf | tr -d \' \')")" -type f ! -group root ! -group adm 2>/dev/null | head -1',
        "run_fix": 'find "$(dirname "$(awk -F= \'/^log_file/{print $2}\' /etc/audit/auditd.conf | tr -d \' \')")" -type f -exec chgrp root {} +',
    },
    "audit-config-owner": {
        "desc": "Audit configuration files must be owned by root.",
        "run_check": "find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root 2>/dev/null | head -1",
        "run_fix": "find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) -exec chown root {} +",
    },
    "audit-config-group": {
        "desc": "Audit configuration files must be group-owned by root.",
        "run_check": "find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root 2>/dev/null | head -1",
        "run_fix": "find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) -exec chgrp root {} +",
    },
    "audit-tools-permissions": {
        "desc": "Audit tool binaries must have restrictive permissions.",
        "run_check": "stat -c '%a' /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null | awk '{if ($1 > 755) exit 1}'",
        "run_fix": "chmod 755 /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null",
    },
    "audit-tools-owner": {
        "desc": "Audit tool binaries must be owned by root.",
        "run_check": "find /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules -type f ! -user root 2>/dev/null | head -1",
        "run_fix": "chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null",
    },
    "audit-tools-group": {
        "desc": "Audit tool binaries must be group-owned by root.",
        "run_check": "find /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules -type f ! -group root 2>/dev/null | head -1",
        "run_fix": "chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules 2>/dev/null",
    },
}

# ── Audit event rules: (grep_pattern, audit_rule, persist_file) ──────────

AUDIT_EVENT_SPECS: dict[str, dict] = {
    "audit-sudoers": {
        "desc": "Changes to sudoers files must be audited to detect privilege escalation attempts.",
        "grep": "sudoers.*scope",
        "rule": "-w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d -p wa -k scope",
        "file": "50-scope.rules",
    },
    "audit-user-emulation": {
        "desc": "Actions performed as another user must be logged to maintain accountability.",
        "grep": "user_emulation",
        "rule": "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation",
        "file": "50-user_emulation.rules",
    },
    "audit-sudo-log": {
        "desc": "The sudo log file must be monitored for tampering.",
        "grep": "sudo.log",
        "rule": "-w /var/log/sudo.log -p wa -k sudo_log",
        "file": "50-sudo.rules",
    },
    "audit-delete": {
        "desc": "File deletion events must be collected to detect unauthorized data destruction.",
        "grep": "delete",
        "rule": "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -k delete",
        "file": "50-delete.rules",
    },
    "audit-file-access-failed": {
        "desc": "Unsuccessful file access attempts must be collected to detect intrusion attempts.",
        "grep": "access",
        "rule": "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
        "file": "50-access.rules",
    },
    "audit-identity-change": {
        "desc": "Changes to user and group identity files must be audited.",
        "grep": "identity",
        "rule": "-w /etc/group -p wa -k identity\n-w /etc/passwd -p wa -k identity\n-w /etc/gshadow -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/security/opasswd -p wa -k identity",
        "file": "50-identity.rules",
    },
    "audit-perm-mod": {
        "desc": "Discretionary access control permission changes must be collected.",
        "grep": "perm_mod",
        "rule": "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod\n-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod\n-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod",
        "file": "50-perm_mod.rules",
    },
    "audit-mounts": {
        "desc": "Successful file system mounts must be collected.",
        "grep": "mounts",
        "rule": "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts",
        "file": "50-mounts.rules",
    },
    "audit-session": {
        "desc": "Session initiation information must be collected.",
        "grep": "session",
        "rule": "-w /var/run/utmp -p wa -k session\n-w /var/log/wtmp -p wa -k session\n-w /var/log/btmp -p wa -k session",
        "file": "50-session.rules",
    },
    "audit-logins": {
        "desc": "Login and logout events must be collected.",
        "grep": "logins",
        "rule": "-w /var/log/lastlog -p wa -k logins\n-w /var/run/faillock -p wa -k logins",
        "file": "50-logins.rules",
    },
    "audit-mac-policy": {
        "desc": "Changes to Mandatory Access Controls must be collected.",
        "grep": "MAC-policy",
        "rule": "-w /etc/selinux -p wa -k MAC-policy\n-w /usr/share/selinux -p wa -k MAC-policy",
        "file": "50-MAC-policy.rules",
    },
    "audit-network-change": {
        "desc": "Changes to the network environment must be collected.",
        "grep": "system-locale",
        "rule": "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale\n-w /etc/issue -p wa -k system-locale\n-w /etc/issue.net -p wa -k system-locale\n-w /etc/hosts -p wa -k system-locale\n-w /etc/sysconfig/network -p wa -k system-locale",
        "file": "50-system_locale.rules",
    },
    "audit-immutable": {
        "desc": "The audit configuration must be set immutable so it cannot be changed at runtime.",
        "grep": "^-e 2",
        "rule": "-e 2",
        "file": "99-finalize.rules",
    },
}

# Additional audit command rules (audit-cmd-*)
AUDIT_CMD_SPECS: dict[str, dict] = {
    "audit-cmd-chcon": {
        "cmd": "chcon",
        "rule": "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng",
    },
    "audit-cmd-setfacl": {
        "cmd": "setfacl",
        "rule": "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng",
    },
    "audit-cmd-chacl": {
        "cmd": "chacl",
        "rule": "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng",
    },
    "audit-cmd-usermod": {
        "cmd": "usermod",
        "rule": "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod",
    },
}

# ── Audit privileged commands ────────────────────────────────────────────
AUDIT_PRIVILEGED_SPEC = {
    "audit-privileged-commands": {
        "desc": "Execution of privileged commands (SUID/SGID binaries) must be audited.",
        "grep": "privileged",
    },
}

# ── SSH config rules: (directive, expected, remediation_note) ────────────

SSH_SPECS: dict[str, dict] = {
    "ssh-approved-ciphers": {
        "directive": "Ciphers",
        "expected": None,  # Site-specific
        "note": "Configure Ciphers with site-approved algorithms per crypto policy",
    },
    "ssh-approved-kex": {
        "directive": "KexAlgorithms",
        "expected": None,
        "note": "Configure KexAlgorithms with site-approved algorithms per crypto policy",
    },
    "ssh-approved-macs": {
        "directive": "MACs",
        "expected": None,
        "note": "Configure MACs with site-approved algorithms per crypto policy",
    },
    "ssh-deny-empty-passwords": {
        "directive": "PermitEmptyPasswords",
        "expected": "no",
    },
    "ssh-disable-gssapi": {
        "directive": "GSSAPIAuthentication",
        "expected": "no",
    },
    "ssh-disable-hostbased-auth": {
        "directive": "HostbasedAuthentication",
        "expected": "no",
    },
    "ssh-disable-user-environment": {
        "directive": "PermitUserEnvironment",
        "expected": "no",
    },
}

# ── Config value rules: (path, key, expected, separator, reload) ─────────

CONFIG_VALUE_SPECS: dict[str, dict] = {
    "journald-no-forward-syslog": {
        "category": "logging",
        "severity": "low",
        "tags": ["journald", "logging"],
        "path": "/etc/systemd/journald.conf",
        "key": "ForwardToSyslog",
        "expected": "no",
        "separator": "=",
        "reload": "systemd-journald",
        "nist": ["AU-4"],
    },
    "journald-storage-persistent": {
        "category": "logging",
        "severity": "low",
        "tags": ["journald", "logging", "storage"],
        "path": "/etc/systemd/journald.conf",
        "key": "Storage",
        "expected": "persistent",
        "separator": "=",
        "reload": "systemd-journald",
        "nist": ["AU-4"],
    },
    "rsyslog-file-permissions": {
        "category": "logging",
        "severity": "medium",
        "tags": ["rsyslog", "logging", "permissions"],
        "path": "/etc/rsyslog.conf",
        "key": "$FileCreateMode",
        "expected": "0640",
        "separator": " ",
        "reload": "rsyslog",
        "nist": ["AU-9"],
    },
    "auditd-space-left-action": {
        "category": "audit",
        "severity": "medium",
        "tags": ["audit", "auditd", "storage"],
        "path": "/etc/audit/auditd.conf",
        "key": "space_left_action",
        "expected": "email",
        "separator": " = ",
        "nist": ["AU-5"],
    },
    "pwquality-difok": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "password", "pwquality"],
        "path": "/etc/security/pwquality.conf",
        "key": "difok",
        "expected": "{{ pam_pwquality_difok }}",
        "separator": " = ",
        "nist": ["IA-5"],
        "comparator": ">=",
    },
    "pwquality-minlen": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "password", "pwquality"],
        "path": "/etc/security/pwquality.conf",
        "key": "minlen",
        "expected": "{{ pam_pwquality_minlen }}",
        "separator": " = ",
        "nist": ["IA-5"],
        "comparator": ">=",
    },
    "pwquality-maxrepeat": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "password", "pwquality"],
        "path": "/etc/security/pwquality.conf",
        "key": "maxrepeat",
        "expected": "3",
        "separator": " = ",
        "nist": ["IA-5"],
        "comparator": "<=",
    },
    "pwquality-maxsequence": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "password", "pwquality"],
        "path": "/etc/security/pwquality.conf",
        "key": "maxsequence",
        "expected": "3",
        "separator": " = ",
        "nist": ["IA-5"],
        "comparator": "<=",
    },
    "pwquality-dictcheck": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "password", "pwquality"],
        "path": "/etc/security/pwquality.conf",
        "key": "dictcheck",
        "expected": "1",
        "separator": " = ",
        "nist": ["IA-5"],
    },
    "pwquality-enforce-root": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "password", "pwquality"],
        "path": "/etc/security/pwquality.conf",
        "key": "enforce_for_root",
        "expected": "",
        "separator": " = ",
        "nist": ["IA-5"],
        "check_method": "command",
        "run_check": "grep -qE '^\\s*enforce_for_root\\b' /etc/security/pwquality.conf",
        "run_fix": "sed -i '/^#.*enforce_for_root/s/^#//' /etc/security/pwquality.conf || echo 'enforce_for_root' >> /etc/security/pwquality.conf",
    },
    "password-max-age": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["password", "login-defs", "aging"],
        "path": "/etc/login.defs",
        "key": "PASS_MAX_DAYS",
        "expected": "{{ login_defs_pass_max_days }}",
        "separator": "\t",
        "nist": ["IA-5"],
        "comparator": "<=",
    },
    "password-min-age": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["password", "login-defs", "aging"],
        "path": "/etc/login.defs",
        "key": "PASS_MIN_DAYS",
        "expected": "{{ login_defs_pass_min_days }}",
        "separator": "\t",
        "nist": ["IA-5"],
        "comparator": ">=",
    },
    "password-warn-age": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["password", "login-defs", "aging"],
        "path": "/etc/login.defs",
        "key": "PASS_WARN_AGE",
        "expected": "{{ login_defs_pass_warn_age }}",
        "separator": "\t",
        "nist": ["IA-5"],
        "comparator": ">=",
    },
}

# ── Service state (enable) rules ────────────────────────────────────────

SERVICE_ENABLE_SPECS: dict[str, dict] = {
    "cron-enabled": {
        "category": "system",
        "service": "crond",
        "tags": ["service", "cron", "scheduling"],
        "nist": ["CM-6"],
    },
    "chrony-enabled": {
        "category": "services",
        "service": "chronyd",
        "tags": ["service", "ntp", "time"],
        "nist": ["AU-8"],
    },
    "rsyslog-enabled": {
        "category": "logging",
        "service": "rsyslog",
        "tags": ["service", "rsyslog", "logging"],
        "nist": ["AU-2", "AU-12"],
    },
    "auditd-enabled": {
        "category": "audit",
        "service": "auditd",
        "tags": ["service", "audit", "auditd"],
        "nist": ["AU-2", "AU-12"],
    },
}

# ── Package present rules ────────────────────────────────────────────────

PACKAGE_PRESENT_SPECS: dict[str, dict] = {
    "auditd-installed": {
        "category": "audit",
        "package": "audit",
        "tags": ["audit", "auditd", "packages"],
        "nist": ["AU-2", "AU-12"],
    },
    "rsyslog-installed": {
        "category": "logging",
        "package": "rsyslog",
        "tags": ["rsyslog", "logging", "packages"],
        "nist": ["AU-2"],
    },
    "package-sudo-installed": {
        "category": "access-control",
        "package": "sudo",
        "tags": ["sudo", "access-control", "packages"],
        "nist": ["AC-6"],
    },
}

# ── Command check rules (complex checks) ────────────────────────────────

COMMAND_SPECS: dict[str, dict] = {
    "chrony-sources": {
        "category": "services",
        "severity": "medium",
        "tags": ["chrony", "ntp", "time"],
        "nist": ["AU-8"],
        "desc": "Chrony must be configured with authoritative time sources.",
        "rationale": "Without reliable time sources, system clocks may drift, compromising log accuracy and time-based security controls.",
        "run_check": "chronyc sources 2>/dev/null | grep -E '^\\^' | head -1",
        "run_fix": None,
        "fix_note": "Configure NTP sources in /etc/chrony.conf with site-specific time servers",
    },
    "cron-allow": {
        "category": "system",
        "severity": "medium",
        "tags": ["cron", "access-control"],
        "nist": ["AC-3", "CM-6"],
        "desc": "Access to crontab must be restricted to authorized users via /etc/cron.allow.",
        "rationale": "Unrestricted cron access allows any user to schedule tasks, potentially enabling privilege escalation or resource abuse.",
        "run_check": "test -f /etc/cron.allow && stat -c '%a %U %G' /etc/cron.allow | grep -q '600 root root'",
        "run_fix": "touch /etc/cron.allow && chmod 600 /etc/cron.allow && chown root:root /etc/cron.allow",
    },
    "at-allow": {
        "category": "system",
        "severity": "medium",
        "tags": ["at", "access-control"],
        "nist": ["AC-3", "CM-6"],
        "desc": "Access to at must be restricted to authorized users via /etc/at.allow.",
        "rationale": "Unrestricted at access allows any user to schedule one-time tasks, potentially enabling privilege escalation.",
        "run_check": "test -f /etc/at.allow && stat -c '%a %U %G' /etc/at.allow | grep -q '600 root root'",
        "run_fix": "touch /etc/at.allow && chmod 600 /etc/at.allow && chown root:root /etc/at.allow",
    },
    "postfix-local-only": {
        "category": "services",
        "severity": "medium",
        "tags": ["postfix", "mail", "network"],
        "nist": ["CM-7"],
        "desc": "The mail transfer agent must be configured for local-only mode.",
        "rationale": "A mail server listening on external interfaces exposes an unnecessary attack surface if remote mail delivery is not required.",
        "run_check": "ss -lntu | grep -E ':25\\s' | grep -qv '127.0.0.1\\|::1' && exit 1 || exit 0",
        "run_fix": None,
        "fix_note": "Configure postfix inet_interfaces = loopback-only in /etc/postfix/main.cf",
    },
    "aide-scheduled": {
        "category": "audit",
        "severity": "medium",
        "tags": ["aide", "integrity", "scheduled"],
        "nist": ["SI-7"],
        "desc": "Filesystem integrity must be regularly checked using AIDE.",
        "rationale": "Without regular integrity checks, unauthorized file modifications could go undetected indefinitely.",
        "run_check": "systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q enabled || crontab -u root -l 2>/dev/null | grep -q aide",
        "run_fix": None,
        "fix_note": "Enable aidecheck.timer or add AIDE to root crontab",
    },
    "no-world-writable": {
        "category": "filesystem",
        "severity": "medium",
        "tags": ["filesystem", "permissions", "world-writable"],
        "nist": ["AC-3", "MP-2"],
        "desc": "World-writable files and directories must be secured.",
        "rationale": "World-writable files can be modified by any user, creating opportunities for privilege escalation or data tampering.",
        "run_check": "df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | head -1 | grep -q . && exit 1 || exit 0",
        "run_fix": None,
        "fix_note": "Review and remove world-writable permissions from flagged files",
    },
    "home-directories-exist": {
        "category": "filesystem",
        "severity": "medium",
        "tags": ["home", "users", "filesystem"],
        "nist": ["AC-2"],
        "desc": "Local interactive user home directories must exist and be properly configured.",
        "rationale": "Missing home directories can prevent users from logging in properly and may indicate orphaned accounts.",
        "run_check": "awk -F: '($3>=1000 && $7 !~ /nologin|false/) {print $6}' /etc/passwd | while read dir; do test -d \"$dir\" || exit 1; done",
        "run_fix": None,
        "fix_note": "Create missing home directories or remove orphaned user accounts",
    },
    "home-dotfiles-permissions": {
        "category": "filesystem",
        "severity": "medium",
        "tags": ["home", "dotfiles", "permissions"],
        "nist": ["AC-3"],
        "desc": "Local interactive user dot files must not be group or world writable.",
        "rationale": "Overly permissive dot files could allow other users to modify login scripts, potentially enabling code execution in the context of another user.",
        "run_check": "awk -F: '($3>=1000 && $7 !~ /nologin|false/) {print $6}' /etc/passwd | while read dir; do find \"$dir\" -maxdepth 1 -name '.*' -type f -perm /go+w 2>/dev/null; done | head -1 | grep -q . && exit 1 || exit 0",
        "run_fix": None,
        "fix_note": "Remove group and world write permissions from user dot files",
    },
    "pam-faillock-enabled": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "authentication", "faillock"],
        "nist": ["AC-7"],
        "desc": "The pam_faillock module must be enabled in the PAM configuration.",
        "rationale": "pam_faillock provides account lockout after failed login attempts, preventing brute-force attacks.",
        "run_check": "grep -qE '^\\s*auth\\s+required\\s+pam_faillock\\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || authselect current 2>/dev/null | grep -q with-faillock",
        "run_fix": "authselect enable-feature with-faillock 2>/dev/null || true",
    },
    "pam-faillock-root": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "authentication", "faillock", "root"],
        "nist": ["AC-7"],
        "desc": "Account lockout must include the root account.",
        "rationale": "Excluding root from lockout allows unlimited password guessing against the most privileged account.",
        "run_check": "grep -qE '^\\s*even_deny_root\\b' /etc/security/faillock.conf",
        "run_fix": "sed -i '/^#.*even_deny_root/s/^#//' /etc/security/faillock.conf || echo 'even_deny_root' >> /etc/security/faillock.conf",
    },
    "pam-pwquality-enabled": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "authentication", "pwquality"],
        "nist": ["IA-5"],
        "desc": "The pam_pwquality module must be enabled in the PAM configuration.",
        "rationale": "pam_pwquality enforces password complexity requirements, preventing weak passwords.",
        "run_check": "grep -qE '^\\s*(password|auth).*pam_pwquality\\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || authselect current 2>/dev/null | grep -q with-pwquality",
        "run_fix": "authselect enable-feature with-pwquality 2>/dev/null || true",
    },
    "pam-pwhistory-remember": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "password", "history"],
        "nist": ["IA-5"],
        "desc": "Password history must be configured to prevent reuse.",
        "rationale": "Without password history, users could alternate between a small set of passwords, reducing security.",
        "run_check": "grep -qE '^\\s*remember\\s*=\\s*[0-9]+' /etc/security/pwhistory.conf 2>/dev/null || grep -qE 'pam_pwhistory\\.so.*remember=' /etc/pam.d/system-auth",
        "run_fix": None,
        "fix_note": "Configure remember in /etc/security/pwhistory.conf or pam_pwhistory.so",
    },
    "pam-password-sha512": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "password", "hashing"],
        "nist": ["IA-5"],
        "desc": "PAM must use a strong password hashing algorithm (SHA-512).",
        "rationale": "Weak hashing algorithms allow faster offline cracking of password hashes.",
        "run_check": "grep -qE '^\\s*password.*pam_unix\\.so.*sha512' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null",
        "run_fix": None,
        "fix_note": "Ensure pam_unix.so includes sha512 in PAM password stack",
    },
    "pam-wheel-su": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["pam", "su", "access-control"],
        "nist": ["AC-3", "AC-6"],
        "desc": "Access to the su command must be restricted to the wheel group.",
        "rationale": "Unrestricted su access allows any user to attempt to become root, increasing brute-force attack surface.",
        "run_check": "grep -qE '^\\s*auth\\s+required\\s+pam_wheel\\.so\\s+use_uid' /etc/pam.d/su",
        "run_fix": "sed -i 's/^#\\(auth.*required.*pam_wheel.so.*use_uid\\)/\\1/' /etc/pam.d/su",
    },
    "password-inactive": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["password", "inactive", "account"],
        "nist": ["AC-2", "IA-5"],
        "desc": "Inactive password lock must be configured to disable unused accounts.",
        "rationale": "Dormant accounts with valid passwords are attractive targets for attackers.",
        "run_check": "useradd -D | grep -q 'INACTIVE=30'",
        "run_fix": "useradd -D -f 30",
    },
    "password-hashing-algorithm": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["password", "hashing", "login-defs"],
        "nist": ["IA-5"],
        "desc": "A strong password hashing algorithm must be configured system-wide.",
        "rationale": "Weak hashing algorithms allow faster offline cracking of password hashes.",
        "run_check": "grep -qE '^\\s*ENCRYPT_METHOD\\s+SHA512' /etc/login.defs",
        "run_fix": "sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs",
    },
    "password-change-past": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["password", "aging", "account"],
        "nist": ["IA-5"],
        "desc": "All user password change dates must be in the past.",
        "rationale": "Future password change dates indicate misconfigured accounts that may bypass password aging policies.",
        "run_check": "awk -F: '{if ($3 > int(systime()/86400)) print $1}' /etc/shadow | head -1 | grep -q . && exit 1 || exit 0",
        "run_fix": None,
        "fix_note": "Investigate and correct accounts with future password change dates",
    },
    "root-only-uid0": {
        "category": "access-control",
        "severity": "high",
        "tags": ["root", "uid", "account"],
        "nist": ["AC-6", "IA-2"],
        "desc": "Root must be the only account with UID 0.",
        "rationale": "Multiple UID 0 accounts make it impossible to attribute root actions to a specific user.",
        "run_check": "awk -F: '($3 == 0 && $1 != \"root\") {found=1} END {exit found ? 1 : 0}' /etc/passwd",
        "run_fix": None,
        "fix_note": "Remove or reassign UID for any non-root accounts with UID 0",
    },
    "root-only-gid0": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["root", "gid", "account"],
        "nist": ["AC-6"],
        "desc": "Root must be the only account with GID 0 as primary group.",
        "rationale": "Additional accounts with GID 0 may gain unintended access to root-owned files.",
        "run_check": "awk -F: '($4 == 0 && $1 != \"root\") {found=1} END {exit found ? 1 : 0}' /etc/passwd",
        "run_fix": None,
        "fix_note": "Change primary group of non-root accounts away from GID 0",
    },
    "root-group-only-gid0": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["root", "group", "account"],
        "nist": ["AC-6"],
        "desc": "The root group must be the only group with GID 0.",
        "rationale": "Multiple GID 0 groups make group-based access controls unreliable.",
        "run_check": "awk -F: '($3 == 0 && $1 != \"root\") {found=1} END {exit found ? 1 : 0}' /etc/group",
        "run_fix": None,
        "fix_note": "Remove or reassign GID for any non-root groups with GID 0",
    },
    "root-access-controlled": {
        "category": "access-control",
        "severity": "high",
        "tags": ["root", "access-control"],
        "nist": ["AC-6"],
        "desc": "Direct root login must be controlled.",
        "rationale": "Uncontrolled root access makes it impossible to maintain accountability for administrative actions.",
        "run_check": "grep -qE '^\\s*[^#]' /etc/securetty 2>/dev/null && exit 0; test ! -f /etc/securetty && exit 0; exit 1",
        "run_fix": None,
        "fix_note": "Configure /etc/securetty to restrict root login to console only",
    },
    "root-path-integrity": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["root", "path", "integrity"],
        "nist": ["CM-6"],
        "desc": "The root PATH must not contain world-writable or group-writable directories.",
        "rationale": "Writable directories in root PATH could allow unprivileged users to place malicious executables that root might inadvertently run.",
        "run_check": "echo \"$PATH\" | tr ':' '\\n' | while read dir; do [ -d \"$dir\" ] && stat -c '%a' \"$dir\" | grep -qE '[2367][2367]$' && exit 1; done; exit 0",
        "run_fix": None,
        "fix_note": "Remove writable directories from root PATH or fix their permissions",
    },
    "root-umask": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["root", "umask"],
        "nist": ["AC-3"],
        "desc": "The root user umask must be configured to 0027 or more restrictive.",
        "rationale": "A permissive root umask allows newly created files to be readable or writable by other users.",
        "run_check": "grep -qE '^\\s*umask\\s+0?[0-2][2-7]7' /root/.bash_profile /root/.bashrc 2>/dev/null",
        "run_fix": None,
        "fix_note": "Set umask 0027 in /root/.bash_profile and /root/.bashrc",
    },
    "nologin-system-accounts": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["accounts", "nologin", "system"],
        "nist": ["AC-2", "CM-6"],
        "desc": "System accounts must not have a valid login shell.",
        "rationale": "System accounts with valid shells could be exploited for interactive access if their passwords are compromised.",
        "run_check": "awk -F: '($3<1000 && $1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\" && $7!~/nologin|false/) {found=1} END {exit found ? 1 : 0}' /etc/passwd",
        "run_fix": None,
        "fix_note": "Set shell to /usr/sbin/nologin for system accounts",
    },
    "accounts-locked-no-shell": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["accounts", "locked", "nologin"],
        "nist": ["AC-2"],
        "desc": "Accounts without a valid login shell must be locked.",
        "rationale": "Unlocked accounts with nologin shells could still be used for non-interactive access.",
        "run_check": "awk -F: '($7 ~ /nologin|false/) {print $1}' /etc/passwd | while read user; do passwd -S \"$user\" 2>/dev/null | grep -qE '^\\S+\\s+L' || exit 1; done; exit 0",
        "run_fix": None,
        "fix_note": "Lock accounts without valid login shells using passwd -l",
    },
    "nologin-not-in-shells": {
        "category": "access-control",
        "severity": "low",
        "tags": ["nologin", "shells"],
        "nist": ["CM-6"],
        "desc": "The nologin shell must not be listed in /etc/shells.",
        "rationale": "Listing nologin in /etc/shells may allow FTP or other services to treat nologin accounts as having valid shells.",
        "run_check": "grep -qE '/nologin$' /etc/shells && exit 1 || exit 0",
        "run_fix": "sed -i '/\\/nologin$/d' /etc/shells",
    },
    "shell-timeout": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["shell", "timeout", "tmout"],
        "nist": ["AC-11"],
        "desc": "A default shell timeout must be configured to terminate idle sessions.",
        "rationale": "Idle sessions left unattended provide an opportunity for unauthorized access.",
        "run_check": "grep -qE '^\\s*(export\\s+)?TMOUT=[0-9]+' /etc/profile /etc/profile.d/*.sh 2>/dev/null",
        "run_fix": 'echo "TMOUT=900; readonly TMOUT; export TMOUT" > /etc/profile.d/tmout.sh',
    },
    "umask-default": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["umask", "defaults"],
        "nist": ["AC-3"],
        "desc": "A restrictive default umask must be configured for all users.",
        "rationale": "A permissive umask allows newly created files to be accessible to other users by default.",
        "run_check": "grep -qE '^\\s*umask\\s+0?[0-2][2-7]7' /etc/profile /etc/bashrc 2>/dev/null",
        "run_fix": None,
        "fix_note": "Set umask 027 in /etc/profile and /etc/bashrc",
    },
    "passwd-shadowed": {
        "category": "access-control",
        "severity": "high",
        "tags": ["passwd", "shadow", "authentication"],
        "nist": ["IA-5"],
        "desc": "All accounts must use shadowed passwords.",
        "rationale": "Unshadowed passwords in /etc/passwd are readable by all users and easily cracked.",
        "run_check": "awk -F: '($2 != \"x\") {found=1} END {exit found ? 1 : 0}' /etc/passwd",
        "run_fix": "pwconv",
    },
    "no-empty-passwords": {
        "category": "access-control",
        "severity": "high",
        "tags": ["passwd", "shadow", "authentication"],
        "nist": ["IA-5"],
        "desc": "No accounts may have empty password fields in /etc/shadow.",
        "rationale": "Empty password fields allow passwordless login, bypassing authentication entirely.",
        "run_check": "awk -F: '($2 == \"\") {found=1} END {exit found ? 1 : 0}' /etc/shadow",
        "run_fix": None,
        "fix_note": "Lock or set passwords for accounts with empty password fields",
    },
    "no-duplicate-uids": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["uid", "accounts", "integrity"],
        "nist": ["AC-2", "IA-2"],
        "desc": "No duplicate UIDs may exist.",
        "rationale": "Duplicate UIDs make it impossible to distinguish between users for access control and auditing.",
        "run_check": "awk -F: '{print $3}' /etc/passwd | sort | uniq -d | head -1 | grep -q . && exit 1 || exit 0",
        "run_fix": None,
        "fix_note": "Resolve duplicate UIDs by assigning unique UIDs to each account",
    },
    "no-duplicate-gids": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["gid", "groups", "integrity"],
        "nist": ["AC-2"],
        "desc": "No duplicate GIDs may exist.",
        "rationale": "Duplicate GIDs make group-based access controls unreliable.",
        "run_check": "awk -F: '{print $3}' /etc/group | sort | uniq -d | head -1 | grep -q . && exit 1 || exit 0",
        "run_fix": None,
        "fix_note": "Resolve duplicate GIDs by assigning unique GIDs to each group",
    },
    "passwd-groups-exist": {
        "category": "access-control",
        "severity": "medium",
        "tags": ["passwd", "groups", "integrity"],
        "nist": ["AC-2"],
        "desc": "All groups referenced in /etc/passwd must exist in /etc/group.",
        "rationale": "Orphaned group references can cause unexpected file access permissions.",
        "run_check": "awk -F: '{print $4}' /etc/passwd | sort -u | while read gid; do getent group \"$gid\" >/dev/null || exit 1; done; exit 0",
        "run_fix": None,
        "fix_note": "Create missing groups or update user primary group assignments",
    },
}

# Rules in the mapping that are NOT in any spec above but exist in sections
# These are already handled by existing rules or the specs above
# Verify completeness in main()


# ═══════════════════════════════════════════════════════════════════════════
#  YAML Generation Functions
# ═══════════════════════════════════════════════════════════════════════════


def _indent(text: str, spaces: int) -> str:
    """Indent every line of text by the given number of spaces."""
    prefix = " " * spaces
    return "\n".join(prefix + line if line.strip() else line for line in text.splitlines())


def _yaml_str(s: str) -> str:
    """Quote a string for safe embedding in YAML.

    Uses single quotes when the string contains backslashes or double
    quotes (since double-quoted YAML interprets backslash escapes).
    """
    if not s:
        return '""'
    if '"' in s or "\\" in s:
        # In single-quoted YAML, only escape is '' for a literal '
        escaped = s.replace("'", "''")
        return f"'{escaped}'"
    return f'"{s}"'


def _nist_list(controls: list[str]) -> str:
    """Format NIST controls as YAML flow-style list."""
    return "[" + ", ".join(f'"{c}"' for c in controls) + "]"


def _tags_list(tags: list[str]) -> str:
    """Format tags as YAML flow-style list."""
    return "[" + ", ".join(tags) + "]"


def _header(
    rule_id: str,
    title: str,
    desc: str,
    rationale: str,
    severity: str,
    category: str,
    tags: list[str],
    cis_section: str,
    cis_level: str,
    cis_type: str,
    nist: list[str],
    depends_on: list[str] | None = None,
) -> str:
    """Generate the common header for a rule YAML file."""
    lines = [
        f"id: {rule_id}",
        f"title: {title}",
        f"description: >",
        f"  {desc}",
        f"rationale: >",
        f"  {rationale}",
        f"severity: {severity}",
        f"category: {category}",
        f"tags: {_tags_list(tags)}",
    ]
    if depends_on:
        dep_str = "[" + ", ".join(depends_on) + "]"
        lines.append("")
        lines.append(f"depends_on: {dep_str}")

    lines.append("")
    lines.append("references:")
    lines.append("  cis:")
    lines.append(
        f'    rhel9_v2: {{ section: "{cis_section}", '
        f'level: "{cis_level}", type: "{cis_type}" }}'
    )
    lines.append(f"  nist_800_53: {_nist_list(nist)}")
    lines.append("")
    lines.append("platforms:")
    lines.append("  - family: rhel")
    lines.append("    min_version: 8")
    lines.append("")

    return "\n".join(lines)


def gen_sysctl_rule(
    rule_id: str,
    cis: dict,
    keys: list[tuple[str, str]],
) -> str:
    """Generate a sysctl rule YAML."""
    title = cis["title"][:100]
    # Generate description from the sysctl keys
    key_names = ", ".join(k for k, _ in keys)
    desc = (
        f"The kernel parameter(s) {key_names} must be configured "
        f"to enforce this network security control."
    )
    rationale = (
        "Improper network kernel parameters can allow network-based attacks "
        "including packet redirection, source routing, and denial of service."
    )
    header = _header(
        rule_id, title, desc, rationale,
        "medium", "network", ["sysctl", "networking", "hardening"],
        cis["section"], cis["level"], cis["type"],
        ["SC-7", "CM-7"],
    )

    if len(keys) == 1:
        key, exp = keys[0]
        impl = textwrap.dedent(f"""\
            implementations:
              - default: true
                check:
                  method: sysctl_value
                  key: "{key}"
                  expected: "{exp}"
                remediation:
                  mechanism: sysctl_set
                  key: "{key}"
                  value: "{exp}"
        """)
    else:
        check_items = "\n".join(
            f'        - method: sysctl_value\n          key: "{k}"\n          expected: "{v}"'
            for k, v in keys
        )
        rem_items = "\n".join(
            f'        - mechanism: sysctl_set\n          key: "{k}"\n          value: "{v}"'
            for k, v in keys
        )
        impl = (
            "implementations:\n"
            "  - default: true\n"
            "    check:\n"
            "      checks:\n"
            f"{check_items}\n"
            "    remediation:\n"
            "      steps:\n"
            f"{rem_items}\n"
        )

    return header + impl


def gen_service_disable_rule(
    rule_id: str,
    cis: dict,
    service_name: str,
) -> str:
    """Generate a service disable rule YAML."""
    title = cis["title"][:100]
    desc = (
        f"The {service_name} service should be stopped and masked "
        f"unless required by the organization."
    )
    rationale = (
        "Unnecessary services increase the attack surface. Disabling "
        "unused services reduces the number of potential entry points."
    )
    header = _header(
        rule_id, title, desc, rationale,
        "medium", "services", ["service", "attack-surface"],
        cis["section"], cis["level"], cis["type"],
        ["CM-7"],
    )
    impl = textwrap.dedent(f"""\
        implementations:
          - default: true
            check:
              method: service_state
              name: "{service_name}"
              state: "stopped"
              enabled: false
            remediation:
              mechanism: service_masked
              name: "{service_name}"
    """)
    return header + impl


def gen_file_permission_rule(
    rule_id: str,
    cis: dict,
    path: str,
    owner: str,
    group: str,
    mode: str,
    category: str = "filesystem",
    severity: str = "medium",
    tags: list[str] | None = None,
    nist: list[str] | None = None,
) -> str:
    """Generate a file permission rule YAML."""
    title = cis["title"][:100]
    if tags is None:
        tags = ["file-permissions"]
        if "shadow" in path or "gshadow" in path:
            tags.append("authentication")
            severity = "high"
        elif "passwd" in path or "group" in path:
            tags.append("authentication")
        elif "cron" in path or "crontab" in path:
            tags.append("cron")
            category = "system"
        elif "ssh" in path:
            tags.append("ssh")
            category = "access-control"
    if nist is None:
        nist = ["AC-3", "MP-2"]

    desc = f"The {path} file must have correct ownership and permissions."
    rationale = (
        f"Incorrect permissions on {path} could allow unauthorized "
        f"access or modification of sensitive system data."
    )
    header = _header(
        rule_id, title, desc, rationale,
        severity, category, tags,
        cis["section"], cis["level"], cis["type"],
        nist,
    )
    impl = textwrap.dedent(f"""\
        implementations:
          - default: true
            check:
              method: file_permission
              path: "{path}"
              owner: "{owner}"
              group: "{group}"
              mode: "{mode}"
            remediation:
              mechanism: file_permissions
              path: "{path}"
              owner: "{owner}"
              group: "{group}"
              mode: "{mode}"
    """)
    return header + impl


def gen_service_enable_rule(
    rule_id: str,
    cis: dict,
    service: str,
    category: str,
    tags: list[str],
    nist: list[str],
) -> str:
    """Generate a service enable rule YAML."""
    title = cis["title"][:100]
    desc = f"The {service} service must be enabled and running."
    rationale = (
        f"The {service} service provides essential system functionality. "
        f"If it is not running, the system may not meet security requirements."
    )
    header = _header(
        rule_id, title, desc, rationale,
        "medium", category, tags,
        cis["section"], cis["level"], cis["type"],
        nist,
    )
    impl = textwrap.dedent(f"""\
        implementations:
          - default: true
            check:
              method: service_state
              name: "{service}"
              state: "running"
              enabled: true
            remediation:
              mechanism: service_enabled
              name: "{service}"
              start: true
    """)
    return header + impl


def gen_package_present_rule(
    rule_id: str,
    cis: dict,
    package: str,
    category: str,
    tags: list[str],
    nist: list[str],
) -> str:
    """Generate a package present rule YAML."""
    title = cis["title"][:100]
    desc = f"The {package} package must be installed."
    rationale = (
        f"The {package} package provides essential functionality. "
        f"Without it, the system cannot meet the corresponding security requirements."
    )
    header = _header(
        rule_id, title, desc, rationale,
        "medium", category, tags,
        cis["section"], cis["level"], cis["type"],
        nist,
    )
    impl = textwrap.dedent(f"""\
        implementations:
          - default: true
            check:
              method: package_state
              name: "{package}"
              state: "present"
            remediation:
              mechanism: package_present
              name: "{package}"
    """)
    return header + impl


def gen_config_value_rule(
    rule_id: str,
    cis: dict,
    spec: dict,
) -> str:
    """Generate a config_value rule YAML."""
    title = cis["title"][:100]
    category = spec.get("category", "access-control")
    severity = spec.get("severity", "medium")
    tags = spec.get("tags", [])
    nist = spec.get("nist", ["CM-6"])
    path = spec["path"]
    key = spec["key"]
    expected = spec["expected"]
    separator = spec.get("separator", " = ")
    comparator = spec.get("comparator")
    reload_svc = spec.get("reload")

    # Handle special case: command-based check
    if spec.get("check_method") == "command":
        return gen_command_rule(rule_id, cis, {
            "category": category,
            "severity": severity,
            "tags": tags,
            "nist": nist,
            "desc": f"The {key} setting must be configured in {path}.",
            "rationale": f"Improper {key} configuration could weaken system security.",
            "run_check": spec["run_check"],
            "run_fix": spec.get("run_fix"),
            "fix_note": spec.get("fix_note"),
        })

    desc = f"The {key} setting in {path} must be properly configured."
    rationale = f"Improper {key} configuration could weaken system security controls."
    header = _header(
        rule_id, title, desc, rationale,
        severity, category, tags,
        cis["section"], cis["level"], cis["type"],
        nist,
    )

    check_lines = [
        "    check:",
        "      method: config_value",
        f'      path: "{path}"',
        f'      key: "{key}"',
        f'      expected: "{expected}"',
    ]
    if comparator:
        check_lines.append(f'      comparator: "{comparator}"')

    rem_lines = [
        "    remediation:",
        "      mechanism: config_set",
        f'      path: "{path}"',
        f'      key: "{key}"',
        f'      value: "{expected}"',
        f'      separator: "{separator}"',
    ]
    if reload_svc:
        rem_lines.append(f'      reload: "{reload_svc}"')

    impl = "implementations:\n  - default: true\n"
    impl += "\n".join(check_lines) + "\n"
    impl += "\n".join(rem_lines) + "\n"

    return header + impl


def gen_audit_event_rule(
    rule_id: str,
    cis: dict,
    spec: dict,
) -> str:
    """Generate an audit event rule YAML."""
    title = cis["title"][:100]
    desc = spec.get("desc", f"Audit events for {rule_id} must be collected.")
    rationale = (
        "Without auditing these events, malicious activity could go "
        "undetected, compromising forensic capabilities."
    )
    grep_pat = spec["grep"]
    audit_rule = spec["rule"]
    persist_file = f"/etc/audit/rules.d/{spec['file']}"

    header = _header(
        rule_id, title, desc, rationale,
        "medium", "audit", ["audit", "auditd"],
        cis["section"], cis["level"], cis["type"],
        ["AU-2", "AU-12"],
        depends_on=["auditd-service-enabled"],
    )

    # Use the first line of the rule for the persist
    first_rule = audit_rule.split("\n")[0]

    impl = textwrap.dedent(f"""\
        implementations:
          - default: true
            check:
              method: command
              run: "auditctl -l 2>/dev/null | grep -qE '{grep_pat}'"
              expected_exit: 0
            remediation:
              mechanism: audit_rule_set
              rule: "{first_rule}"
              persist_file: "{persist_file}"
    """)
    return header + impl


def gen_audit_cmd_rule(
    rule_id: str,
    cis: dict,
    spec: dict,
) -> str:
    """Generate an audit command tracking rule YAML."""
    cmd = spec["cmd"]
    title = cis["title"][:100]
    desc = f"Attempts to use the {cmd} command must be audited."
    rationale = (
        f"The {cmd} command can modify security-relevant settings. "
        f"Auditing its use provides accountability."
    )
    audit_rule = spec["rule"]

    header = _header(
        rule_id, title, desc, rationale,
        "medium", "audit", ["audit", "auditd", cmd],
        cis["section"], cis["level"], cis["type"],
        ["AU-2", "AU-12"],
        depends_on=["auditd-service-enabled"],
    )
    impl = textwrap.dedent(f"""\
        implementations:
          - default: true
            check:
              method: command
              run: "auditctl -l 2>/dev/null | grep -q '{cmd}'"
              expected_exit: 0
            remediation:
              mechanism: audit_rule_set
              rule: "{audit_rule}"
              persist_file: "/etc/audit/rules.d/50-{cmd}.rules"
    """)
    return header + impl


def gen_audit_perm_rule(
    rule_id: str,
    cis: dict,
    spec: dict,
) -> str:
    """Generate an audit permission/ownership rule YAML."""
    title = cis["title"][:100]
    desc = spec["desc"]
    rationale = (
        "Incorrect ownership or permissions on audit files could allow "
        "unauthorized users to tamper with audit evidence."
    )
    header = _header(
        rule_id, title, desc, rationale,
        "medium", "audit", ["audit", "permissions"],
        cis["section"], cis["level"], cis["type"],
        ["AU-9"],
    )
    run_check = spec["run_check"]
    run_fix = spec["run_fix"]
    lines = [
        "implementations:",
        "  - default: true",
        "    check:",
        "      method: command",
        f"      run: {_yaml_str(run_check)}",
        "      expected_exit: 0",
        '      expected_stdout: ""',
        "    remediation:",
        "      mechanism: command_exec",
        f"      run: {_yaml_str(run_fix)}",
    ]
    return header + "\n".join(lines) + "\n"


def gen_ssh_rule(
    rule_id: str,
    cis: dict,
    spec: dict,
) -> str:
    """Generate an SSH configuration rule YAML."""
    title = cis["title"][:100]
    directive = spec["directive"]
    expected = spec.get("expected")
    note = spec.get("note")

    desc = f"The sshd {directive} directive must be properly configured."
    rationale = (
        f"Improper SSH {directive} configuration could weaken "
        f"the security of remote access to the system."
    )
    header = _header(
        rule_id, title, desc, rationale,
        "medium", "access-control", ["ssh", "sshd", "access-control"],
        cis["section"], cis["level"], cis["type"],
        ["AC-17", "SC-8"],
        depends_on=["pkg-openssh-server-present"],
    )

    if expected:
        lines = [
            "implementations:",
            "  - default: true",
            "    check:",
            "      method: sshd_effective_config",
            f'      key: "{directive}"',
            f'      expected: "{expected}"',
            "    remediation:",
            "      mechanism: config_set_dropin",
            '      dir: "/etc/ssh/sshd_config.d"',
            '      file: "99-kensa.conf"',
            f'      key: "{directive}"',
            f'      value: "{expected}"',
        ]
    else:
        cmd = f"sshd -T 2>/dev/null | grep -qi '^{directive.lower()}\\s'"
        lines = [
            "implementations:",
            "  - default: true",
            "    check:",
            "      method: command",
            f"      run: {_yaml_str(cmd)}",
            "      expected_exit: 0",
            "    remediation:",
            "      mechanism: manual",
            f"      note: {_yaml_str(note)}",
        ]

    return header + "\n".join(lines) + "\n"


def gen_command_rule(
    rule_id: str,
    cis: dict,
    spec: dict,
) -> str:
    """Generate a command check rule YAML."""
    title = cis["title"][:100]
    category = spec.get("category", "system")
    severity = spec.get("severity", "medium")
    tags = spec.get("tags", ["security"])
    nist = spec.get("nist", ["CM-6"])
    desc = spec.get("desc", f"{title}.")
    rationale = spec.get("rationale", "This control is required for system security compliance.")

    header = _header(
        rule_id, title, desc, rationale,
        severity, category, tags,
        cis["section"], cis["level"], cis["type"],
        nist,
    )

    run_check = spec["run_check"]
    run_fix = spec.get("run_fix")
    fix_note = spec.get("fix_note")
    expected_stdout = spec.get("expected_stdout")

    # Use _yaml_str to properly quote command strings for YAML
    lines = [
        "implementations:",
        "  - default: true",
        "    check:",
        "      method: command",
        f"      run: {_yaml_str(run_check)}",
        "      expected_exit: 0",
    ]
    if expected_stdout is not None:
        lines.append(f"      expected_stdout: {_yaml_str(expected_stdout)}")

    if run_fix:
        lines.extend([
            "    remediation:",
            "      mechanism: command_exec",
            f"      run: {_yaml_str(run_fix)}",
        ])
    elif fix_note:
        lines.extend([
            "    remediation:",
            "      mechanism: manual",
            f"      note: {_yaml_str(fix_note)}",
        ])
    else:
        lines.extend([
            "    remediation:",
            "      mechanism: manual",
            '      note: "Review and remediate manually"',
        ])

    return header + "\n".join(lines) + "\n"


# ═══════════════════════════════════════════════════════════════════════════
#  Category Resolver
# ═══════════════════════════════════════════════════════════════════════════


def get_category(rule_id: str) -> str:
    """Determine the rules/ subdirectory for a rule ID."""
    if rule_id.startswith("sysctl-"):
        return "network"
    if rule_id.startswith("service-disable-"):
        return "services"
    if rule_id.startswith(("audit-", "auditd-", "aide-")):
        return "audit"
    if rule_id.startswith(("journald-", "rsyslog-")):
        return "logging"
    if rule_id.startswith(("cron", "at-allow")):
        return "system"
    if rule_id.startswith("etc-") or rule_id in (
        "no-world-writable", "home-directories-exist", "home-dotfiles-permissions",
    ):
        return "filesystem"
    if rule_id.startswith(("ssh-", "sshd-", "pam-", "pwquality-", "password-", "package-")):
        return "access-control"
    if rule_id in ("chrony-enabled", "chrony-sources", "postfix-local-only"):
        return "services"
    # Default: access-control covers most remaining rules
    return "access-control"


# ═══════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate missing CIS RHEL 9 rule YAMLs")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created")
    args = parser.parse_args()

    # Load mapping
    mapping = yaml.safe_load(MAPPING_PATH.read_text())

    # Build CIS metadata lookup: rule_id -> {section, title, level, type}
    cis_info: dict[str, dict] = {}
    for section_id, entry in mapping.get("controls", {}).items():
        if isinstance(entry, dict):
            rules = entry.get("rules", [])
            for rule_id in rules:
                cis_info[rule_id] = {
                    "section": str(section_id),
                    "title": entry.get("title", ""),
                    "level": entry.get("level", "L1"),
                    "type": entry.get("type", "Automated"),
                }

    # Find existing rules
    existing = {p.stem for p in RULES_DIR.rglob("*.yml") if p.name != "defaults.yml"}

    # Generate missing rules
    count = 0
    skipped = 0
    errors = []

    for rule_id in sorted(cis_info.keys()):
        if rule_id in existing:
            continue

        cis = cis_info[rule_id]
        content = None

        # Dispatch to the right generator based on specs
        if rule_id in SYSCTL_SPECS:
            content = gen_sysctl_rule(rule_id, cis, SYSCTL_SPECS[rule_id])
        elif rule_id in SERVICE_DISABLE_SPECS:
            content = gen_service_disable_rule(rule_id, cis, SERVICE_DISABLE_SPECS[rule_id])
        elif rule_id in FILE_PERM_SPECS:
            path, owner, group, mode = FILE_PERM_SPECS[rule_id]
            content = gen_file_permission_rule(rule_id, cis, path, owner, group, mode)
        elif rule_id in CRON_PERM_SPECS:
            path, owner, group, mode = CRON_PERM_SPECS[rule_id]
            content = gen_file_permission_rule(
                rule_id, cis, path, owner, group, mode,
                category="system", tags=["file-permissions", "cron"],
                nist=["CM-6"],
            )
        elif rule_id in AUDIT_PERM_SPECS:
            content = gen_audit_perm_rule(rule_id, cis, AUDIT_PERM_SPECS[rule_id])
        elif rule_id in AUDIT_EVENT_SPECS:
            content = gen_audit_event_rule(rule_id, cis, AUDIT_EVENT_SPECS[rule_id])
        elif rule_id in AUDIT_CMD_SPECS:
            content = gen_audit_cmd_rule(rule_id, cis, AUDIT_CMD_SPECS[rule_id])
        elif rule_id in SSH_SPECS:
            content = gen_ssh_rule(rule_id, cis, SSH_SPECS[rule_id])
        elif rule_id in CONFIG_VALUE_SPECS:
            content = gen_config_value_rule(rule_id, cis, CONFIG_VALUE_SPECS[rule_id])
        elif rule_id in SERVICE_ENABLE_SPECS:
            spec = SERVICE_ENABLE_SPECS[rule_id]
            content = gen_service_enable_rule(
                rule_id, cis, spec["service"],
                spec["category"], spec["tags"], spec["nist"],
            )
        elif rule_id in PACKAGE_PRESENT_SPECS:
            spec = PACKAGE_PRESENT_SPECS[rule_id]
            content = gen_package_present_rule(
                rule_id, cis, spec["package"],
                spec["category"], spec["tags"], spec["nist"],
            )
        elif rule_id in COMMAND_SPECS:
            content = gen_command_rule(rule_id, cis, COMMAND_SPECS[rule_id])
        else:
            errors.append(f"No spec for: {rule_id} (CIS {cis['section']})")
            continue

        category = get_category(rule_id)
        path = RULES_DIR / category / f"{rule_id}.yml"

        if args.dry_run:
            print(f"  Would create: {path}")
            count += 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            print(f"  Created: {path}")
            count += 1

    print(f"\n{'Would create' if args.dry_run else 'Created'}: {count} rules")
    if errors:
        print(f"\nMissing specs ({len(errors)}):")
        for err in errors:
            print(f"  - {err}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
