#!/usr/bin/env python3
"""Helper script to map CIS controls to Aegis rules.

Usage:
    python3 scripts/map_cis_controls.py --analyze [--rhel8|--rhel9]
    python3 scripts/map_cis_controls.py --suggest [--rhel8|--rhel9]
    python3 scripts/map_cis_controls.py --generate-yaml [--rhel8|--rhel9]
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Default paths for each benchmark
BENCHMARK_CONFIGS = {
    # CIS benchmarks
    "cis-rhel8": {
        "json": "extracted/cis_rhel8_rules.json",
        "mapping": "mappings/cis/rhel8_v4.0.0.yaml",
        "framework": "cis",
        "id_field": "number",
    },
    "cis-rhel9": {
        "json": "extracted/cis_rhel9_rules.json",
        "mapping": "mappings/cis/rhel9_v2.0.0.yaml",
        "framework": "cis",
        "id_field": "number",
    },
    # STIG benchmarks
    "stig-rhel8": {
        "json": "extracted/stig_rhel8_rules.json",
        "mapping": "mappings/stig/rhel8_v2r6.yaml",
        "framework": "stig",
        "id_field": "vuln_id",
    },
    "stig-rhel9": {
        "json": "extracted/stig_rhel9_rules.json",
        "mapping": "mappings/stig/rhel9_v2r7.yaml",
        "framework": "stig",
        "id_field": "vuln_id",
    },
}

# Backward compatibility aliases
RHEL_CONFIGS = {
    "rhel8": BENCHMARK_CONFIGS["cis-rhel8"],
    "rhel9": BENCHMARK_CONFIGS["cis-rhel9"],
}


def load_controls(path: str, framework: str = "cis") -> list[dict]:
    """Load controls from extracted JSON."""
    with open(path) as f:
        data = json.load(f)
    if framework == "stig":
        return data["rules"]
    return data["recommendations"]


def load_cis_controls(path: str = "extracted/cis_rhel9_rules.json") -> list[dict]:
    """Load CIS controls from extracted JSON (backward compat)."""
    return load_controls(path, "cis")


def load_rules(rules_dir: str = "rules") -> dict[str, dict]:
    """Load all rules and return as dict keyed by rule ID."""
    import yaml

    rules = {}
    for path in Path(rules_dir).rglob("*.yml"):
        try:
            with open(path) as f:
                rule = yaml.safe_load(f)
            if rule and "id" in rule:
                rules[rule["id"]] = {
                    "path": str(path),
                    "title": rule.get("title", ""),
                    "category": rule.get("category", ""),
                }
        except Exception:
            pass
    return rules


def load_current_mapping(path: str = "mappings/cis/rhel9_v2.0.0.yaml") -> dict:
    """Load current mapping to see what's already mapped."""
    import yaml

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        data = {}

    controls = data.get("controls") or {}
    unimplemented = data.get("unimplemented") or {}
    mapped = set(controls.keys())
    unimpl = set(unimplemented.keys())
    return {"controls": controls, "unimplemented": unimplemented, "mapped": mapped, "unimplemented_set": unimpl}


def normalize_title(title: str) -> str:
    """Normalize title for matching."""
    title = title.lower()
    title = re.sub(r"[^a-z0-9\s]", "", title)
    return title


def suggest_rule_for_stig(finding: dict, rules: dict[str, dict], rhel_version: str = "stig-rhel8") -> str | None:
    """Try to find a matching rule for a STIG finding."""
    vuln_id = finding.get("vuln_id", "")
    title = finding.get("title", "").lower()
    rule_version = finding.get("rule_version", "")

    # STIG RHEL 8 V2R6 exact mappings (verified against actual STIG content)
    stig_rhel8_mappings = {
        # FIPS/Crypto
        "V-230223": "fips-mode-enabled",  # FIPS 140-3 systemwide crypto policy
        "V-230231": "login-defs-encrypt-method",  # encrypt stored passwords
        # SSH
        "V-230225": "banner-ssh-dod",  # SSH DOD banner
        "V-230251": "ssh-macs-fips",  # SSH MACs FIPS
        "V-230252": "ssh-ciphers-fips",  # SSH ciphers FIPS
        "V-230330": "ssh-permit-user-environment",  # not allow users override SSH env
        "V-230380": "ssh-permit-empty-passwords",  # not allow blank/null passwords
        "V-244541": "ssh-permit-empty-passwords",  # blank/null passwords password-auth
        "V-251706": "ssh-permit-empty-passwords",  # blank/null passwords
        "V-268322": "ssh-permit-empty-passwords",  # blank/null passwords system-auth
        "V-272482": "ssh-macs-fips",  # SSH client MACs
        "V-272483": "ssh-ciphers-fips",  # SSH client ciphers
        # SELinux
        "V-230282": "selinux-policy-targeted",  # SELinux targeted policy (enables enforcing)
        # Password settings
        "V-230364": "login-defs-pass-min-days",  # 24h/1 day min password life /etc/shadow
        "V-230365": "login-defs-pass-min-days",  # 24h/1 day min for new users
        "V-230366": "login-defs-pass-max-days",  # 60-day max password life
        "V-230367": "login-defs-pass-max-days",  # existing passwords max
        # PAM pwquality
        "V-230357": "pam-pwquality-ucredit",  # uppercase character
        "V-230358": "pam-pwquality-lcredit",  # lowercase character
        "V-230359": "pam-pwquality-dcredit",  # numeric character
        "V-230360": "pam-pwquality-maxclassrepeat",  # max repeating same class
        "V-230361": "pam-pwquality-maxrepeat",  # max repeating characters
        "V-230362": "pam-pwquality-minclass",  # change at least 4 char classes
        "V-230363": "pam-pwquality-difok",  # change at least 8 characters
        "V-230369": "pam-pwquality-minlen",  # min 15 chars
        "V-230370": "pam-pwquality-minlen",  # min 15 chars for new users
        "V-230375": "pam-pwquality-ocredit",  # special character
        "V-230377": "pam-pwquality-dictcheck",  # dictionary check
        # PAM faillock
        "V-230332": "pam-faillock-deny",  # auto lock after 3 attempts
        "V-230333": "pam-faillock-deny",  # auto lock after 3 attempts
        "V-230334": "pam-faillock-fail-interval",  # 15 min interval
        "V-230335": "pam-faillock-fail-interval",  # 15 min interval
        "V-230336": "pam-faillock-unlock-time",  # locked until released
        "V-230337": "pam-faillock-unlock-time",  # locked until released
        "V-230344": "pam-faillock-even-deny-root",  # include root
        "V-230345": "pam-faillock-even-deny-root",  # include root
        "V-230373": "inactive-password-lock",  # disable after 35 days inactive
        # Kernel hardening
        "V-230266": "kexec-load-disabled",  # prevent loading new kernel
        "V-230269": "kernel-dmesg-restrict",  # restrict kernel message buffer
        "V-230270": "kernel-perf-restrict",  # prevent kernel profiling
        "V-230280": "aslr-enabled",  # ASLR
        "V-230545": "kernel-unprivileged-bpf",  # disable bpf from unprivileged
        "V-230546": "kernel-yama-ptrace",  # ptrace restriction
        "V-230548": "user-namespaces-disabled",  # disable user namespaces
        "V-230549": "sysctl-net-ipv4-conf-all-rp-filter",  # reverse path filtering
        # Network sysctl
        "V-230535": "sysctl-net-ipv6-conf-all-accept-redirects",  # IPv6 ICMP redirects
        "V-230536": "sysctl-net-ipv4-conf-all-send-redirects",  # not send ICMP redirects
        "V-230537": "sysctl-net-ipv4-icmp-echo-ignore-broadcasts",  # ignore broadcast echoes
        "V-230538": "sysctl-net-ipv6-conf-all-accept-source-route",  # IPv6 source-routed
        "V-230539": "sysctl-net-ipv6-conf-all-accept-source-route",  # IPv6 source-routed default
        "V-230540": "sysctl-net-ipv6-conf-all-forwarding",  # IPv6 forwarding
        "V-230541": "sysctl-net-ipv6-conf-all-accept-ra",  # IPv6 router advertisements
        "V-230542": "sysctl-net-ipv6-conf-all-accept-ra",  # IPv6 router advertisements default
        "V-230543": "sysctl-net-ipv4-conf-all-accept-redirects",  # IPv4 ICMP redirects
        "V-230544": "sysctl-net-ipv6-conf-all-accept-redirects",  # ignore IPv6 ICMP redirects
        "V-244550": "sysctl-net-ipv4-conf-all-accept-redirects",  # IPv4 ICMP redirects
        "V-244551": "sysctl-net-ipv4-conf-all-accept-source-route",  # IPv4 source-routed
        "V-244552": "sysctl-net-ipv4-conf-all-accept-source-route",  # IPv4 source-routed default
        "V-244553": "sysctl-net-ipv4-conf-all-accept-redirects",  # ignore IPv4 ICMP redirects
        "V-250317": "sysctl-net-ipv4-ip-forward",  # IPv4 forwarding
        # Mount options
        "V-230508": "mount-dev-shm-nodev",  # /dev/shm nodev
        "V-230509": "mount-dev-shm-nosuid",  # /dev/shm nosuid
        "V-230510": "mount-dev-shm-noexec",  # /dev/shm noexec
        "V-230511": "mount-tmp-nodev",  # /tmp nodev
        "V-230512": "mount-tmp-nosuid",  # /tmp nosuid
        "V-230513": "mount-tmp-noexec",  # /tmp noexec
        "V-230520": "mount-var-tmp-nodev",  # /var/tmp nodev
        "V-230521": "mount-var-tmp-nosuid",  # /var/tmp nosuid
        "V-230522": "mount-var-tmp-noexec",  # /var/tmp noexec
        # Kernel modules
        "V-230503": "kmod-disable-usb-storage",  # USB storage
        "V-230507": "kmod-disable-bluetooth",  # Bluetooth
        "V-230499": "kmod-disable-firewire",  # FireWire (IEEE 1394)
        # Ctrl-Alt-Delete
        "V-230529": "ctrl-alt-del-disabled",  # x86 Ctrl-Alt-Del
        "V-230530": "ctrl-alt-del-disabled",  # x86 Ctrl-Alt-Del GUI
        "V-230531": "ctrl-alt-del-disabled",  # systemd Ctrl-Alt-Del burst
        # Sudo
        "V-237641": "su-require-wheel",  # restrict privilege elevation
        "V-237643": "sudo-timeout",  # re-authenticate when using sudo
        # Bootloader
        "V-230234": "single-user-auth",  # UEFI single-user auth
        "V-230235": "single-user-auth",  # BIOS single-user auth
        "V-230236": "single-user-auth",  # rescue mode auth
        "V-244521": "grub-password",  # UEFI unique superuser
        "V-244522": "grub-password",  # BIOS superuser
        "V-244523": "single-user-auth",  # emergency mode auth
        # Package/GPG
        "V-230264": "gpgcheck-enabled",  # verify local packages signed
        "V-230265": "gpgcheck-enabled",  # verify packages digitally signed
        "V-256973": "gpgcheck-enabled",  # crypto verification vendor packages
        # World writable / ownership
        "V-230318": "no-world-writable-files",  # world-writable files
        "V-230319": "no-world-writable-files",  # world-writable dirs
        "V-230243": "sticky-bit-world-writable",  # sticky bit on public dirs
        # Umask/timeout
        "V-230383": "login-defs-umask",  # default permissions umask
        "V-230384": "login-defs-umask",  # umask 077 for users
        "V-257258": "shell-timeout",  # terminate idle sessions
        "V-279929": "shell-timeout",  # exit interactive shell after 10 min
        # Core dumps
        "V-230312": "coredump-restricted",  # core dump backtraces
        "V-230313": "coredump-restricted",  # core dump storage
        "V-230314": "coredump-suid-disabled",  # disable core dumps for SUID
        # Audit
        "V-230386": "auditd-service-enabled",  # audit privileged functions
        "V-230411": "auditd-service-enabled",  # audit package installed
        "V-230404": "audit-user-group-changes",  # audit /etc/shadow
        "V-230405": "audit-user-group-changes",  # audit /etc/passwd
        "V-230406": "audit-user-group-changes",  # audit /etc/group
        "V-230407": "audit-user-group-changes",  # audit /etc/gshadow
        "V-230408": "audit-user-group-changes",  # audit /etc/security/opasswd
        "V-230409": "audit-user-group-changes",  # audit faillock
        "V-230410": "audit-user-group-changes",  # audit lastlog
        "V-230413": "audit-xattr-changes",  # audit setxattr
        "V-230423": "audit-mount-operations",  # mount command
        "V-230424": "audit-mount-operations",  # umount command
        "V-230425": "audit-mount-operations",  # mount syscall
        "V-230438": "audit-kernel-modules",  # init_module/finit_module
        "V-230439": "audit-file-deletion",  # rename/unlink/rmdir
        # Root account
        "V-230534": "accounts-no-uid-zero",  # only root has unrestricted access
    }

    # STIG RHEL 9 V2R7 exact mappings (verified against actual STIG content)
    stig_rhel9_mappings = {
        # FIPS/Crypto
        "V-258230": "fips-mode-enabled",  # enable FIPS mode
        "V-258231": "fips-mode-enabled",  # FIPS 140-3 for stored passwords
        "V-258241": "fips-mode-enabled",  # FIPS 140-3 systemwide crypto policy
        "V-257819": "gpgcheck-enabled",  # crypto verification vendor packages
        "V-257820": "gpgcheck-enabled",  # GPG signature external packages
        "V-257821": "gpgcheck-enabled",  # GPG signature local packages
        "V-257822": "gpgcheck-enabled",  # GPG verification for repos
        # SSH
        "V-257981": "banner-ssh-dod",  # SSH DOD banner
        "V-257984": "ssh-permit-empty-passwords",  # SSHD no blank passwords
        "V-257985": "ssh-disable-root-login",  # no direct root logon via SSH
        "V-257989": "ssh-ciphers-fips",  # SSH server ciphers FIPS
        "V-257991": "ssh-macs-fips",  # SSH server MACs FIPS
        "V-257993": "ssh-permit-user-environment",  # not allow users override SSH env
        "V-258094": "ssh-permit-empty-passwords",  # not allow blank/null passwords
        "V-258120": "ssh-permit-empty-passwords",  # blank/null passwords configured
        "V-270177": "ssh-ciphers-fips",  # SSH client ciphers FIPS
        "V-270178": "ssh-macs-fips",  # SSH client MACs FIPS
        # SELinux
        "V-258079": "selinux-policy-targeted",  # SELinux targeted policy
        # Password settings
        "V-258041": "login-defs-pass-max-days",  # 60-day max for new users
        "V-258042": "login-defs-pass-max-days",  # 60-day max password life
        "V-258104": "login-defs-pass-min-days",  # 24h min for new users
        "V-258105": "login-defs-pass-min-days",  # 24h min password life
        # PAM pwquality
        "V-258102": "pam-pwquality-lcredit",  # lowercase character
        "V-258103": "pam-pwquality-dcredit",  # numeric character
        "V-258107": "pam-pwquality-minlen",  # min 15 chars
        "V-258109": "pam-pwquality-ocredit",  # special character
        "V-258110": "pam-pwquality-dictcheck",  # dictionary check
        "V-258111": "pam-pwquality-ucredit",  # uppercase character
        "V-258112": "pam-pwquality-difok",  # change at least 8 chars
        "V-258113": "pam-pwquality-maxclassrepeat",  # max repeating same class
        "V-258114": "pam-pwquality-maxrepeat",  # max repeating characters
        "V-258115": "pam-pwquality-minclass",  # at least 4 char classes
        # PAM faillock
        "V-258054": "pam-faillock-deny",  # auto lock after 3 attempts
        "V-258055": "pam-faillock-even-deny-root",  # auto lock root
        "V-258056": "pam-faillock-fail-interval",  # 15 min interval
        "V-258057": "pam-faillock-unlock-time",  # locked until released
        "V-258049": "inactive-password-lock",  # disable after 35 days inactive
        # Kernel hardening
        "V-257797": "kernel-dmesg-restrict",  # restrict kernel message buffer
        "V-257798": "kernel-perf-restrict",  # prevent kernel profiling
        "V-257799": "kexec-load-disabled",  # prevent loading new kernel
        "V-257809": "aslr-enabled",  # ASLR
        "V-257810": "kernel-unprivileged-bpf",  # disable bpf from unprivileged
        "V-257811": "kernel-yama-ptrace",  # ptrace restriction
        "V-257816": "user-namespaces-disabled",  # disable user namespaces
        "V-257942": "kernel-unprivileged-bpf",  # hardening for BPF JIT
        # Network sysctl
        "V-257957": "sysctl-net-ipv4-tcp-syncookies",  # TCP syncookies
        "V-257958": "sysctl-net-ipv4-conf-all-accept-redirects",  # ignore IPv4 ICMP redirects
        "V-257959": "sysctl-net-ipv4-conf-all-accept-source-route",  # IPv4 source-routed
        "V-257960": "sysctl-net-ipv4-conf-all-log-martians",  # log martians
        "V-257961": "sysctl-net-ipv4-conf-all-log-martians",  # log martians default
        "V-257962": "sysctl-net-ipv4-conf-all-rp-filter",  # reverse path filtering
        "V-257963": "sysctl-net-ipv4-conf-all-accept-redirects",  # prevent ICMP redirects
        "V-257964": "sysctl-net-ipv4-conf-all-accept-source-route",  # IPv4 source-routed default
        "V-257965": "sysctl-net-ipv4-conf-all-rp-filter",  # rp filter default
        "V-257966": "sysctl-net-ipv4-icmp-echo-ignore-broadcasts",  # ignore broadcast echoes
        "V-257967": "sysctl-net-ipv4-icmp-ignore-bogus-error-responses",  # bogus ICMP
        "V-257968": "sysctl-net-ipv4-conf-all-send-redirects",  # not send ICMP redirects
        "V-257969": "sysctl-net-ipv4-conf-all-accept-redirects",  # not allow ICMP redirects
        "V-257970": "sysctl-net-ipv4-ip-forward",  # IPv4 forwarding
        "V-257971": "sysctl-net-ipv6-conf-all-accept-ra",  # IPv6 router advertisements
        "V-257972": "sysctl-net-ipv6-conf-all-accept-redirects",  # ignore IPv6 ICMP redirects
        "V-257973": "sysctl-net-ipv6-conf-all-accept-source-route",  # IPv6 source-routed
        "V-257974": "sysctl-net-ipv6-conf-all-forwarding",  # IPv6 forwarding
        "V-257975": "sysctl-net-ipv6-conf-all-accept-ra",  # IPv6 router ads default
        "V-257976": "sysctl-net-ipv6-conf-all-accept-redirects",  # prevent IPv6 ICMP redirects
        "V-257977": "sysctl-net-ipv6-conf-all-accept-source-route",  # IPv6 source-routed default
        # Mount options
        "V-257863": "mount-dev-shm-nodev",  # /dev/shm nodev
        "V-257864": "mount-dev-shm-noexec",  # /dev/shm noexec
        "V-257865": "mount-dev-shm-nosuid",  # /dev/shm nosuid
        "V-257866": "mount-tmp-nodev",  # /tmp nodev
        "V-257867": "mount-tmp-noexec",  # /tmp noexec
        "V-257868": "mount-tmp-nosuid",  # /tmp nosuid
        "V-257876": "mount-var-tmp-nodev",  # /var/tmp nodev
        "V-257877": "mount-var-tmp-noexec",  # /var/tmp noexec
        "V-257878": "mount-var-tmp-nosuid",  # /var/tmp nosuid
        # Kernel modules
        "V-258034": "kmod-disable-usb-storage",  # USB storage
        "V-258039": "kmod-disable-bluetooth",  # Bluetooth
        "V-257806": "kmod-disable-firewire",  # FireWire
        "V-257807": "kmod-disable-sctp",  # SCTP
        "V-257808": "kmod-disable-tipc",  # TIPC
        # Ctrl-Alt-Delete
        "V-257784": "ctrl-alt-del-disabled",  # systemd Ctrl-Alt-Del burst
        "V-257785": "ctrl-alt-del-disabled",  # x86 Ctrl-Alt-Del
        "V-258031": "ctrl-alt-del-disabled",  # GUI Ctrl-Alt-Del
        "V-258032": "ctrl-alt-del-disabled",  # prevent override Ctrl-Alt-Del
        # Sudo
        "V-258087": "su-require-wheel",  # restrict privilege elevation
        "V-258088": "su-require-wheel",  # restrict use of su
        "V-258084": "sudo-timeout",  # re-authenticate when using sudo
        # Bootloader
        "V-257787": "grub-password",  # boot loader superuser password
        "V-257789": "single-user-auth",  # unique superuser name single-user
        "V-258128": "single-user-auth",  # require auth emergency mode
        "V-258129": "single-user-auth",  # require auth single-user mode
        # File permissions
        "V-257891": "fs-permissions-etc-group",  # /etc/group mode
        "V-257892": "fs-permissions-etc-group-backup",  # /etc/group- mode
        "V-257893": "fs-permissions-etc-gshadow",  # /etc/gshadow mode
        "V-257894": "fs-permissions-etc-gshadow-backup",  # /etc/gshadow- mode
        "V-257895": "fs-permissions-etc-passwd",  # /etc/passwd mode
        "V-257896": "fs-permissions-etc-passwd-backup",  # /etc/passwd- mode
        "V-257897": "fs-permissions-etc-shadow-backup",  # /etc/shadow- mode
        "V-257934": "fs-permissions-etc-shadow",  # /etc/shadow mode
        # World writable / ownership
        "V-257928": "no-world-writable-files",  # world-writable dirs
        "V-257929": "sticky-bit-world-writable",  # sticky bit on public dirs
        "V-257930": "no-ungrouped-files",  # files must have valid group
        "V-257931": "no-unowned-files",  # files must have valid owner
        # Umask/timeout
        "V-258044": "login-defs-umask",  # umask 077 for users
        "V-258068": "shell-timeout",  # exit interactive shell after 10 min
        "V-258077": "shell-timeout",  # terminate idle sessions
        # Core dumps
        "V-257812": "coredump-restricted",  # disable core dump backtraces
        "V-257813": "coredump-restricted",  # disable storing core dumps
        "V-257814": "coredump-suid-disabled",  # disable core dumps for users
        "V-257815": "coredump-suid-disabled",  # disable acquiring core dumps
        # Audit
        "V-258151": "auditd-service-enabled",  # audit package installed
        "V-258152": "auditd-service-enabled",  # audit service enabled
        "V-258217": "audit-user-group-changes",  # audit /etc/shadow
        "V-258218": "audit-user-group-changes",  # audit /etc/passwd
        "V-258219": "audit-user-group-changes",  # audit /etc/group
        "V-258220": "audit-user-group-changes",  # audit /etc/gshadow
        "V-258177": "audit-permission-changes",  # audit chmod
        "V-258178": "audit-chown-changes",  # audit chown
        "V-258179": "audit-xattr-changes",  # audit setxattr
        "V-258187": "audit-file-deletion",  # audit rename/unlink/rmdir
        "V-258189": "audit-kernel-modules",  # audit delete_module
        "V-258190": "audit-kernel-modules",  # audit init_module/finit_module
        "V-258180": "audit-mount-operations",  # audit umount
        "V-258210": "audit-mount-operations",  # audit mount command
        # Root account
        "V-258059": "accounts-no-uid-zero",  # only root has unrestricted access
        "V-258046": "nologin-system-accounts",  # system accounts no interactive shell
    }

    # Select the right mappings based on version
    if rhel_version == "stig-rhel9":
        stig_mappings = stig_rhel9_mappings
    else:
        stig_mappings = stig_rhel8_mappings

    if vuln_id in stig_mappings:
        rule_id = stig_mappings[vuln_id]
        if rule_id in rules:
            return rule_id

    # Fallback to pattern matching
    pattern_mappings = {
        r"ssh.*root.*login": "ssh-disable-root-login",
        r"ssh.*banner": "ssh-banner",
        r"selinux.*enforc": "selinux-enforcing",
        r"selinux.*targeted": "selinux-policy-targeted",
        r"fips": "fips-mode-enabled",
        r"auditd.*enabled": "auditd-service-enabled",
        r"aslr|randomize_va_space": "aslr-enabled",
        r"ptrace_scope": "kernel-yama-ptrace",
        r"dmesg_restrict": "kernel-dmesg-restrict",
        r"kexec": "kexec-load-disabled",
    }

    for pattern, rule_id in pattern_mappings.items():
        if re.search(pattern, title, re.IGNORECASE):
            if rule_id in rules:
                return rule_id

    return None


def suggest_rule_for_control(control: dict, rules: dict[str, dict], rhel_version: str = "rhel9") -> str | None:
    """Try to find a matching rule for a CIS control."""
    title = control.get("title", "").lower()
    num = control.get("number", "")

    # Handle STIG format
    if "vuln_id" in control:
        return suggest_rule_for_stig(control, rules, rhel_version)

    # RHEL 8 specific mappings (CIS RHEL 8 v4.0.0)
    rhel8_mappings = {
        # Kernel modules (1.1.1.x) - RHEL 8 numbering
        "1.1.1.1": "kmod-disable-cramfs",
        "1.1.1.2": "kmod-disable-freevxfs",
        "1.1.1.3": "kmod-disable-hfs",
        "1.1.1.4": "kmod-disable-hfsplus",
        "1.1.1.5": "kmod-disable-jffs2",
        # 1.1.1.6 = overlay - no rule yet
        "1.1.1.7": "kmod-disable-squashfs",
        "1.1.1.8": "kmod-disable-udf",
        "1.1.1.9": "kmod-disable-firewire",
        "1.1.1.10": "kmod-disable-usb-storage",
        # Mount options
        "1.1.2.1.2": "mount-tmp-nodev",
        "1.1.2.1.3": "mount-tmp-nosuid",
        "1.1.2.1.4": "mount-tmp-noexec",
        "1.1.2.2.2": "mount-dev-shm-nodev",
        "1.1.2.2.3": "mount-dev-shm-nosuid",
        "1.1.2.2.4": "mount-dev-shm-noexec",
        "1.1.2.3.2": "mount-home-nodev",
        "1.1.2.3.3": "mount-home-nosuid",
        "1.1.2.5.2": "mount-var-tmp-nodev",
        "1.1.2.5.3": "mount-var-tmp-nosuid",
        "1.1.2.5.4": "mount-var-tmp-noexec",
        # Package management
        "1.2.1": "gpgcheck-enabled",
        "1.2.2": "repo-gpgcheck-enabled",
        # SELinux
        "1.3.1.3": "selinux-policy-targeted",
        "1.3.1.4": "selinux-enforcing",
        # Bootloader
        "1.4.1": "grub-password",
        "1.4.2": "grub-config-permissions",
        "1.4.3": "grub-user-cfg-permissions",
        # Process hardening (RHEL 8 numbering)
        "1.5.4": "coredump-suid-disabled",
        "1.5.5": "kernel-dmesg-restrict",
        "1.5.6": "kernel-perf-restrict",
        "1.5.7": "kernel-yama-ptrace",
        "1.5.8": "aslr-enabled",
        "1.5.9": "coredump-restricted",
        "1.5.10": "coredump-suid-disabled",
        # Crypto policy
        "1.6.1": "crypto-policy-no-weak",
        # Banners (RHEL 8 numbering)
        "1.7.1": "banner-dod-consent",
        "1.7.2": "banner-ssh-dod",
        "1.7.4": "motd-permissions",
        "1.7.5": "issue-permissions",
        "1.7.6": "issue-net-permissions",
        # Network kernel modules (Chapter 3)
        "3.1.1": "kmod-disable-bluetooth",
        "3.1.2": "kmod-disable-bluetooth",
        "3.2.1": "kmod-disable-dccp",
        "3.2.2": "kmod-disable-tipc",
        "3.2.3": "kmod-disable-rds",
        "3.2.4": "kmod-disable-sctp",
        # Network params (3.3.x)
        "3.3.1": "sysctl-net-ipv4-ip-forward",
        "3.3.2": "sysctl-net-ipv4-conf-all-send-redirects",
        "3.3.3": "sysctl-net-ipv4-conf-all-accept-source-route",
        "3.3.4": "sysctl-net-ipv4-conf-all-accept-redirects",
        "3.3.5": "sysctl-net-ipv4-conf-all-secure-redirects",
        "3.3.6": "sysctl-net-ipv4-conf-all-log-martians",
        "3.3.7": "sysctl-net-ipv4-icmp-echo-ignore-broadcasts",
        "3.3.8": "sysctl-net-ipv4-icmp-ignore-bogus-error-responses",
        "3.3.9": "sysctl-net-ipv4-conf-all-rp-filter",
        "3.3.10": "sysctl-net-ipv4-tcp-syncookies",
        "3.3.11": "sysctl-net-ipv6-conf-all-accept-ra",
        # SSH (5.1.x)
        "5.1.2": "ssh-config-permissions",
        "5.1.3": "ssh-private-key-permissions",
        "5.1.4": "ssh-public-key-permissions",
        "5.1.5": "ssh-access-control",
        "5.1.6": "ssh-banner",
        "5.1.7": "ssh-ciphers-fips",
        "5.1.8": "ssh-kex-fips",
        "5.1.9": "ssh-macs-fips",
        "5.1.10": "ssh-max-auth-tries",
        "5.1.11": "ssh-max-startups",
        "5.1.12": "ssh-max-sessions",
        "5.1.13": "ssh-login-grace-time",
        "5.1.14": "ssh-client-alive-interval",
        "5.1.15": "ssh-client-alive-interval",
        "5.1.17": "ssh-permit-empty-passwords",
        "5.1.18": "ssh-hostbased-authentication",
        "5.1.19": "ssh-permit-user-environment",
        "5.1.20": "ssh-ignore-rhosts",
        "5.1.21": "ssh-disable-forwarding",
        "5.1.22": "ssh-disable-root-login",
        # Sudo (5.2.x)
        "5.2.2": "sudo-use-pty",
        "5.2.3": "sudo-logfile",
        "5.2.5": "sudo-timeout",
        "5.2.6": "su-require-wheel",
        # PAM pwquality (5.3.3.2.x)
        "5.3.3.2.1": "pam-pwquality-minlen",
        "5.3.3.2.2": "pam-pwquality-minclass",
        "5.3.3.2.3": "pam-pwquality-dcredit",
        "5.3.3.2.4": "pam-pwquality-ucredit",
        "5.3.3.2.5": "pam-pwquality-lcredit",
        "5.3.3.2.6": "pam-pwquality-ocredit",
        "5.3.3.2.7": "pam-pwquality-dictcheck",
        "5.3.3.3.1": "password-remember",
        "5.3.3.3.2": "pam-pwquality-difok",
        "5.3.3.4.1": "pam-faillock-deny",
        "5.3.3.4.2": "pam-faillock-unlock-time",
        "5.3.3.4.3": "pam-faillock-fail-interval",
        "5.3.3.4.4": "pam-faillock-even-deny-root",
        # Login defs (5.4.1.x)
        "5.4.1.1": "login-defs-pass-max-days",
        "5.4.1.2": "login-defs-pass-min-days",
        "5.4.1.3": "login-defs-pass-warn-age",
        "5.4.1.4": "inactive-password-lock",
        "5.4.1.5": "nologin-system-accounts",
        "5.4.1.6": "default-group-root",
        "5.4.2.1": "login-defs-umask",
        "5.4.2.4": "shell-timeout",
        "5.4.3.1": "accounts-no-uid-zero",
        "5.4.3.2": "root-gid",
        "5.4.3.3": "root-path-integrity",
        # Audit (6.3.x)
        "6.3.1.4": "auditd-service-enabled",
        "6.3.3.4": "audit-time-change",
        "6.3.3.6": "audit-user-group-changes",
        "6.3.3.7": "audit-network-changes",
        "6.3.3.8": "audit-permission-changes",
        "6.3.3.10": "audit-login-logout",
        "6.3.3.11": "audit-session-initiation",
        "6.3.3.12": "audit-unsuccessful-access",
        "6.3.3.13": "audit-unsuccessful-perm",
        "6.3.3.19": "audit-kernel-modules",
        "6.3.3.20": "audit-chown-changes",
        "6.3.3.21": "audit-xattr-changes",
        # File permissions (7.x)
        "7.1.1": "fs-permissions-etc-passwd",
        "7.1.2": "fs-permissions-etc-passwd-backup",
        "7.1.3": "fs-permissions-etc-group",
        "7.1.4": "fs-permissions-etc-group-backup",
        "7.1.5": "fs-permissions-etc-shadow",
        "7.1.6": "fs-permissions-etc-shadow-backup",
        "7.1.7": "fs-permissions-etc-gshadow",
        "7.1.8": "fs-permissions-etc-gshadow-backup",
        "7.1.11": "no-world-writable-files",
        "7.1.12": "no-unowned-files",
        "7.1.13": "no-ungrouped-files",
        "7.2.4": "audit-suid-files",
        "7.2.5": "audit-sgid-files",
    }

    # RHEL 9 specific mappings (CIS RHEL 9 v2.0.0)
    rhel9_mappings = {
        # Kernel modules (different numbering than RHEL 8)
        "1.1.1.8": "kmod-disable-usb-storage",
        # Mount options - only map those we have rules for
        "1.1.2.1.2": "mount-tmp-nodev",
        "1.1.2.1.3": "mount-tmp-nosuid",
        "1.1.2.1.4": "mount-tmp-noexec",
        "1.1.2.2.2": "mount-dev-shm-nodev",
        "1.1.2.2.3": "mount-dev-shm-nosuid",
        "1.1.2.2.4": "mount-dev-shm-noexec",
        "1.1.2.3.2": "mount-home-nodev",
        "1.1.2.3.3": "mount-home-nosuid",
        "1.1.2.5.2": "mount-var-tmp-nodev",
        "1.1.2.5.3": "mount-var-tmp-nosuid",
        "1.1.2.5.4": "mount-var-tmp-noexec",
        # Package management
        "1.2.1.2": "gpgcheck-enabled",
        "1.2.1.3": "repo-gpgcheck-enabled",
        "1.2.1.4": "localpkg-gpgcheck-enabled",
        # SELinux
        "1.3.1.3": "selinux-policy-targeted",
        "1.3.1.5": "selinux-enforcing",
        # Bootloader
        "1.4.1": "grub-password",
        "1.4.2": "grub-config-permissions",
        # Process hardening
        "1.5.1": "aslr-enabled",
        "1.5.2": "kernel-yama-ptrace",
        "1.5.3": "coredump-restricted",
        "1.5.4": "coredump-suid-disabled",
        # Crypto policy
        "1.6.1": "crypto-policy-no-weak",
        "1.6.2": "crypto-policy-fips",
        # Banners
        "1.7.1": "banner-dod-consent",
        "1.7.4": "motd-permissions",
        "1.7.5": "issue-permissions",
        "1.7.6": "issue-net-permissions",
        # Network kernel modules
        "3.1.3": "kmod-disable-bluetooth",
        "3.2.1": "kmod-disable-dccp",
        "3.2.2": "kmod-disable-tipc",
        "3.2.3": "kmod-disable-rds",
        "3.2.4": "kmod-disable-sctp",
        # SSH
        "5.1.20": "ssh-disable-root-login",
        "5.1.21": "ssh-permit-user-environment",
        # Sudo
        "5.2.2": "sudo-use-pty",
        "5.2.3": "sudo-logfile",
        "5.2.6": "sudo-timeout",
        "5.2.7": "su-require-wheel",
        # PAM - pwquality
        "5.3.3.2.1": "pam-pwquality-minlen",
        "5.3.3.2.2": "pam-pwquality-minclass",
        "5.3.3.2.3": "pam-pwquality-dcredit",
        "5.3.3.2.4": "pam-pwquality-ucredit",
        "5.3.3.2.5": "pam-pwquality-lcredit",
        "5.3.3.2.6": "pam-pwquality-ocredit",
        "5.3.3.2.7": "pam-pwquality-dictcheck",
        "5.3.3.3.1": "password-remember",
        "5.3.3.3.2": "pam-pwquality-difok",
        "5.3.3.4.1": "pam-faillock-deny",
        "5.3.3.4.2": "pam-faillock-unlock-time",
        "5.3.3.4.3": "pam-faillock-fail-interval",
        "5.3.3.4.4": "pam-faillock-even-deny-root",
        # Login defs
        "5.4.1.1": "login-defs-pass-max-days",
        "5.4.1.2": "login-defs-pass-min-days",
        "5.4.1.3": "login-defs-pass-warn-age",
        "5.4.1.4": "inactive-password-lock",
        "5.4.1.5": "nologin-system-accounts",
        "5.4.1.6": "default-group-root",
        "5.4.2.1": "login-defs-umask",
        "5.4.2.4": "shell-timeout",
        # Root account
        "5.4.3.1": "accounts-no-uid-zero",
        "5.4.3.2": "root-gid",
        "5.4.3.3": "root-path-integrity",
        # Audit rules (chapter 6.3.3)
        "6.3.3.4": "audit-time-change",
        "6.3.3.6": "audit-user-group-changes",
        "6.3.3.7": "audit-network-changes",
        "6.3.3.8": "audit-permission-changes",
        "6.3.3.10": "audit-login-logout",
        "6.3.3.11": "audit-session-initiation",
        "6.3.3.12": "audit-unsuccessful-access",
        "6.3.3.13": "audit-unsuccessful-perm",
        "6.3.3.19": "audit-kernel-modules",
        "6.3.3.20": "audit-chown-changes",
        "6.3.3.21": "audit-xattr-changes",
        # File permissions (chapter 7)
        "7.1.1": "fs-permissions-etc-passwd",
        "7.1.2": "fs-permissions-etc-passwd-backup",
        "7.1.3": "fs-permissions-etc-group",
        "7.1.4": "fs-permissions-etc-group-backup",
        "7.1.5": "fs-permissions-etc-shadow",
        "7.1.6": "fs-permissions-etc-shadow-backup",
        "7.1.7": "fs-permissions-etc-gshadow",
        "7.1.8": "fs-permissions-etc-gshadow-backup",
        "7.1.11": "no-world-writable-files",
        "7.1.12": "no-unowned-files",
        "7.1.13": "no-ungrouped-files",
        "7.2.4": "audit-suid-files",
        "7.2.5": "audit-sgid-files",
    }

    # Select mappings based on RHEL version
    exact_mappings = rhel8_mappings if rhel_version == "rhel8" else rhel9_mappings

    if num in exact_mappings:
        rule_id = exact_mappings[num]
        if rule_id in rules:
            return rule_id

    # Fallback to pattern matching for controls not in exact list
    keywords_to_rules = {
        "cramfs": "kmod-disable-cramfs",
        "freevxfs": "kmod-disable-freevxfs",
        r"\bhfs\b(?!plus)": "kmod-disable-hfs",
        "hfsplus": "kmod-disable-hfsplus",
        "squashfs": "kmod-disable-squashfs",
        r"\budf\b": "kmod-disable-udf",
        "firewire": "kmod-disable-firewire",
        r"ip.forward": "sysctl-net-ipv4-ip-forward",
        r"ipv6.forward": "sysctl-net-ipv6-conf-all-forwarding",
        r"packet.redirect.send": "sysctl-net-ipv4-conf-all-send-redirects",
        r"icmp.redirect.*accept": "sysctl-net-ipv4-conf-all-accept-redirects",
        r"broadcast.icmp": "sysctl-net-ipv4-icmp-echo-ignore-broadcasts",
        r"bogus.icmp": "sysctl-net-ipv4-icmp-ignore-bogus-error-responses",
        r"martian": "sysctl-net-ipv4-conf-all-log-martians",
        r"source.routed": "sysctl-net-ipv4-conf-all-accept-source-route",
        r"syn.cookies": "sysctl-net-ipv4-tcp-syncookies",
        r"reverse.path": "sysctl-net-ipv4-conf-all-rp-filter",
        r"ipv6.router.advertisement": "sysctl-net-ipv6-conf-all-accept-ra",
        r"auditd.*(installed|enabled)": "auditd-service-enabled",
        r"aide.*installed": "aide-installed",
        r"single.user.*auth": "single-user-auth",
        r"ctrl.alt.del": "ctrl-alt-del-disabled",
        r"kernel.dmesg": "kernel-dmesg-restrict",
        r"kernel.kexec": "kexec-load-disabled",
        r"unprivileged.bpf": "kernel-unprivileged-bpf",
        r"user.namespace": "user-namespaces-disabled",
        r"sticky.bit": "sticky-bit-world-writable",
        r"fips.mode": "fips-mode-enabled",
    }

    for pattern, rule_id in keywords_to_rules.items():
        if re.search(pattern, title, re.IGNORECASE):
            if rule_id in rules:
                return rule_id

    return None


def analyze_controls(benchmark: str = "cis-rhel9"):
    """Analyze all controls and show mapping status."""
    # Support old-style version strings
    if benchmark in RHEL_CONFIGS:
        config = RHEL_CONFIGS[benchmark]
        benchmark = f"cis-{benchmark}"
    else:
        config = BENCHMARK_CONFIGS.get(benchmark, BENCHMARK_CONFIGS["cis-rhel9"])

    framework = config.get("framework", "cis")
    id_field = config.get("id_field", "number")

    controls = load_controls(config["json"], framework)
    rules = load_rules()
    mapping = load_current_mapping(config["mapping"])

    print(f"{benchmark.upper()} controls: {len(controls)}")
    print(f"Total Aegis rules: {len(rules)}")
    print(f"Currently mapped: {len(mapping['mapped'])}")
    print(f"Currently unimplemented: {len(mapping['unimplemented_set'])}")
    print()

    if framework == "stig":
        # STIG: Group by severity
        by_severity: dict[str, list] = {}
        for control in controls:
            severity = control.get("severity", "Unknown")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(control)

        for severity in ["CAT I", "CAT II", "CAT III"]:
            if severity not in by_severity:
                continue
            controls_in_sev = by_severity[severity]
            mapped = sum(1 for c in controls_in_sev if c.get(id_field) in mapping["mapped"])
            unimpl = sum(1 for c in controls_in_sev if c.get(id_field) in mapping["unimplemented_set"])
            unmapped = len(controls_in_sev) - mapped - unimpl
            print(f"{severity}: {len(controls_in_sev)} controls, {mapped} mapped, {unimpl} skipped, {unmapped} need mapping")
    else:
        # CIS: Group by chapter
        by_chapter: dict[str, list] = {}
        for control in controls:
            num = control.get(id_field, "0")
            chapter = num.split(".")[0]
            if chapter not in by_chapter:
                by_chapter[chapter] = []
            by_chapter[chapter].append(control)

        for chapter in sorted(by_chapter.keys(), key=lambda x: int(x) if x.isdigit() else 0):
            controls_in_chapter = by_chapter[chapter]
            mapped = sum(1 for c in controls_in_chapter if c.get(id_field) in mapping["mapped"])
            unimpl = sum(1 for c in controls_in_chapter if c.get(id_field) in mapping["unimplemented_set"])
            unmapped = len(controls_in_chapter) - mapped - unimpl
            print(f"Chapter {chapter}: {len(controls_in_chapter)} controls, {mapped} mapped, {unimpl} skipped, {unmapped} need mapping")


def suggest_mappings(benchmark: str = "cis-rhel9"):
    """Suggest mappings for unmapped controls."""
    # Support old-style version strings for backward compat
    if benchmark in RHEL_CONFIGS:
        config = RHEL_CONFIGS[benchmark]
        benchmark = f"cis-{benchmark}"
    else:
        config = BENCHMARK_CONFIGS.get(benchmark, BENCHMARK_CONFIGS["cis-rhel9"])

    framework = config.get("framework", "cis")
    id_field = config.get("id_field", "number")

    controls = load_controls(config["json"], framework)
    rules = load_rules()
    mapping = load_current_mapping(config["mapping"])

    accounted = mapping["mapped"] | mapping["unimplemented_set"]
    unmapped = [c for c in controls if c.get(id_field) not in accounted]

    print(f"Unmapped controls: {len(unmapped)}\n")

    can_map = []
    cannot_map = []

    for control in unmapped:
        suggested = suggest_rule_for_control(control, rules, benchmark)
        if suggested:
            can_map.append((control, suggested))
        else:
            cannot_map.append(control)

    print(f"Can auto-map: {len(can_map)}")
    print(f"Need manual review: {len(cannot_map)}\n")

    if can_map:
        print("=== Suggested mappings ===")
        for control, rule_id in can_map[:30]:
            ctrl_id = control.get(id_field, control.get("number", "?"))
            print(f"  {ctrl_id}: {control['title'][:50]}...")
            print(f"    -> {rule_id}")
        if len(can_map) > 30:
            print(f"  ... and {len(can_map) - 30} more")

    print()
    if cannot_map:
        print("=== Need manual review ===")
        for control in cannot_map[:20]:
            ctrl_id = control.get(id_field, control.get("number", "?"))
            print(f"  {ctrl_id}: {control['title']}")
        if len(cannot_map) > 20:
            print(f"  ... and {len(cannot_map) - 20} more")


def generate_yaml(benchmark: str = "cis-rhel9"):
    """Generate YAML for unmapped controls."""
    # Support old-style version strings for backward compat
    if benchmark in RHEL_CONFIGS:
        config = RHEL_CONFIGS[benchmark]
        benchmark = f"cis-{benchmark}"
    else:
        config = BENCHMARK_CONFIGS.get(benchmark, BENCHMARK_CONFIGS["cis-rhel9"])

    framework = config.get("framework", "cis")
    id_field = config.get("id_field", "number")

    controls = load_controls(config["json"], framework)
    rules = load_rules()
    mapping = load_current_mapping(config["mapping"])

    accounted = mapping["mapped"] | mapping["unimplemented_set"]
    unmapped = [c for c in controls if c.get(id_field) not in accounted]

    # Group by what we can do
    controls_yaml = []
    unimpl_yaml = []

    for control in unmapped:
        suggested = suggest_rule_for_control(control, rules, benchmark)
        ctrl_id = control.get(id_field, control.get("number", "?"))
        title = control["title"].replace('"', '\\"')  # Escape quotes

        if framework == "stig":
            # STIG format
            severity = control.get("severity", "CAT II")
            if suggested:
                controls_yaml.append(
                    f'  "{ctrl_id}":\n'
                    f'    rules:\n'
                    f'      - {suggested}\n'
                    f'    severity: "{severity}"\n'
                    f'    title: "{title}"\n'
                )
            else:
                reason = "Needs rule implementation"
                unimpl_yaml.append(
                    f'  "{ctrl_id}":\n'
                    f'    title: "{title}"\n'
                    f'    severity: "{severity}"\n'
                    f'    reason: "{reason}"\n'
                )
        else:
            # CIS format
            control_type = control.get("type", "Automated")
            level = control.get("level", "L1")
            if suggested:
                controls_yaml.append(
                    f'  "{ctrl_id}":\n'
                    f'    rules:\n'
                    f'      - {suggested}\n'
                    f'    level: {level}\n'
                    f'    type: {control_type}\n'
                    f'    title: "{title}"\n'
                )
            else:
                # Mark as unimplemented - needs rule creation or is manual
                reason = "Manual check - requires human verification" if control_type == "Manual" else "Needs rule implementation"
                unimpl_yaml.append(
                    f'  "{ctrl_id}":\n'
                    f'    title: "{title}"\n'
                    f'    reason: "{reason}"\n'
                    f'    type: {control_type}\n'
                )

    print("# === Add to controls: ===")
    print("".join(controls_yaml))
    print()
    print("# === Add to unimplemented: ===")
    print("".join(unimpl_yaml))


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: map_cis_controls.py [--analyze|--suggest|--generate-yaml] [--cis-rhel8|--cis-rhel9|--stig-rhel8|--stig-rhel9]")
        print("       (Legacy: --rhel8|--rhel9 for CIS benchmarks)")
        sys.exit(1)

    # Parse benchmark flag
    benchmark = "cis-rhel9"  # default
    if "--stig-rhel8" in sys.argv:
        benchmark = "stig-rhel8"
    elif "--stig-rhel9" in sys.argv:
        benchmark = "stig-rhel9"
    elif "--cis-rhel8" in sys.argv or "--rhel8" in sys.argv:
        benchmark = "cis-rhel8"
    elif "--cis-rhel9" in sys.argv or "--rhel9" in sys.argv:
        benchmark = "cis-rhel9"

    if "--analyze" in sys.argv:
        analyze_controls(benchmark)
    elif "--suggest" in sys.argv:
        suggest_mappings(benchmark)
    elif "--generate-yaml" in sys.argv:
        generate_yaml(benchmark)
    else:
        print(f"Unknown option. Use --analyze, --suggest, or --generate-yaml")
        sys.exit(1)
