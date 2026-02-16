#!/usr/bin/env python3
"""Gap analysis between AEGIS and OpenSCAP scan results.

Compares AEGIS JSON results with OpenSCAP XML results to identify:
1. Result mismatches (different pass/fail outcomes)
2. Coverage gaps (rules in one tool but not the other)
3. Agreement statistics

Usage:
    python3 scripts/gap_analysis.py \
        --aegis results/aegis-results.json \
        --openscap results/openscap-results.xml \
        --output CIS_RHEL9_GAP_ANALYSIS.md
"""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# XCCDF namespace
NS = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}


@dataclass
class RuleResult:
    """Result for a single rule."""

    rule_id: str
    title: str
    passed: bool
    detail: str = ""
    section: str = ""  # CIS section number


def parse_openscap_xml(xml_path: str) -> dict[str, RuleResult]:
    """Parse OpenSCAP XCCDF results XML.

    Returns dict mapping rule_id (short form) to RuleResult.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    results = {}

    # Find TestResult element
    for test_result in root.findall(".//xccdf:TestResult", NS):
        for rule_result in test_result.findall("xccdf:rule-result", NS):
            idref = rule_result.get("idref", "")
            # Extract short rule ID from full XCCDF ID
            # xccdf_org.ssgproject.content_rule_sshd_disable_root_login -> sshd_disable_root_login
            short_id = idref.replace("xccdf_org.ssgproject.content_rule_", "")

            result_elem = rule_result.find("xccdf:result", NS)
            result_text = result_elem.text if result_elem is not None else "unknown"

            # Get title from the Rule definition
            title = ""

            # Map result to passed boolean
            if result_text == "pass":
                passed = True
            elif result_text == "fail":
                passed = False
            elif result_text in ("notapplicable", "notselected", "notchecked"):
                continue  # Skip non-applicable rules
            else:
                continue

            results[short_id] = RuleResult(
                rule_id=short_id,
                title=title,
                passed=passed,
                detail=result_text,
            )

    # Try to get titles from Rule definitions
    for rule in root.findall(".//xccdf:Rule", NS):
        rule_id = rule.get("id", "").replace("xccdf_org.ssgproject.content_rule_", "")
        if rule_id in results:
            title_elem = rule.find("xccdf:title", NS)
            if title_elem is not None and title_elem.text:
                results[rule_id].title = title_elem.text

    return results


def parse_aegis_json(json_path: str) -> dict[str, RuleResult]:
    """Parse AEGIS JSON results.

    Returns dict mapping rule_id to RuleResult.
    """
    with open(json_path) as f:
        data = json.load(f)

    results = {}

    # Handle both single-host and multi-host formats
    hosts = data.get("hosts", [data]) if "hosts" in data else [data]

    for host in hosts:
        for rule in host.get("results", []):
            rule_id = rule.get("rule_id", "")
            if rule.get("skipped"):
                continue

            results[rule_id] = RuleResult(
                rule_id=rule_id,
                title=rule.get("title", ""),
                passed=rule.get("passed", False),
                detail=rule.get("detail", ""),
                section=rule.get("framework_section", ""),
            )

    return results


# Mapping from AEGIS rule IDs to OpenSCAP rule IDs
# This covers common naming differences
AEGIS_TO_OPENSCAP = {
    # Kernel modules
    "kmod-disable-cramfs": "kernel_module_cramfs_disabled",
    "kmod-disable-freevxfs": "kernel_module_freevxfs_disabled",
    "kmod-disable-hfs": "kernel_module_hfs_disabled",
    "kmod-disable-hfsplus": "kernel_module_hfsplus_disabled",
    "kmod-disable-squashfs": "kernel_module_squashfs_disabled",
    "kmod-disable-udf": "kernel_module_udf_disabled",
    "kmod-disable-usb-storage": "kernel_module_usb-storage_disabled",
    "kmod-disable-dccp": "kernel_module_dccp_disabled",
    "kmod-disable-sctp": "kernel_module_sctp_disabled",
    "kmod-disable-tipc": "kernel_module_tipc_disabled",
    "kmod-disable-rds": "kernel_module_rds_disabled",
    # SSH
    "ssh-disable-root-login": "sshd_disable_root_login",
    "ssh-protocol-version": "sshd_use_strong_rng",
    "ssh-permit-empty-passwords": "sshd_disable_empty_passwords",
    "ssh-ignore-rhosts": "sshd_disable_rhosts",
    "ssh-hostbased-authentication": "sshd_disable_user_known_hosts",
    "ssh-max-auth-tries": "sshd_set_max_auth_tries",
    "ssh-client-alive-interval": "sshd_set_idle_timeout",
    "ssh-client-alive-count-max": "sshd_set_keepalive",
    "ssh-login-grace-time": "sshd_set_login_grace_time",
    "ssh-max-sessions": "sshd_set_max_sessions",
    "ssh-max-startups": "sshd_set_maxstartups",
    "ssh-pubkey-authentication": "sshd_enable_pubkey_auth",
    "ssh-banner": "sshd_enable_warning_banner",
    "ssh-strict-modes": "sshd_enable_strictmodes",
    "ssh-log-level": "sshd_set_loglevel_info",
    "ssh-x11-forwarding": "sshd_disable_x11_forwarding",
    "ssh-disable-tcp-forwarding": "sshd_disable_tcp_forwarding",
    "ssh-gssapi-authentication": "sshd_disable_gssapi_auth",
    "ssh-use-pam": "sshd_enable_pam",
    "ssh-ciphers-fips": "sshd_use_strong_ciphers",
    "ssh-macs-fips": "sshd_use_strong_macs",
    "ssh-kex-fips": "sshd_use_strong_kex",
    # Services
    "service-disable-avahi": "service_avahi-daemon_disabled",
    "service-disable-cups": "service_cups_disabled",
    "service-disable-dhcpd": "service_dhcpd_disabled",
    "service-disable-named": "service_named_disabled",
    "service-disable-nfs": "service_nfs_disabled",
    "service-disable-rpcbind": "service_rpcbind_disabled",
    "service-disable-slapd": "service_slapd_disabled",
    "service-disable-snmpd": "service_snmpd_disabled",
    "service-disable-squid": "service_squid_disabled",
    "service-disable-vsftpd": "service_vsftpd_disabled",
    "service-disable-httpd": "service_httpd_disabled",
    "service-disable-dovecot": "service_dovecot_disabled",
    "service-disable-smb": "service_smb_disabled",
    "service-disable-postfix": "postfix_network_listening_disabled",
    "service-disable-rsync": "service_rsyncd_disabled",
    "service-disable-autofs": "service_autofs_disabled",
    "service-enable-firewalld": "service_firewalld_enabled",
    "service-enable-auditd": "service_auditd_enabled",
    "service-enable-rsyslog": "service_rsyslog_enabled",
    "service-enable-crond": "service_crond_enabled",
    # Crypto policy
    "crypto-policy-fips": "configure_crypto_policy",
    "crypto-policy-no-sha1": "configure_crypto_policy",
    # PAM / Password
    "pam-pwquality-minlen": "accounts_password_pam_minlen",
    "pam-pwquality-minclass": "accounts_password_pam_minclass",
    "pam-pwquality-dcredit": "accounts_password_pam_dcredit",
    "pam-pwquality-ucredit": "accounts_password_pam_ucredit",
    "pam-pwquality-lcredit": "accounts_password_pam_lcredit",
    "pam-pwquality-ocredit": "accounts_password_pam_ocredit",
    "pam-pwquality-difok": "accounts_password_pam_difok",
    "pam-pwquality-maxrepeat": "accounts_password_pam_maxrepeat",
    "pam-pwquality-maxclassrepeat": "accounts_password_pam_maxclassrepeat",
    "pam-faillock-deny": "accounts_passwords_pam_faillock_deny",
    "pam-faillock-unlock-time": "accounts_passwords_pam_faillock_unlock_time",
    "pam-faillock-interval": "accounts_passwords_pam_faillock_interval",
    "pam-password-remember": "accounts_password_pam_unix_remember",
    # Login defs
    "login-defs-pass-max-days": "accounts_maximum_age_login_defs",
    "login-defs-pass-min-days": "accounts_minimum_age_login_defs",
    "login-defs-pass-warn-age": "accounts_password_warn_age_login_defs",
    "login-defs-umask": "accounts_umask_etc_login_defs",
    # Sysctl
    "sysctl-net-ipv4-ip-forward": "sysctl_net_ipv4_ip_forward",
    "sysctl-net-ipv4-conf-all-send-redirects": "sysctl_net_ipv4_conf_all_send_redirects",
    "sysctl-net-ipv4-conf-default-send-redirects": "sysctl_net_ipv4_conf_default_send_redirects",
    "sysctl-net-ipv4-conf-all-accept-source-route": "sysctl_net_ipv4_conf_all_accept_source_route",
    "sysctl-net-ipv4-conf-default-accept-source-route": "sysctl_net_ipv4_conf_default_accept_source_route",
    "sysctl-net-ipv4-conf-all-accept-redirects": "sysctl_net_ipv4_conf_all_accept_redirects",
    "sysctl-net-ipv4-conf-default-accept-redirects": "sysctl_net_ipv4_conf_default_accept_redirects",
    "sysctl-net-ipv4-conf-all-secure-redirects": "sysctl_net_ipv4_conf_all_secure_redirects",
    "sysctl-net-ipv4-conf-default-secure-redirects": "sysctl_net_ipv4_conf_default_secure_redirects",
    "sysctl-net-ipv4-conf-all-log-martians": "sysctl_net_ipv4_conf_all_log_martians",
    "sysctl-net-ipv4-conf-default-log-martians": "sysctl_net_ipv4_conf_default_log_martians",
    "sysctl-net-ipv4-icmp-echo-ignore-broadcasts": "sysctl_net_ipv4_icmp_echo_ignore_broadcasts",
    "sysctl-net-ipv4-icmp-ignore-bogus-error-responses": "sysctl_net_ipv4_icmp_ignore_bogus_error_responses",
    "sysctl-net-ipv4-conf-all-rp-filter": "sysctl_net_ipv4_conf_all_rp_filter",
    "sysctl-net-ipv4-conf-default-rp-filter": "sysctl_net_ipv4_conf_default_rp_filter",
    "sysctl-net-ipv4-tcp-syncookies": "sysctl_net_ipv4_tcp_syncookies",
    "sysctl-net-ipv6-conf-all-accept-ra": "sysctl_net_ipv6_conf_all_accept_ra",
    "sysctl-net-ipv6-conf-default-accept-ra": "sysctl_net_ipv6_conf_default_accept_ra",
    "sysctl-net-ipv6-conf-all-accept-redirects": "sysctl_net_ipv6_conf_all_accept_redirects",
    "sysctl-net-ipv6-conf-default-accept-redirects": "sysctl_net_ipv6_conf_default_accept_redirects",
    "sysctl-net-ipv6-conf-all-accept-source-route": "sysctl_net_ipv6_conf_all_accept_source_route",
    "sysctl-net-ipv6-conf-default-accept-source-route": "sysctl_net_ipv6_conf_default_accept_source_route",
    "sysctl-net-ipv6-conf-all-forwarding": "sysctl_net_ipv6_conf_all_forwarding",
    "sysctl-kernel-randomize-va-space": "sysctl_kernel_randomize_va_space",
    "sysctl-kernel-yama-ptrace-scope": "sysctl_kernel_yama_ptrace_scope",
    "sysctl-fs-suid-dumpable": "sysctl_fs_suid_dumpable",
    "sysctl-kernel-core-uses-pid": "sysctl_kernel_core_uses_pid",
    # SELinux
    "selinux-state-enforcing": "selinux_state",
    "selinux-policy-targeted": "selinux_policytype",
    # Audit
    "auditd-data-retention-max-log-file": "auditd_data_retention_max_log_file",
    "auditd-data-retention-max-log-file-action": "auditd_data_retention_max_log_file_action",
    "auditd-data-retention-space-left-action": "auditd_data_retention_space_left_action",
    "auditd-data-retention-admin-space-left-action": "auditd_data_retention_admin_space_left_action",
    "auditd-data-retention-action-mail-acct": "auditd_data_retention_action_mail_acct",
    "auditd-data-disk-full-action": "auditd_data_disk_full_action",
    "auditd-local-events": "auditd_local_events",
    "auditd-log-format": "auditd_log_format",
    "auditd-write-logs": "auditd_write_logs",
    # Files
    "file-permissions-etc-passwd": "file_permissions_etc_passwd",
    "file-permissions-etc-shadow": "file_permissions_etc_shadow",
    "file-permissions-etc-group": "file_permissions_etc_group",
    "file-permissions-etc-gshadow": "file_permissions_etc_gshadow",
    "file-permissions-etc-passwd-": "file_permissions_backup_etc_passwd",
    "file-permissions-etc-shadow-": "file_permissions_backup_etc_shadow",
    "file-permissions-etc-group-": "file_permissions_backup_etc_group",
    "file-permissions-etc-gshadow-": "file_permissions_backup_etc_gshadow",
    "file-owner-etc-passwd": "file_owner_etc_passwd",
    "file-owner-etc-shadow": "file_owner_etc_shadow",
    "file-owner-etc-group": "file_owner_etc_group",
    "file-owner-etc-gshadow": "file_owner_etc_gshadow",
    "file-groupowner-etc-passwd": "file_groupowner_etc_passwd",
    "file-groupowner-etc-shadow": "file_groupowner_etc_shadow",
    "file-groupowner-etc-group": "file_groupowner_etc_group",
    "file-groupowner-etc-gshadow": "file_groupowner_etc_gshadow",
    # Packages
    "package-aide-installed": "package_aide_installed",
    "package-audit-installed": "package_audit_installed",
    "package-rsyslog-installed": "package_rsyslog_installed",
    # GRUB
    "grub-password-set": "grub2_password",
    # Misc
    "banner-etc-issue": "banner_etc_issue",
    "banner-etc-issue-net": "banner_etc_issue_net",
    "banner-etc-motd": "banner_etc_motd",
    "journald-compress": "journald_compress",
    "journald-storage-persistent": "journald_storage",
    "coredump-disable-storage": "coredump_disable_storage",
    "coredump-disable-backtraces": "coredump_disable_backtraces",
}

# Build reverse mapping
OPENSCAP_TO_AEGIS = {v: k for k, v in AEGIS_TO_OPENSCAP.items()}


def normalize_rule_id(rule_id: str) -> str:
    """Normalize rule ID for comparison."""
    # Remove common prefixes/suffixes
    normalized = rule_id.lower()
    normalized = re.sub(r"[-_]", "", normalized)
    return normalized


def find_matching_openscap_rule(
    aegis_id: str, openscap_results: dict[str, RuleResult]
) -> str | None:
    """Find matching OpenSCAP rule for an AEGIS rule."""
    # Direct mapping
    if aegis_id in AEGIS_TO_OPENSCAP:
        openscap_id = AEGIS_TO_OPENSCAP[aegis_id]
        if openscap_id in openscap_results:
            return openscap_id

    # Try fuzzy matching
    aegis_norm = normalize_rule_id(aegis_id)
    for openscap_id in openscap_results:
        openscap_norm = normalize_rule_id(openscap_id)
        if aegis_norm in openscap_norm or openscap_norm in aegis_norm:
            return openscap_id

    return None


def generate_report(
    aegis_results: dict[str, RuleResult],
    openscap_results: dict[str, RuleResult],
    output_path: str,
) -> None:
    """Generate gap analysis markdown report."""
    # Categorize results
    both_pass = []
    both_fail = []
    aegis_pass_openscap_fail = []
    aegis_fail_openscap_pass = []
    aegis_only = []
    openscap_only_pass = []
    openscap_only_fail = []

    matched_openscap = set()

    for aegis_id, aegis_result in aegis_results.items():
        openscap_id = find_matching_openscap_rule(aegis_id, openscap_results)

        if openscap_id:
            matched_openscap.add(openscap_id)
            openscap_result = openscap_results[openscap_id]

            if aegis_result.passed and openscap_result.passed:
                both_pass.append((aegis_id, openscap_id, aegis_result, openscap_result))
            elif not aegis_result.passed and not openscap_result.passed:
                both_fail.append((aegis_id, openscap_id, aegis_result, openscap_result))
            elif aegis_result.passed and not openscap_result.passed:
                aegis_pass_openscap_fail.append(
                    (aegis_id, openscap_id, aegis_result, openscap_result)
                )
            else:
                aegis_fail_openscap_pass.append(
                    (aegis_id, openscap_id, aegis_result, openscap_result)
                )
        else:
            aegis_only.append((aegis_id, aegis_result))

    for openscap_id, openscap_result in openscap_results.items():
        if openscap_id not in matched_openscap:
            if openscap_result.passed:
                openscap_only_pass.append((openscap_id, openscap_result))
            else:
                openscap_only_fail.append((openscap_id, openscap_result))

    # Generate report
    report = []
    report.append("# CIS RHEL 9 Gap Analysis: AEGIS vs OpenSCAP\n")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("**AEGIS Framework:** cis-rhel9-v2.0.0")
    report.append("**OpenSCAP Profile:** xccdf_org.ssgproject.content_profile_cis")
    report.append("")
    report.append("---\n")

    # Executive Summary
    report.append("## Executive Summary\n")
    report.append("| Metric | AEGIS | OpenSCAP |")
    report.append("|--------|-------|----------|")
    aegis_pass = sum(1 for r in aegis_results.values() if r.passed)
    aegis_fail = sum(1 for r in aegis_results.values() if not r.passed)
    openscap_pass = sum(1 for r in openscap_results.values() if r.passed)
    openscap_fail = sum(1 for r in openscap_results.values() if not r.passed)
    report.append(f"| Rules checked | {len(aegis_results)} | {len(openscap_results)} |")
    report.append(
        f"| Pass | {aegis_pass} ({100*aegis_pass//len(aegis_results)}%) | {openscap_pass} ({100*openscap_pass//len(openscap_results)}%) |"
    )
    report.append(
        f"| Fail | {aegis_fail} ({100*aegis_fail//len(aegis_results)}%) | {openscap_fail} ({100*openscap_fail//len(openscap_results)}%) |"
    )
    report.append("")

    mapped_count = len(both_pass) + len(both_fail) + len(aegis_pass_openscap_fail) + len(
        aegis_fail_openscap_pass
    )
    report.append(f"**Mapped Rules Analysis ({mapped_count} rules compared):**")
    report.append(f"- Both tools agree (pass): {len(both_pass)}")
    report.append(f"- Both tools agree (fail): {len(both_fail)}")
    report.append(
        f"- Mismatches requiring investigation: {len(aegis_pass_openscap_fail) + len(aegis_fail_openscap_pass)}"
    )
    report.append("")
    report.append("---\n")

    # Result Mismatches
    report.append("## 1. Result Mismatches\n")
    report.append(
        "These rules have different pass/fail results between AEGIS and OpenSCAP.\n"
    )

    if aegis_pass_openscap_fail:
        report.append("### 1.1 AEGIS Passes, OpenSCAP Fails\n")
        report.append("| AEGIS Rule | OpenSCAP Rule | AEGIS Detail | Analysis |")
        report.append("|------------|---------------|--------------|----------|")
        for aegis_id, openscap_id, aegis_r, openscap_r in sorted(aegis_pass_openscap_fail):
            detail = aegis_r.detail[:40] if aegis_r.detail else "ok"
            report.append(
                f"| `{aegis_id}` | `{openscap_id}` | {detail} | Check logic difference |"
            )
        report.append("")

    if aegis_fail_openscap_pass:
        report.append("### 1.2 AEGIS Fails, OpenSCAP Passes\n")
        report.append("| AEGIS Rule | OpenSCAP Rule | AEGIS Detail | Root Cause |")
        report.append("|------------|---------------|--------------|------------|")
        for aegis_id, openscap_id, aegis_r, openscap_r in sorted(aegis_fail_openscap_pass):
            detail = aegis_r.detail[:40] if aegis_r.detail else "fail"
            report.append(
                f"| `{aegis_id}` | `{openscap_id}` | {detail} | Investigate |"
            )
        report.append("")

    report.append("---\n")

    # Coverage Gaps
    report.append("## 2. Coverage Gaps\n")
    report.append("### 2.1 Summary\n")
    report.append(
        f"- **OpenSCAP rules not mapped to AEGIS:** {len(openscap_only_pass) + len(openscap_only_fail)}"
    )
    report.append(f"  - Passing (lower priority): {len(openscap_only_pass)}")
    report.append(f"  - **Failing (critical gaps): {len(openscap_only_fail)}**")
    report.append(f"- **AEGIS rules not mapped to OpenSCAP:** {len(aegis_only)}")
    report.append("")

    if openscap_only_fail:
        report.append("### 2.2 Critical Gaps (Failing in OpenSCAP, Missing in AEGIS)\n")
        report.append("| OpenSCAP Rule | Title |")
        report.append("|---------------|-------|")
        for openscap_id, openscap_r in sorted(openscap_only_fail)[:50]:
            title = openscap_r.title[:60] if openscap_r.title else ""
            report.append(f"| `{openscap_id}` | {title} |")
        if len(openscap_only_fail) > 50:
            report.append(f"| ... | ({len(openscap_only_fail) - 50} more) |")
        report.append("")

    report.append("---\n")

    # Agreement Details
    report.append("## 3. Agreement Details\n")
    report.append(f"### 3.1 Both Pass ({len(both_pass)} rules)\n")
    if both_pass:
        report.append("<details><summary>Click to expand</summary>\n")
        report.append("| AEGIS Rule | OpenSCAP Rule |")
        report.append("|------------|---------------|")
        for aegis_id, openscap_id, _, _ in sorted(both_pass):
            report.append(f"| `{aegis_id}` | `{openscap_id}` |")
        report.append("</details>\n")

    report.append(f"### 3.2 Both Fail ({len(both_fail)} rules)\n")
    if both_fail:
        report.append("| AEGIS Rule | OpenSCAP Rule | AEGIS Detail |")
        report.append("|------------|---------------|--------------|")
        for aegis_id, openscap_id, aegis_r, _ in sorted(both_fail):
            detail = aegis_r.detail[:50] if aegis_r.detail else "fail"
            report.append(f"| `{aegis_id}` | `{openscap_id}` | {detail} |")
        report.append("")

    report.append("---\n")

    # AEGIS Only
    report.append("## 4. AEGIS-Only Rules\n")
    report.append(
        f"These {len(aegis_only)} rules exist in AEGIS but have no OpenSCAP equivalent.\n"
    )
    if aegis_only:
        report.append("<details><summary>Click to expand</summary>\n")
        report.append("| AEGIS Rule | CIS Section | Result |")
        report.append("|------------|-------------|--------|")
        for aegis_id, aegis_r in sorted(aegis_only):
            section = aegis_r.section or "-"
            result = "PASS" if aegis_r.passed else "FAIL"
            report.append(f"| `{aegis_id}` | {section} | {result} |")
        report.append("</details>\n")

    # Write report
    output = Path(output_path)
    output.write_text("\n".join(report))
    print(f"Report written to {output_path}")
    print(f"\nSummary:")
    print(f"  AEGIS: {len(aegis_results)} rules ({aegis_pass} pass, {aegis_fail} fail)")
    print(
        f"  OpenSCAP: {len(openscap_results)} rules ({openscap_pass} pass, {openscap_fail} fail)"
    )
    print(f"  Mapped: {mapped_count} rules")
    print(f"  Agree: {len(both_pass) + len(both_fail)}")
    print(f"  Mismatch: {len(aegis_pass_openscap_fail) + len(aegis_fail_openscap_pass)}")


def main():
    parser = argparse.ArgumentParser(description="AEGIS vs OpenSCAP gap analysis")
    parser.add_argument("--aegis", required=True, help="Path to AEGIS JSON results")
    parser.add_argument("--openscap", required=True, help="Path to OpenSCAP XML results")
    parser.add_argument(
        "--output", default="GAP_ANALYSIS.md", help="Output markdown file"
    )
    args = parser.parse_args()

    print(f"Parsing AEGIS results from {args.aegis}...")
    aegis_results = parse_aegis_json(args.aegis)
    print(f"  Found {len(aegis_results)} rules")

    print(f"Parsing OpenSCAP results from {args.openscap}...")
    openscap_results = parse_openscap_xml(args.openscap)
    print(f"  Found {len(openscap_results)} rules")

    generate_report(aegis_results, openscap_results, args.output)


if __name__ == "__main__":
    main()
