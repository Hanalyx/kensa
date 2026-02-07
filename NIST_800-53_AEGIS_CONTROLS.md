# NIST SP 800-53 Rev. 5 Controls in Aegis

This document describes the NIST SP 800-53 Rev. 5 security controls implemented by Aegis rules and how to use them for compliance reporting.

## Overview

NIST Special Publication 800-53 Revision 5 defines security and privacy controls for federal information systems. Unlike CIS or STIG benchmarks that have a 1:1 relationship between controls and rules, NIST controls are **many-to-many**:

- One NIST control may require multiple Aegis rules
- One Aegis rule may satisfy multiple NIST controls

Aegis maps 87 NIST controls to 194 canonical rules, covering the following control families:

| Family | Description | Controls Mapped |
|--------|-------------|-----------------|
| **AC** | Access Control | 19 |
| **AU** | Audit and Accountability | 14 |
| **CM** | Configuration Management | 10 |
| **IA** | Identification and Authentication | 14 |
| **SC** | System and Communications Protection | 14 |
| **SI** | System and Information Integrity | 16 |

## Using NIST Controls

### Query Rules for a Control

Find all rules that help satisfy a NIST control:

```bash
# Query a specific control
aegis info --control "nist-800-53-r5:AC-6"

# Output:
# Rules implementing nist-800-53-r5:AC-6:
# nist-800-53-r5: Least Privilege
#
#   accounts-no-uid-zero
#     Ensure only root has UID 0
#     Severity: critical
#
#   ssh-disable-root-login
#     Disable SSH root login
#     Severity: high
#   ...
```

### Query Controls for a Rule

Find all NIST controls satisfied by a rule:

```bash
aegis info --rule ssh-ciphers-fips

# Shows:
#   nist-800-53-r5: AC-17(2) - Remote Access | Encryption
#   nist-800-53-r5: SC-8 - Transmission Confidentiality
#   nist-800-53-r5: SC-13 - Cryptographic Protection
```

### Query Control Families

Find all rules for a control family using prefix matching:

```bash
# All Access Control rules
aegis info --control "nist-800-53-r5:AC" --prefix-match

# All Audit rules
aegis info --control "nist-800-53-r5:AU" --prefix-match
```

### Run Compliance Checks

Run checks filtered to NIST-referenced rules:

```bash
# Check all NIST-mapped rules
aegis check -i inventory.ini --sudo --framework nist-800-53-r5

# Check a specific control family
aegis info --control "nist-800-53-r5:SC" --prefix-match --json | \
  jq -r '.rules[].rule_id' | \
  xargs -I {} aegis check -i inventory.ini --sudo --rule rules/*/{}.yml
```

### Generate JSON Reports

```bash
aegis info --control "nist-800-53-r5:AC-6" --json
```

Output:
```json
{
  "query": {"control": "nist-800-53-r5:AC-6", "prefix_match": false},
  "control_info": [{
    "mapping_id": "nist-800-53-r5",
    "section_id": "AC-6",
    "title": "Least Privilege",
    "metadata": {"rules": ["ssh-disable-root-login", "sudo-use-pty", ...]}
  }],
  "rules": [
    {"rule_id": "ssh-disable-root-login", "title": "Disable SSH root login", "severity": "high"},
    {"rule_id": "sudo-use-pty", "title": "Ensure sudo commands use a pseudo terminal", "severity": "medium"}
  ]
}
```

## Control Family Details

### AC - Access Control

Controls related to account management, access enforcement, least privilege, and session management.

| Control | Title | Rules |
|---------|-------|-------|
| AC-2 | Account Management | accounts-no-uid-zero, nologin-system-accounts, inactive-password-lock |
| AC-3 | Access Enforcement | selinux-enforcing, fs-permissions-*, sudo-use-pty |
| AC-6 | Least Privilege | ssh-disable-root-login, sudo-*, su-require-wheel |
| AC-7 | Unsuccessful Logon Attempts | pam-faillock-* |
| AC-8 | System Use Notification | banner-*, motd-*, issue-* |
| AC-10 | Concurrent Session Control | ssh-max-sessions |
| AC-11 | Device Lock | shell-timeout, ssh-client-alive-* |
| AC-12 | Session Termination | ssh-client-alive-*, shell-timeout |
| AC-17 | Remote Access | ssh-disable-root-login, ssh-permit-empty-passwords, ssh-max-auth-tries |
| AC-17(2) | Remote Access Encryption | ssh-ciphers-fips, ssh-macs-fips, ssh-kex-fips |

### AU - Audit and Accountability

Controls for event logging, audit storage, and audit protection.

| Control | Title | Rules |
|---------|-------|-------|
| AU-2 | Event Logging | auditd-service-enabled, audit-* (all audit rules) |
| AU-3 | Content of Audit Records | audit-time-change, audit-user-group-changes |
| AU-4 | Audit Log Storage Capacity | auditd-space-action, auditd-disk-* |
| AU-5 | Response to Audit Failures | auditd-admin-space-action, auditd-disk-* |
| AU-6 | Audit Review and Reporting | journald-*, rsyslog-* |
| AU-8 | Time Stamps | audit-time-change |
| AU-9 | Protection of Audit Information | rsyslog-default-permissions |
| AU-12 | Audit Record Generation | auditd-service-enabled, audit-privileged-commands |

### CM - Configuration Management

Controls for configuration settings, least functionality, and change control.

| Control | Title | Rules |
|---------|-------|-------|
| CM-5 | Access Restrictions for Change | grub-password, sudo-logfile, audit-sudoers-changes |
| CM-6 | Configuration Settings | crypto-policy-*, selinux-* |
| CM-7 | Least Functionality | service-disable-* (all disabled services) |
| CM-7(2) | Prevent Program Execution | mount-*-noexec |
| CM-7(4) | Unauthorized Software | gpgcheck-*, aide-installed |
| CM-11 | User-Installed Software | gpgcheck-*, sudo-use-pty |

### IA - Identification and Authentication

Controls for user authentication, password policies, and cryptographic authentication.

| Control | Title | Rules |
|---------|-------|-------|
| IA-2 | User Authentication | ssh-pubkey-authentication, pam-faillock-deny |
| IA-4 | Identifier Management | accounts-no-uid-zero, root-gid |
| IA-5 | Authenticator Management | pam-pwquality-*, login-defs-*, password-remember |
| IA-5(1) | Password-Based Authentication | pam-pwquality-* (complexity rules) |
| IA-5(2) | Public Key Authentication | ssh-pubkey-authentication, ssh-*-key-permissions |
| IA-6 | Authentication Feedback | pam-faillock-* |
| IA-7 | Cryptographic Module Authentication | crypto-policy-fips, fips-mode-enabled |
| IA-11 | Re-authentication | sudo-timeout, shell-timeout |

### SC - System and Communications Protection

Controls for boundary protection, transmission security, and cryptographic protection.

| Control | Title | Rules |
|---------|-------|-------|
| SC-2 | Separation of System and User Functionality | nologin-system-accounts, selinux-enforcing |
| SC-4 | Information in Shared Resources | coredump-*, mount-*-noexec |
| SC-5 | Denial-of-Service Protection | sysctl-net-ipv4-tcp-syncookies, ssh-max-startups |
| SC-7 | Boundary Protection | service-enable-firewalld, sysctl-net-ipv4-* |
| SC-8 | Transmission Confidentiality | ssh-ciphers-fips, ssh-macs-fips, ssh-kex-fips |
| SC-10 | Network Disconnect | ssh-client-alive-*, shell-timeout |
| SC-12 | Cryptographic Key Management | ssh-kex-fips, ssh-*-key-permissions |
| SC-13 | Cryptographic Protection | fips-mode-enabled, crypto-policy-fips |
| SC-28 | Protection of Information at Rest | crypto-policy-fips, selinux-enforcing |

### SI - System and Information Integrity

Controls for flaw remediation, malicious code protection, and system monitoring.

| Control | Title | Rules |
|---------|-------|-------|
| SI-2 | Flaw Remediation | gpgcheck-*, repo-gpgcheck-* |
| SI-3 | Malicious Code Protection | selinux-enforcing, mount-*-noexec |
| SI-4 | System Monitoring | auditd-service-enabled, audit-*, journald-* |
| SI-6 | Security Function Verification | aide-installed, selinux-enforcing |
| SI-7 | Software Integrity | aide-installed, gpgcheck-*, grub-password |
| SI-10 | Information Input Validation | ssh-permit-user-environment, ssh-ignore-rhosts |
| SI-11 | Error Handling | kernel-dmesg-restrict, coredump-restricted |
| SI-16 | Memory Protection | aslr-enabled, kernel-yama-ptrace, kernel-* |

## Unimplemented Controls

The following NIST controls are marked as unimplemented in Aegis because they require organizational policies, manual processes, or are outside the scope of technical hardening:

| Control | Title | Reason |
|---------|-------|--------|
| AC-1 | Policy and Procedures | Organizational policy document |
| AC-5 | Separation of Duties | Requires organizational role definitions |
| AU-1 | Policy and Procedures | Organizational policy document |
| AU-7 | Audit Reduction and Report Generation | Requires SIEM tooling |
| AU-11 | Audit Record Retention | Organizational retention policy |
| CM-2 | Baseline Configuration | Aegis itself provides baseline enforcement |
| CM-3 | Configuration Change Control | Requires change management process |
| IA-8 | Non-Organizational User Authentication | Requires identity federation |
| SI-5 | Security Alerts and Advisories | Requires security feed subscription |

## Mapping Methodology

The NIST control mapping follows these principles:

1. **Evidence-Based**: Each control-to-rule mapping is based on the control's assessment objectives from NIST SP 800-53A.

2. **Conservative**: Rules are only mapped to controls they directly address. Indirect relationships are not included.

3. **Many-to-Many**: A single rule may satisfy multiple controls (e.g., `fips-mode-enabled` satisfies IA-7, SC-8(1), SC-13, SC-28(1)).

4. **Control Enhancements**: NIST control enhancements (e.g., AC-6(2)) are mapped separately from base controls (AC-6) when their requirements differ.

## Coverage Statistics

```bash
aegis coverage --framework nist-800-53-r5
```

Output:
```
NIST SP 800-53 Rev. 5 Security Controls

Coverage:
  Total controls: 105
  Implemented: 87 (mapped to rules)
  Unimplemented: 18 (need rules or manual)

  Rule coverage: 82.9%
```

## References

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-53A Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final) (Assessment Procedures)
- [NIST SP 800-53B](https://csrc.nist.gov/publications/detail/sp/800-53b/final) (Control Baselines)
