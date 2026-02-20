# Services Rule Review — Findings & Fix Plan

**Scope:** All 92 rules in `rules/services/`
**Date:** 2026-02-18
**Guide:** RULE_REVIEW_GUIDE_V0.md

---

## Executive Summary

Reviewed 92 services rules against the 5-dimension criteria in
RULE_REVIEW_GUIDE_V0.md. Found **~139 findings** across 80+ rules, organized
into 8 fix phases. The most critical findings are:

1. **30 runtime-critical field bugs** — `state: "stopped"` (25 rules) and
   `state: "running"` (5 rules) are silently ignored by the `service_state`
   handler, which only reads `enabled` and `active` keys. Every disable-service
   rule using `state: "stopped"` does NOT verify the service is actually stopped.

2. **8 duplicate rule pairs** — same control implemented by two rules without
   declaring `supersedes` or `conflicts_with` (e.g., `service-disable-avahi-daemon`
   vs `service-disable-avahi`, `service-disable-kdump` vs `kdump-disabled`).

3. **9 GDM rules with always-pass default** — default implementation runs
   `echo 'OK: GDM not installed'; exit 0` instead of verifying GDM is absent.

4. **9 wrong STIG vuln_id references** — rules claim STIG IDs that map to
   completely different controls in the mapping file.

---

## Table of Contents

1. [FIX-01: state: stopped/running → active: false/true (P0)](#fix-01)
2. [FIX-02: GDM Default Always-Pass & Missing depends_on (P1)](#fix-02)
3. [FIX-03: Config Separator & Handler Type Bugs (P1)](#fix-03)
4. [FIX-04: Duplicate Rule Resolution (P1)](#fix-04)
5. [FIX-05: Wrong STIG vuln_id/stig_id References (P1)](#fix-05)
6. [FIX-06: Wrong/Missing CIS Section References (P1-P2)](#fix-06)
7. [FIX-07: Missing depends_on & Platform Scope (P2)](#fix-07)
8. [FIX-08: Missing Framework Cross-References (P2)](#fix-08)

---

## FIX-01: state: stopped/running → active: false/true (P0) {#fix-01}

### Problem

The `service_state` check handler (`runner/handlers/checks/_service.py`) only
reads `enabled` and `active` keys. `state: "stopped"` and `state: "running"`
are silently ignored, meaning:
- Rules using `state: "stopped"` do NOT verify the service is actually stopped
- Rules using `state: "running"` do NOT verify the service is actually running

### Findings

#### 1a. `state: "stopped"` → `active: false` (25 rules)

| Rule File | Service |
|-----------|---------|
| `service-disable-avahi-daemon.yml` | avahi-daemon |
| `service-disable-samba.yml` | smb |
| `service-disable-rsync.yml` | rsyncd |
| `service-disable-kdump.yml` | kdump |
| `service-disable-autofs.yml` | autofs |
| `service-disable-dhcpd.yml` | dhcpd |
| `service-disable-nfs.yml` | nfs-server |
| `service-disable-cups.yml` | cups |
| `service-disable-httpd.yml` | httpd |
| `service-disable-named.yml` | named |
| `service-disable-tftp.yml` | tftp.socket |
| `service-disable-squid.yml` | squid |
| `service-disable-rpcbind.yml` | rpcbind |
| `service-disable-vsftpd.yml` | vsftpd |
| `service-disable-telnet.yml` | telnet.socket |
| `service-disable-snmpd.yml` | snmpd |
| `service-disable-smb.yml` | smb |
| `service-disable-ypserv.yml` | ypserv |
| `service-disable-dnsmasq.yml` | dnsmasq |
| `service-disable-dovecot.yml` | dovecot |
| `service-disable-rsyncd.yml` | rsyncd |
| `service-disable-xinetd.yml` | xinetd |
| `service-disable-avahi.yml` | avahi-daemon |
| `debug-shell-disabled.yml` | debug-shell |
| `kdump-disabled.yml` | kdump |

**Fix:** Replace `state: "stopped"` with `active: false` in all 25 rules.

#### 1b. `state: "running"` → `active: true` (5 rules)

| Rule File | Service |
|-----------|---------|
| `crond-service-enabled.yml` | crond |
| `journald-service-enabled.yml` | systemd-journald |
| `rsyslog-service-enabled.yml` | rsyslog |
| `chrony-enabled.yml` | chronyd |
| `service-enable-firewalld.yml` | firewalld |

**Fix:** Replace `state: "running"` with `active: true` in all 5 rules.

---

## FIX-02: GDM Default Always-Pass & Missing depends_on (P1) {#fix-02}

### Problem

9 GDM rules use a dual-implementation pattern with `when: gdm_installed` for the
real check and a default implementation that always passes:

```yaml
# Default (always passes -- broken)
- default: true
  check:
    method: command
    run: "echo 'OK: GDM not installed'; exit 0"
```

If a host has GDM installed but the `gdm_installed` capability is not detected,
the check silently passes instead of flagging a misconfiguration.

Additionally, GDM override rules (e.g., `gdm-automount-override`) should
declare `depends_on` for the setting rule (e.g., `gdm-automount-disabled`).

### Findings

#### 2a. Default implementation always passes (9 rules)

| Rule File | GDM Setting |
|-----------|-------------|
| `gdm-automount-disabled.yml` | automount |
| `gdm-autorun-never.yml` | autorun-never |
| `gdm-automount-override.yml` | automount lock |
| `gdm-autorun-never-override.yml` | autorun-never lock |
| `gdm-login-banner.yml` | banner-message-enable |
| `gdm-screen-lock-override.yml` | lock-enabled lock |
| `gdm-screen-lock-idle.yml` | idle-delay |
| `gdm-disable-user-list.yml` | disable-user-list |
| `gdm-xdmcp-disabled.yml` | Enable (xdmcp) |

**Fix:** Replace the default `echo 'OK'; exit 0` with a `package` check that
verifies GDM is actually not installed:
```yaml
- default: true
  check:
    method: package
    name: "gdm"
    state: absent
```

#### 2b. Override rules missing `depends_on` (2 rules)

| Rule File | Should depend on |
|-----------|-----------------|
| `gdm-automount-override.yml` | `gdm-automount-disabled` |
| `gdm-autorun-never-override.yml` | `gdm-autorun-never` |

**Fix:** Add `depends_on:` for the setting rule.

---

## FIX-03: Config Separator & Handler Type Bugs (P1) {#fix-03}

### Problem

Specific rules have remediation config issues or use the wrong check handler.

### Findings

#### 3a. `chrony-user.yml` missing separator

Uses `config_set` on `/etc/sysconfig/chronyd` with key `OPTIONS` and value
`"-u chrony"`. The sysconfig file uses `=` separator (`OPTIONS="-u chrony"`),
but no `separator` is specified. Default separator is space, which would write
`OPTIONS "-u chrony"` instead of `OPTIONS="-u chrony"`.

**Fix:** Add `separator: "="` to the remediation.

#### 3b. `service-disable-debug-shell.yml` uses command instead of service_state

Uses a complex `grep`-based command check to determine if debug-shell is
enabled/masked. The `debug-shell-disabled.yml` duplicate already uses the
correct `service_state` handler approach.

**Fix:** Replace the command check with `service_state` handler (or consolidate
with `debug-shell-disabled.yml` in Phase 4).

---

## FIX-04: Duplicate Rule Resolution (P1) {#fix-04}

### Problem

8 pairs of rules implement the same control with different IDs and framework
references, without declaring their relationship via `supersedes` or
`conflicts_with`.

### Findings

| # | Rule 1 (Canonical) | Rule 2 (Duplicate) | Control |
|---|--------------------|--------------------|---------|
| C1 | `service-disable-avahi.yml` | `service-disable-avahi-daemon.yml` | Disable avahi-daemon |
| C2 | `service-disable-smb.yml` | `service-disable-samba.yml` | Disable SMB/Samba |
| C3 | `service-disable-rsyncd.yml` | `service-disable-rsync.yml` | Disable rsyncd |
| C4 | `kdump-disabled.yml` | `service-disable-kdump.yml` | Disable kdump |
| C5 | `debug-shell-disabled.yml` | `service-disable-debug-shell.yml` | Disable debug-shell |
| C6 | `pkg-ypserv-absent.yml` | `package-ypserv-removed.yml` | Remove ypserv |
| C7 | `xorg-removed.yml` | `package-xorg-x11-server-common-removed.yml` | Remove xorg |
| C8 | `chrony-enabled.yml` | `chrony-installed.yml` | Chrony time sync (service vs package) |

**Fix:** For each pair:
1. Determine which is canonical (the one referenced in the mapping files)
2. Add `conflicts_with: [canonical-id]` to the non-canonical rule
3. Ensure framework references are on the canonical rule
4. For C8 (chrony), add `depends_on: [chrony-installed]` to `chrony-enabled.yml`

---

## FIX-05: Wrong STIG vuln_id/stig_id References (P1) {#fix-05}

### Problem

Rules claim STIG vuln_ids that map to completely different controls in the
STIG mapping file, or have duplicate stig_ids across different rules.

### Findings

#### 5a. Wrong vuln_id (6 rules)

| Rule File | Claims | Actually Maps To | Correct vuln_id |
|-----------|--------|------------------|-----------------|
| `service-disable-kdump.yml` | V-257797 | `kernel-dmesg-restrict` | V-257818 |
| `service-disable-debug-shell.yml` | V-257798 | `kernel-perf-restrict` | V-257786 |
| `service-disable-autofs.yml` | V-257796 | `grub-audit-enabled` | Remove ref (no STIG entry) |
| `service-disable-vsftpd.yml` | V-257778 | unimplemented (system patches) | V-257826 via `pkg-vsftpd-absent` |
| `service-disable-telnet.yml` | V-257779 | `banner-dod-consent` | V-257837 via `pkg-telnet-server-absent` |
| `service-enable-firewalld.yml` | V-257780 | not in control_ids | Remove ref |

#### 5b. Duplicate stig_ids across rules (3 pairs)

| stig_id | Rule 1 | Rule 2 |
|---------|--------|--------|
| RHEL-09-215030 | `pkg-krb5-server-absent.yml` | `pkg-ypserv-absent.yml` |
| RHEL-09-215055 | `pkg-libnsl-absent.yml` | `pkg-tuned-absent.yml` |
| RHEL-09-215065 | `pkg-telnet-server-absent.yml` | `pkg-quagga-absent.yml` |

**Fix:** Cross-reference the actual DISA STIG RHEL 9 V2R7 document and correct
all vuln_id and stig_id values. Remove STIG refs from rules where no valid
STIG entry exists.

---

## FIX-06: Wrong/Missing CIS Section References (P1-P2) {#fix-06}

### Problem

Rules claim CIS section numbers that map to different rules in the mapping
files, or package-removal rules claim CIS sections that belong to the
service-disable counterpart.

### Findings

#### 6a. CIS RHEL 9 section belongs to a different rule (P1, 10 rules)

| Rule File | Claims Section | Mapping Points To |
|-----------|---------------|-------------------|
| `service-disable-avahi-daemon.yml` | 2.2.2 | `package-openldap-clients-removed` |
| `package-bind-removed.yml` | 2.1.4 | `service-disable-named` |
| `package-net-snmp-removed.yml` | 2.1.14 | `service-disable-snmpd` |
| `package-xinetd-removed.yml` | 2.1.19 | `service-disable-xinetd` |
| `package-dnsmasq-removed.yml` | 2.1.5 | `service-disable-dnsmasq` |
| `package-dovecot-removed.yml` | 2.1.8 | `service-disable-dovecot` |
| `package-cyrus-imapd-removed.yml` | 2.1.8 | `service-disable-dovecot` |
| `package-nginx-removed.yml` | 2.1.18 | `service-disable-httpd` |
| `package-ypserv-removed.yml` | 2.1.10 | `service-disable-ypserv` |
| `package-xorg-x11-server-common-removed.yml` | 2.1.20 | `xorg-removed` |

**Fix:** Remove the CIS RHEL 9 references from these rules since the mapping
file assigns the section to a different canonical rule. The CIS section covers
both the package removal and service disable, but only one rule should own it.

#### 6b. CIS RHEL 8 refs not in mapping (P2, 13 rules)

Many `service-disable-*` rules include CIS RHEL 8 v4.0.0 section references
that do not appear in the RHEL 8 mapping file. These need verification:

| Rule File | CIS RHEL 8 Section |
|-----------|-------------------|
| `service-disable-avahi-daemon.yml` | 2.2.2 |
| `service-disable-dhcpd.yml` | 2.2.5 |
| `service-disable-nfs.yml` | 2.2.7 |
| `service-disable-cups.yml` | 2.2.4 |
| `service-disable-httpd.yml` | 2.2.10 |
| `service-disable-named.yml` | 2.2.6 |
| `service-disable-tftp.yml` | 2.2.19 |
| `service-disable-squid.yml` | 2.2.12 |
| `service-disable-rpcbind.yml` | 2.2.8 |
| `service-disable-vsftpd.yml` | 2.2.9 |
| `service-disable-telnet.yml` | 2.2.18 |
| `service-disable-snmpd.yml` | 2.2.13 |
| `service-disable-rsync.yml` | 2.2.20 |

**Fix:** Verify these sections exist in the CIS RHEL 8 v4.0.0 benchmark. If
valid, add them to the RHEL 8 mapping file. If from an older benchmark version,
correct or remove.

---

## FIX-07: Missing depends_on & Platform Scope (P2) {#fix-07}

### Problem

Service-enable rules missing `depends_on` for their package prerequisite, and
STIG-only rules unnecessarily restricted to `min_version: 9` when they apply
equally to RHEL 8.

### Findings

#### 7a. Missing depends_on (3 rules)

| Rule File | Should depend on |
|-----------|-----------------|
| `chrony-enabled.yml` | `chrony-installed` |
| `gdm-automount-override.yml` | `gdm-automount-disabled` |
| `gdm-autorun-never-override.yml` | `gdm-autorun-never` |

#### 7b. Narrow platform scope — min_version: 9 → 8 (18 rules)

| Rule File | Package/Service |
|-----------|----------------|
| `pkg-vsftpd-absent.yml` | vsftpd |
| `pkg-sendmail-absent.yml` | sendmail |
| `pkg-nfs-utils-absent.yml` | nfs-utils |
| `pkg-tuned-absent.yml` | tuned |
| `pkg-ypserv-absent.yml` | ypserv |
| `pkg-gssproxy-absent.yml` | gssproxy |
| `pkg-iprutils-absent.yml` | iprutils |
| `pkg-quagga-absent.yml` | quagga |
| `pkg-krb5-server-absent.yml` | krb5-server |
| `pkg-krb5-workstation-absent.yml` | krb5-workstation |
| `pkg-libnsl-absent.yml` | libnsl |
| `pkg-telnet-server-absent.yml` | telnet-server |
| `debug-shell-disabled.yml` | debug-shell |
| `interactive-boot-disabled.yml` | systemd.confirm_spawn |
| `kdump-disabled.yml` | kdump |
| `rsyslog-service-enabled.yml` | rsyslog |
| `gdm-removed.yml` | gdm |
| All `pkg-*-present` rules | Various required packages |

**Fix:** Widen `min_version` to `8` for rules where the package/service exists
on both RHEL 8 and 9.

---

## FIX-08: Missing Framework Cross-References (P2) {#fix-08}

### Problem

Rules that have CIS-only or STIG-only references when the same control exists
in both frameworks.

### Findings

#### 8a. Missing CIS RHEL 8 references (11 rules)

Rules that apply to RHEL 8+ but lack CIS RHEL 8 v4.0.0 references. The RHEL 8
mapping file has these as "unimplemented":

| Rule File | RHEL 8 Mapping Section |
|-----------|----------------------|
| `service-disable-mcstrans.yml` | 1.3.1.7 |
| `package-setroubleshoot-removed.yml` | 1.3.1.8 |
| `service-disable-autofs.yml` | 2.1.1 |
| `chrony-installed.yml` | 2.3.1 |
| `crond-service-enabled.yml` | 2.4.1.1 |
| `package-ypbind-removed.yml` | 2.2.3 |
| `package-ftp-removed.yml` | 2.2.1 |
| `package-openldap-clients-removed.yml` | 2.2.2 |
| `package-tftp-removed.yml` | 2.2.5 |
| `package-telnet-removed.yml` | 2.2.4 |
| `journald-service-enabled.yml` | (no mapping entry) |

#### 8b. Missing STIG references on CIS-only rules (9 rules)

| Rule File | Related STIG Control |
|-----------|---------------------|
| `service-disable-smb.yml` | (indirect) |
| `service-disable-ypserv.yml` | V-257829 |
| `service-disable-dnsmasq.yml` | (indirect) |
| `service-disable-dovecot.yml` | (indirect) |
| `service-disable-rsyncd.yml` | (indirect) |
| `service-disable-xinetd.yml` | (indirect) |
| `chrony-enabled.yml` | chronyd enabled |
| `chrony-sources.yml` | time sources |
| `postfix-local-only.yml` | V-257951 |

#### 8c. Missing CIS references on STIG-only rules (4+ rules)

| Rule File | Related CIS Control |
|-----------|-------------------|
| `pkg-vsftpd-absent.yml` | CIS 9 2.1.7 |
| `pkg-sendmail-absent.yml` | (none) |
| `pkg-nfs-utils-absent.yml` | CIS 9 2.1.9 |
| Other `pkg-*` STIG rules | Various |

**Fix:** Add applicable cross-framework references and update mapping files to
move entries from "unimplemented" to active controls.

---

## Recommended Phase Execution Order

| Phase | PR Title | Scope | Files |
|-------|----------|-------|-------|
| 1 | `fix(services): replace state: stopped/running with active: false/true` | 30 rules | ~30 |
| 2 | `fix(services): fix GDM default always-pass and add depends_on` | 11 rules | ~11 |
| 3 | `fix(services): fix chrony-user separator and debug-shell handler` | 2 rules | ~2 |
| 4 | `fix(services): resolve 8 duplicate rule pairs with conflicts_with` | ~16 rules | ~16 |
| 5 | `fix(services): correct wrong STIG vuln_id/stig_id references` | ~9 rules | ~9 |
| 6 | `fix(services): correct CIS section references` | ~23 rules | ~23 |
| 7 | `fix(services): add missing depends_on and widen platform scope` | ~21 rules | ~21 |
| 8 | `fix(services): add missing framework cross-references` | ~24 rules | ~24 |

**Total: ~139 findings across ~80 rules, 8 PRs**

---

## Verification Commands

```bash
# After each phase:
pytest tests/ -v
ruff check runner/ schema/ tests/
python schema/validate.py

# CIS validation
python scripts/cis_validate.py --mapping cis-rhel9-v2.0.0
python scripts/cis_validate.py --mapping cis-rhel8-v4.0.0

# Coverage
./kensa coverage --framework cis-rhel9-v2.0.0
./kensa coverage --framework stig-rhel9-v2r7
```
