# Typed Mechanism Migration Plan

**Goal:** Convert manual and command_exec remediations to typed/declarative mechanisms where it improves rollback safety and commercial value.

**Plan created:** 2026-03-13

---

## Current State (post-Wave 2)

After Wave 2, 110 rules use non-capturable remediation paths:

| Mechanism | Rules | Notes |
|---|---|---|
| manual | 82 | Human judgment, org-specific, or high-risk |
| command_exec | 20 | Arbitrary shell commands, no pre-state capture |
| grub_parameter_set | 7 | Requires regenerating boot config |
| grub_parameter_remove | 1 | Requires regenerating boot config |
| **Total non-capturable** | **110** | |

Typed/declarative remediation coverage: ~85% of all remediation steps (up from ~83% post-Wave 1).

GRUB parameter rules (8) are structurally non-capturable and out of scope for this plan. The migration target is the remaining 102 manual + command_exec rules.

---

## Wave 1: Convert Now with Existing Mechanisms ✅ COMPLETE

High-value, straightforward conversions using existing handlers. No new handler code required.

**Converted (7 rules):**

| Rule ID | Was | Now | Config target |
|---|---|---|---|
| postfix-local-only | manual | config_set | /etc/postfix/main.cf (restart postfix) |
| fapolicyd-deny-all | manual | config_append | /etc/fapolicyd/fapolicyd.rules (restart fapolicyd) |
| motd-configured | manual | file_content | /etc/motd (`{{ banner_text }}`) |
| banner-ssh-dod | manual | file_content | /etc/issue.net (`{{ banner_text }}`) |
| sudo-timestamp-timeout | manual | file_content | /etc/sudoers.d/00-kensa-timestamp (mode 0440) |
| rsyslog-remote-server | manual | config_set_dropin | /etc/rsyslog.d/00-kensa-remote.conf (`{{ rsyslog_remote_server }}`) |
| rsyslog-verify-remote-server | manual | config_set_dropin | /etc/rsyslog.d/00-kensa-stream-auth.conf |

**Already typed (1 rule):**
- `journald-to-rsyslog` — already has `config_set_dropin` for `when: rsyslog_active` path; default path is manual (correct: no-op when rsyslog absent).

**Deferred to Wave 2 (2 rules):**
- `firewalld-loopback` — needs dedicated firewalld handler (command_exec with unless guard is functional but non-capturable).
- `gdm-xdmcp-disabled` — needs section-aware INI config handler; `config_set` can't target `[xdmcp]` section safely.

**Variables added:** `rsyslog_remote_server` in `config/defaults.yml` (default: `logserver.example.com:514`). `banner_text` already existed.

**Actual impact:** 7 rules converted (manual → typed), 0 new handler code.

---

## Wave 2: Convert After Adding 2-4 New Typed Mechanisms

The biggest leverage area. Many manual rules cluster around a few config families. Adding a small number of targeted mechanisms unlocks large groups of rules.

### SSH crypto rules (5 rules) — ✅ COMPLETE via `config_set_dropin`

| Rule ID | Was | Now | sshd directive |
|---|---|---|---|
| ssh-approved-ciphers | manual | config_set_dropin | Ciphers (`{{ ssh_approved_ciphers }}`) |
| ssh-approved-kex | manual | config_set_dropin | KexAlgorithms (`{{ ssh_approved_kex }}`) |
| ssh-approved-macs | manual | config_set_dropin | MACs (`{{ ssh_approved_macs }}`) |
| ssh-ciphers-fips | manual | config_set_dropin | Ciphers (hardcoded FIPS subset) |
| ssh-macs-fips | manual | config_set_dropin | MACs (hardcoded FIPS subset) |

All 5 write to `/etc/ssh/sshd_config.d/` and restart sshd. Variable-driven rules use site-configurable algorithm lists; FIPS rules use hardcoded validated sets. Variable `ssh_approved_ciphers` added to `config/defaults.yml`.

**Also fixed:** `sudo-use-pty` and `sudo-logfile` had wrong field names (`directory`/`filename`/`content` → `dir`/`file`/`key`/`value`) that would have caused runtime KeyErrors.

### Sudo and chrony conversions (2 rules) — ✅ COMPLETE via existing handlers

| Rule ID | Was | Now | Target |
|---|---|---|---|
| sudo-include-directory | manual | config_append | /etc/sudoers (@includedir line) |
| chrony-sources | manual | config_set_dropin | /etc/chrony.d/00-kensa-sources.conf (`{{ chrony_ntp_pool }}`) |

Variable `chrony_ntp_pool` added to `config/defaults.yml` (default: `2.rhel.pool.ntp.org iburst`).

### Moved to Wave 3 (stay manual — need new mechanisms or human judgment)

| Rule ID | Reason |
|---|---|
| sudo-nopasswd-prohibited | Removal of NOPASSWD is org-specific and destructive |
| sudo-require-password | Multi-file sudoers editing with org-specific policies |
| sudo-restrict-privilege-escalation | Requires human judgment about privilege scope |
| firewalld-default-deny | Needs dedicated firewalld handler for typed remediation |
| nftables-default-deny | Needs dedicated nftables handler |
| nftables-loopback | Needs dedicated nftables handler |
| firewall-single-utility | Validation-only — no remediation applicable |
| dns-nameservers-configured | resolv.conf managed by NetworkManager, not safe for direct manipulation |

**Actual impact:** 7 rules converted in Wave 2 (5 SSH crypto + sudo-include-directory + chrony-sources), 2 sudo field-name bugs fixed, 8 rules reclassified to Wave 3.

---

## Wave 3: Keep Manual

These are legitimately harder, interactive, environment-specific, or risky enough that manual is defensible. Automating them adds risk without commercial value.

### GRUB identity/password (2 rules)
- `grub-password` — requires interactive grub2-setpassword
- `grub-unique-superuser` — requires manual grub.cfg editing

### FIPS and SELinux mode flips (2 rules)
- `fips-mode-enabled` — requires reboot, can break workloads
- `selinux-not-disabled` — requires reboot, can break applications

### Filesystem partitioning and mount-separation (~12 rules)
`mount-home-separate-fs`, `mount-tmp-separate-fs`, `mount-var-separate-fs`, `mount-var-log-separate-fs`, `mount-var-log-audit-separate-fs`, `mount-var-tmp-separate-fs`, `separate-filesystem-home`, `separate-filesystem-tmp`, `separate-filesystem-var`, `separate-filesystem-var-log`, etc.

Invasive and highly site-specific. Partitioning decisions depend on disk layout, LVM configuration, and org policy.

### Identity/integrity cleanup (~15 rules)
`no-duplicate-gids`, `no-duplicate-uids`, `no-duplicate-groupnames`, `no-duplicate-usernames`, `no-unowned-files`, `no-forward-files`, `no-netrc-files`, `root-only-uid0`, `root-only-gid0`, `root-group-only-gid0`, `passwd-groups-exist`, `password-change-past`, `root-access-controlled`, `root-path-integrity`, etc.

High blast radius, often need human judgment. Automatically deleting unowned files or modifying UIDs can break running services.

### Sudo policy (3 rules — moved from Wave 2)
`sudo-nopasswd-prohibited`, `sudo-require-password`, `sudo-restrict-privilege-escalation` — removal/policy operations that are org-specific and require human judgment. A `sudoers_policy_set` mechanism with visudo validation would be needed to automate safely.

### Firewall policy (4 rules — moved from Wave 2)
`firewalld-default-deny`, `nftables-default-deny`, `nftables-loopback`, `firewall-single-utility` — need dedicated firewalld/nftables handlers. `firewall-single-utility` is validation-only (no remediation). `firewalld-loopback` (already command_exec) also needs a firewalld handler.

### DNS resolution
`dns-nameservers-configured` — resolv.conf is managed by NetworkManager on RHEL; direct file manipulation is overwritten on restart. Remediation must go through nmcli or systemd-resolved.

### Other legitimately manual
`aide-acl-check`, `aide-xattr-check`, `audit-suid-files`, `audit-sgid-files`, `crypto-policy-not-overridden`, `emergency-service-auth`, `single-user-auth`, `ssh-access-control`, `single-logging-system`, `kernel-nx-enabled`, `rhel-vendor-supported`, `no-promiscuous-interfaces`, `gdm-xdmcp-disabled` (needs section-aware INI handler)

---

## Recommended Priority (Future Work)

Waves 1 and 2 converted 14 rules total. Remaining high-value targets needing new handler code:

1. **firewalld-loopback** — needs dedicated firewalld handler (currently command_exec)
2. **gdm-xdmcp-disabled** — needs section-aware INI handler
3. **firewalld-default-deny** — needs firewalld handler
4. **nftables-default-deny** / **nftables-loopback** — need nftables handler
5. **sudo-nopasswd-prohibited** / **sudo-require-password** — need sudoers_policy_set with visudo validation

---

## Per-Wave SDD Workflow

Each wave follows the development pipeline:

1. Write or update handler spec (if new mechanism needed)
2. Get spec approved
3. Write spec-derived tests (will fail initially)
4. Implement handler code to pass tests
5. Rewrite rule YAML files to use the new mechanism
6. Run full test suite + schema validation
7. PR workflow: branch -> commit -> push -> CI -> merge

---

## Success Criteria

1. ✅ Wave 1 converted 7 rules with zero new handler code
2. Wave 2 adds 2-4 new mechanisms and converts ~15 more rules
3. All migrated rules pass check + remediate + rollback on RHEL 8 and RHEL 9
4. No regressions in existing test suite
5. Remaining manual rules are documented with justification (Wave 3)
6. New handlers have specs, spec-derived tests, and capture/rollback support
