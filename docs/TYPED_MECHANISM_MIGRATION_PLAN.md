# Typed Mechanism Migration Plan

**Goal:** Convert manual and command_exec remediations to typed/declarative mechanisms where it improves rollback safety and commercial value.

**Plan created:** 2026-03-13

---

## Current State (post-Wave 1)

After Wave 1, 117 rules use non-capturable remediation paths:

| Mechanism | Rules | Notes |
|---|---|---|
| manual | 89 | Human judgment, org-specific, or high-risk |
| command_exec | 20 | Arbitrary shell commands, no pre-state capture |
| grub_parameter_set | 7 | Requires regenerating boot config |
| grub_parameter_remove | 1 | Requires regenerating boot config |
| **Total non-capturable** | **117** | |

Typed/declarative remediation coverage: ~83% of all remediation steps (up from ~82%).

GRUB parameter rules (8) are structurally non-capturable and out of scope for this plan. The migration target is the remaining 109 manual + command_exec rules.

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

### SSH crypto rules (5 rules) — new: `sshd_option_set` or extend `config_set_dropin`

| Rule ID | Current | sshd directive |
|---|---|---|
| ssh-approved-ciphers | manual | Ciphers |
| ssh-approved-kex | manual | KexAlgorithms |
| ssh-approved-macs | manual | MACs |
| ssh-ciphers-fips | manual | Ciphers (FIPS subset) |
| ssh-macs-fips | manual | MACs (FIPS subset) |

These want `config_set_dropin` with list-value normalization (comma-separated cipher/MAC/KEX lists). Minimal new code — extend the existing dropin handler to handle ordered list values.

### Sudo policy rules (4 rules) — new: `sudoers_policy_set`

| Rule ID | Current | Policy |
|---|---|---|
| sudo-nopasswd-prohibited | manual | Remove NOPASSWD entries |
| sudo-require-password | manual | Ensure Defaults !authenticate removed |
| sudo-restrict-privilege-escalation | manual | Restrict escalation paths |
| sudo-include-directory | manual | Ensure #includedir /etc/sudoers.d |

A `sudoers_policy_set` mechanism that writes to `/etc/sudoers.d/` drop-ins and runs `visudo -c` before committing. Syntax safety is critical — sudoers errors can lock out administrative access.

### Firewall policy rules (4 rules) — new: `firewalld_policy_*` / `nftables_rule_*`

| Rule ID | Current | Target |
|---|---|---|
| firewalld-default-deny | manual | firewalld_policy mechanism |
| nftables-default-deny | manual | nftables_rule mechanism |
| nftables-loopback | manual | nftables_rule mechanism |
| firewall-single-utility | manual | validation-only (no remediation) |

Lower priority than SSH and sudo clusters. These rules are rarely auto-remediated in practice.

### DNS and chrony site-config rules (2 rules) — variable-driven config_set

| Rule ID | Current | Target |
|---|---|---|
| dns-nameservers-configured | manual | config_set with `{{ dns_servers }}` variable |
| chrony-sources | manual | config_set with `{{ ntp_servers }}` variable |

Convertible if made variable-driven and explicit about ownership of the target config file.

**Estimated impact:** ~15 rules converted, 2-4 new mechanisms added.

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

### Other legitimately manual
`aide-acl-check`, `aide-xattr-check`, `audit-suid-files`, `audit-sgid-files`, `crypto-policy-not-overridden`, `emergency-service-auth`, `single-user-auth`, `ssh-access-control`, `single-logging-system`, `kernel-nx-enabled`, `rhel-vendor-supported`, `no-promiscuous-interfaces`

---

## Recommended Priority (Next 5)

Wave 1 completed items 2-8 from the original top 10. Remaining high-value targets:

1. **firewalld-loopback** — needs firewalld handler (Wave 2)
2. **gdm-xdmcp-disabled** — needs section-aware INI handler (Wave 2)
3. **ssh-approved-ciphers** / **ssh-approved-macs** — needs list-normalization in config_set_dropin (Wave 2)
4. **dns-nameservers-configured** / **chrony-sources** — variable-driven config_set (Wave 2)
5. **sudo-nopasswd-prohibited** / **sudo-require-password** — needs sudoers_policy_set handler (Wave 2)

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
