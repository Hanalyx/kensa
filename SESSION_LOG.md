# Session Log

Append-only. Most recent session first. Read at start of each session for context.

---

## 2026-02-18 — Complete check handler unit tests (all 21 types)

### Done
- Added 43 new unit tests for 13 previously untested check handlers:
  `service_state`, `systemd_target`, `config_absent`, `file_not_exists`,
  `file_content_match`, `file_content_no_match`, `mount_option`, `grub_parameter`,
  `selinux_state`, `selinux_boolean`, `audit_rule_exists`, `sshd_effective_config`,
  `pam_module`, plus `config_value` comparator tests (>=, <=)
- Each handler has pass, fail, and edge-case tests using mocked SSH responses
- Fixed mock pattern: `shell_util.file_exists()` uses `test -f` not `test -e`

### Coverage
- Tests: 247 pass (+43), 508 rules valid, 21 check handler types fully tested

---

## 2026-02-18 — file_content check handler + banner drift detection (PR #63)

### Done
- Added new `file_content` check handler that compares entire file content against expected text
- Added `content` and `expected_content` to `SAFE_SUBSTITUTION_FIELDS` — previously
  `{{ banner_text }}` in remediation `content:` field was never resolved (bug in PR #62)
- Updated `banner-dod-consent` and `issue-net-configured` checks: replaced keyword grep
  with exact content matching via `file_content` check + `{{ banner_text }}`
- Now when admin overrides `banner_text` in `rules.d/`, check fails on servers with old text
  and remediation writes the new content automatically
- Added `file_content` to check handler registry, schema, and 4 unit tests

### Coverage
- Tests: 204 pass (+4), 508 rules valid, 21 check handler types

---

## 2026-02-18 — Customizable login banner text (PR #62)

### Done
- Replaced hardcoded DOD consent banner with `{{ banner_text }}` template variable
- Added `banner_text` variable to `rules/defaults.yml` with generic default
- Updated `banner-dod-consent.yml`: framework-agnostic title/description, automated
  `file_content` remediation for `/etc/issue` using `{{ banner_text }}`
- Updated `issue-net-configured.yml`: switched to `{{ banner_text }}` for `/etc/issue.net`,
  widened platform scope from RHEL 9 to RHEL 8+, added CIS RHEL 8 v4.0.0 reference
- Created `rules/rules.d/99-banner-example.yml.example` with documented override template
- Variable priority: CLI `--var` > `rules/rules.d/*.yml` > framework defaults > `defaults.yml`

### Coverage
- Tests: 200 pass, 508 rules valid

---

## 2026-02-18 — Fix command handler expected_stdout="" false positive (PR #61)

### Done
- Diagnosed production false-positive: `crypto-policy-no-sha1` (CIS 1.6.3) passed on a
  server where SHA1 was clearly present in `/etc/crypto-policies/state/CURRENT.pol`
- Root cause: `runner/handlers/checks/_command.py:63` used `expected_stdout not in result.stdout`
  — the empty string `""` is always "in" any string, so `expected_stdout: ""` never failed
- Fixed: empty string now means "expect no output" (`not result.stdout`); non-empty retains
  substring match semantics
- 19 rules affected: crypto-policy-no-sha1, 10 audit permission rules, selinux-not-disabled,
  groups-in-passwd-exist, no-duplicate-usernames/groupnames, accounts-password-shadowed,
  accounts-no-empty-passwords, no-netrc-files, no-forward-files
- Added 2 regression tests: `test_expected_empty_stdout_pass`, `test_expected_empty_stdout_fail`
- Updated CLAUDE.md with `expected_stdout` semantics documentation

### Coverage
- Tests: 200 pass (was 198), 508 rules valid

---

## 2026-02-18 — STIG RHEL 9 80% coverage (PR #60)

### Done
- Analyzed 111 unimplemented STIG RHEL 9 findings, categorized by difficulty
- Created 24 new rule YAMLs using existing check handlers:
  - 8 package/service rules: usbguard (V-258035/36), fapolicyd (V-258089/90),
    pcsc-lite/pcscd (V-258124/25), opensc (V-258126), rngd (V-257782)
  - 12 auditd config rules: write_logs (V-258170), local_events (V-258164),
    log_format (V-258169), flush (V-258168), overflow_action (V-258162),
    space_left (V-258157), admin_space_left_action (V-258158),
    backlog_limit (V-258173), immutable rules (V-258229),
    loginuid-immutable (V-258228), /etc/audit/ owner/group (V-270175/76)
  - 4 separate filesystem rules: /home (V-257843), /tmp (V-257844),
    /var (V-257845), /var/log (V-257846)
- Updated STIG RHEL 9 v2r7 mapping: moved 24 findings from unimplemented to controls
- CIS RHEL 9 missing rules resolved (was 102, now 0) — completed during quality review

### Coverage
- STIG RHEL 9: 81.2% (362/446) — up from 75.8%, exceeds 80% target
- CIS RHEL 9: 95.3% (303/318) — 0 missing rules, 0 gaps
- CIS RHEL 8: 56.3% (175/311)
- Tests: 198 pass, 508 rules valid

---

## 2026-02-18 — Logging category rule review (PRs #57-#59)

### Done
- Reviewed all 18 rules in `rules/logging/` against 5-dimension criteria
- ~28 findings: silently-ignored fields, 3 duplicate/contradictory pairs, 2 fabricated STIG vuln_ids,
  3 wrong CIS RHEL 8 sections, 3 wrong CIS levels, missing deps/reload, missing RHEL 8 refs
- Review agent incorrectly flagged `expected_exit` as silently ignored — confirmed it IS supported
  by the command handler (line 39 of `_command.py`)
- PR #57: Fixed silently-ignored `state: "running"` in rsyslog-enabled (added `active: true`),
  added bidirectional conflicts_with for 3 pairs (forward↔no-forward syslog, storage↔storage-persistent,
  default-permissions↔file-permissions), removed wrong CIS 6.2.2.2 from journald-forward-syslog,
  added depends_on for rsyslog-enabled
- PR #58: Removed 2 fabricated STIG vuln_ids (V-258062, V-258065), corrected 3 wrong CIS RHEL 8
  sections (4.2.x→6.2.x for v4.0.0 renumbering), fixed 3 CIS levels (L2→L1), added depends_on
  for journald-upload-enabled, added restart directive for journald-to-rsyslog
- PR #59: Added CIS RHEL 8 refs to 10 rules, widened 3 rules from RHEL 9 to RHEL 8+, activated
  12 controls in CIS RHEL 8 mapping
- Low-priority deferred: boilerplate descriptions (5 rules), journald drop-in override detection
  (5 rules use static config_value instead of systemd-analyze cat-config)
- ALL 8 CATEGORIES NOW COMPLETE — 484 rules reviewed

### Coverage
- CIS RHEL 8: 56.3% (175/311) — up from 52.4%
- CIS RHEL 9: unchanged
- Tests: 198 pass, 484 rules valid

---

## 2026-02-18 — Kernel category rule review (PRs #55-#56)

### Done
- Reviewed all 19 rules in `rules/kernel/` against 5-dimension criteria
- ~18 findings: 8 wrong STIG vuln_ids, 6 wrong CIS sections/levels, missing framework refs
- PR #55: Corrected 8 wrong STIG vuln_ids, fixed CIS levels (L2→L1 for protocol modules),
  fixed CIS RHEL 8 sections (squashfs, udf, usb-storage, ip-forward), removed incorrect stig_ids
- PR #56: Added STIG RHEL 8 refs (firewire/usb-storage/bluetooth), CIS RHEL 8 ref for firewire,
  widened hardlink/symlink protection from RHEL 9 to RHEL 8+
- Low-priority deferred: description quality, persist_file for ip-forward

### Coverage
- Tests: 198 pass, 484 rules valid

---

## 2026-02-18 — Network category rule review (PRs #49-#54)

### Done
- Reviewed all 42 rules in `rules/network/` against 5-dimension criteria
- ~64 findings across check accuracy, remediation, schema, references, forward compatibility
- Key structural issue: 22 granular sysctl rules duplicate 11 composite rules
- PR #49: Corrected 5 wrong STIG vuln_ids in granular sysctl rules
- PR #50: Added bidirectional conflicts_with between 11 composite/granular pairs (33 rules)
- PR #51: Removed wrong CIS refs from 22 granular rules, added unless guards, widened firewall-single-utility
- PR #52: Added missing STIG refs (log-martians V-257960, ipv6-forwarding V-257974), widened 3 nftables rules
- PR #53: Improved check accuracy — wireless-disabled fragile check, nftables always-pass defaults
- PR #54: Added CIS RHEL 8 refs to 20 granular rules, activated in mapping (coverage 46% → 52.4%)

### Coverage
- CIS RHEL 8: 52.4% (163/311) — up from 46%
- CIS RHEL 9: unchanged
- Tests: 198 pass, 484 rules valid

---

## 2026-02-18 — Filesystem category rule review (PRs #43-#48)

### Done
- Reviewed all 51 rules in `rules/filesystem/` against 5-dimension criteria
- Found ~68 findings across 40+ rules, organized into 6 fix phases
- Phase 1 (PR #43): Fixed silently-ignored `max_mode` and `missing_ok` fields in 5 rules — `file_permission` handler only reads `mode`, `owner`, `group`, `path`
- Phase 2 (PR #44): Resolved 11 duplicate rule pairs with bidirectional `conflicts_with` (fs-permissions-etc-* ↔ etc-*-permissions naming variants)
- Phase 3 (PR #45): Corrected wrong CIS section references in 27 rules — RHEL 8 used RHEL 9 numbering (6.1.x→7.1.x, mount rules needed deeper nesting), removed wrong RHEL 9 refs from 4 rules (6.1.1-6.1.3 = aide/auditd not permissions), removed fabricated refs from 3 rules
- Phase 4 (PR #46): Fixed 4 wrong STIG vuln_ids (fs-permissions-etc-passwd/group/gshadow/shadow)
- Phase 5 (PR #47): Converted 4 backup-file rules from fragile command method (stat|grep) to file_permission handler, added unless guard to sticky-bit-world-writable remediation
- Phase 6 (PR #48): Added CIS RHEL 8 v4.0.0 references and widened min_version 9→8 for 3 banner permission rules (motd, issue, issue.net)

### Next
- Continue rule quality review: network (42 rules), kernel (19), logging (18)

### Notes
- `file_permission` handler: only reads `mode`, `owner`, `group`, `path`, `glob`. Fields `max_mode` and `missing_ok` are silently ignored
- RHEL 8 v4.0.0 renumbered file permission sections from 6.1.x to 7.1.x and mount sections use deeper nesting (1.1.2.x.y vs 1.1.x.y)
- 11 duplicate rule pairs exist because RHEL 8 mapping uses `fs-permissions-*` rules while RHEL 9 mapping uses `etc-*-permissions` rules for the same CIS sections
- CIS RHEL 9 sections 6.1.1-6.1.3 map to aide-installed, aide-scheduled, auditd-tools-integrity (NOT file permissions)

---

## 2026-02-18 — System category rule review (PRs #37-#42)

### Done
- Reviewed all 56 rules in `rules/system/` against 5-dimension criteria
- Found ~30 findings across 22 rules, organized into 6 fix phases
- Phase 1 (PR #37): Fixed silently-ignored fields in 3 rules — `state:` in cron-enabled, `mode:` in selinux-enforcing, `expected_pattern`/`on_missing` in coredump-storage-disabled
- Phase 2 (PR #38): Fixed inverted check logic in 2 rules — grub-selinux-not-disabled (replaced grep|head with negated grep -q), crypto-policy-disable-sha1-signatures (replaced grep -v SHA1 with grep -q NO-SHA1)
- Phase 3 (PR #39): Corrected 22 wrong STIG vuln_ids (systematic offset error), removed stig_id fields, removed STIG blocks from 2 unmapped rules
- Phase 4 (PR #40): Fixed crypto-policy remediation dedup in 3 rules — added sed strip + re-append pattern and `unless` guards
- Phase 5 (PR #41): Resolved duplicate pair (crypto-policy-disable-sha1-signatures ↔ crypto-policy-no-sha1), added depends_on for crypto-policy-fips, removed wrong CIS ref from no-graphical-target
- Phase 6 (PR #42): Added CIS RHEL 8 v4.0.0 references to 17 rules, activated 13 controls in RHEL 8 mapping

### Next
- Continue rule quality review: filesystem (51 rules), network (42), kernel (19), logging (18)

### Notes
- CIS RHEL 8 coverage improved from 42% to 46% (130→143 implemented)
- STIG vuln_ids in system rules had a systematic offset error — nearly all 22 were pointing to the wrong finding
- `selinux_state` handler reads `state` key (not `mode`), `service_state` handler reads `enabled`/`active` (not `state`)
- `command` handler only supports `run`, `expected_exit`, `expected_stdout` — `expected_pattern` and `on_missing` silently ignored

---

## 2026-02-18 — Services category rule review (PRs #29-#36)

### Done
- Reviewed all 92 rules in `rules/services/` against 5-dimension criteria
- Found ~139 findings across 80+ rules, organized into 8 fix phases
- Phase 1 (PR #29): Replaced `state: "stopped"/"running"` with `active: false/true` in 30 rules — `service_state` handler silently ignores `state:` key
- Phase 2 (PR #30): Fixed 9 GDM rules with always-pass default; added `conflicts_with`/`depends_on`
- Phase 3 (PR #31): Fixed chrony-user `separator: "="` and debug-shell handler (command→service_state)
- Phase 4 (PR #32): Resolved 8 duplicate rule pairs with bidirectional `conflicts_with`
- Phase 5 (PR #33): Removed 6 wrong STIG vuln_ids and 3 duplicate stig_ids
- Phase 6 (PR #34): Corrected CIS section references across 23 rules (RHEL 8 v4.0.0 renumbering 2.2.x→2.1.x)
- Phase 7 (PR #35): Widened `min_version: 9` to `8` for 44 rules
- Phase 8 (PR #36): Added CIS RHEL 8 v4.0.0 references to 10 rules, moved from unimplemented to active in mapping

### Next
- Continue rule quality review: system (56 rules), filesystem (51), network (42), kernel (19), logging (18)

### Notes
- CIS RHEL 8 coverage improved from 39% to 42% (120→130 implemented)
- CIS RHEL 8 Chapter 2 (Services) went from 0 to 8 implemented controls
- STIG mapping has wrong chrony/postfix rule mappings (V-257943/44/46/47 → pam-pwquality rules) — not fixed in this review, flagged for future

---

## 2026-02-16 — FedRAMP Moderate Rev 5 baseline integration (PR #8)

### Done
- Fetched official GSA OSCAL profile to identify all 323 FedRAMP Moderate Rev 5 controls
- Created `context/fedramp/moderate-rev5-baseline.yaml` — authoritative control list with applicability tags (83 technical, 56 semi-technical, 184 procedural)
- Created `context/fedramp/FEDRAMP_MODERATE_REFERENCE.md` — human-readable reference with FedRAMP-specific parameters
- Updated `mappings/fedramp/moderate.yaml` — added `control_ids` manifest, source citation, 9 new technical controls, 232 `unimplemented` entries. Mapping is 100% accounted (91 implemented + 232 unimplemented = 323)
- Created `scripts/fedramp_validate.py` — dev-time gap analysis with `--json` and `--family` flags
- Created `scripts/parse_fedramp_oscal.py` — OSCAL parser to regenerate baseline from official sources
- Created `.claude/commands/fedramp.md` — `/fedramp` slash command for interactive gap analysis
- Cleaned up stale scratch files: CIS PDFs, CIS/STIG/NIST gap analysis markdown, STIG zips, `extracted/`, `results/`
- Updated `CLAUDE.md` with correct file references
- Updated `BACKLOG.md` with completed FedRAMP work

### Next
- Pick up top backlog item: create missing CIS RHEL 9 rule YAMLs (102 rules)
- Or: reach STIG RHEL 9 80% coverage (18 more implementations)

### Notes
- 5 controls in the existing mapping were not in the official OSCAL baseline (AC-10, AC-3(4), AU-5(1), AU-8(1), SC-3) — kept in `controls:` but excluded from `control_ids:` manifest
- FedRAMP rule coverage is 28.2% (91/323) — most uncovered controls are procedural/organizational and cannot be enforced via SSH

---

## 2026-02-16 — Session continuity infrastructure + branch protection

### Done
- Created `BACKLOG.md` with prioritized work queue seeded from TECH_DEBT.md and IMPLEMENTATION_PLAN.md
- Created `SESSION_LOG.md` (this file) for session handoff notes
- Added session workflow section to `CLAUDE.md` (quality sweeps, review checklist, start/end protocol)
- Added `BACKLOG.md`, `SESSION_LOG.md`, `CLAUDE.md` to `.gitignore` (local workflow files, not shared)
- Removed `CLAUDE.md` from git tracking (file remains on disk)
- Protected `main` branch: requires PR, status checks must pass, no force push/delete, no review required
- Merged PR #7 (`chore: gitignore session continuity files`)

### Next
- Pick up top backlog item: create missing CIS RHEL 9 rule YAMLs (102 rules)
- Or: reach STIG RHEL 9 80% coverage (18 more implementations)

### Notes
- Direct pushes to `main` are no longer possible — all changes go through PRs
- Branch protection does not require reviews, only passing status checks

---

## 2026-02-16 — Docs refresh (PR #6)

### Done
- Updated `TECH_DEBT.md` to reflect current state — resolved stale PRD items
- Rewrote `prd/IMPLEMENTATION_PLAN.md` with current stats (390 rules, 94% CIS, 76% STIG)
- Marked phases 1/3/4/5 complete, documented remaining Phase 2 gap
- Updated `prd/p3-2-rule-scaling.md` status to "Largely Complete (superseded)"

### Next
- Address Phase 2 remaining work: 102 missing CIS rule YAMLs, STIG 80% target

### Notes
- CIS RHEL 9 coverage at 94% exceeds the 85% target, but 102 dangling rule references remain

---

## 2026-02-16 — CIS RHEL 9 mapping fix (PR #5)

### Done
- Converted CIS RHEL 9 mapping from incompatible nested format to standard format
- Fixed `framework:` field, `sections:` structure, added `unimplemented:` and `control_ids:`
- Removed dead `order_by_framework()` from `runner/mappings.py`

### Next
- Address the 102 missing rule YAMLs referenced in the CIS mapping

### Notes
- The mapping previously registered with an empty ID and zero sections due to format mismatch

---

## 2026-02-15 — Sed over-escaping and test alignment (PR #4)

### Done
- Fixed sed over-escaping in `shell_util.escape_sed()` — was double-escaping
- Aligned test mocks with actual handler signatures and return types

### Next
- CIS mapping format fix (became PR #5)

### Notes
- None

---

## 2026-02-15 — P1/P2 tech debt resolution (PR #3)

### Done
- Resolved P1 items: missing evidence on check handler edge cases, propagated sub-check evidence
- Added synthetic `Evidence(method="error")` for unknown check/package/module states
- Resolved P2 items: updated stale handler counts in CLAUDE.md, fixed architecture.md descriptions
- Added `from __future__ import annotations` to 5 modules missing it

### Next
- Sed over-escaping issue (became PR #4)

### Notes
- None

---

## 2026-02-15 — CIS v2.0.0 rules and cleanup (PR #2)

### Done
- Added CIS v2.0.0 rules batch
- Renamed inventory references to neutral naming convention
- General cleanup

### Next
- Tech debt sweep (became PR #3)

### Notes
- None

---

## 2026-02-15 — Shell injection hardening (PR #1)

### Done
- Added `shell_util.escape_sed()` and `shell_util.escape_grep_bre()` helpers
- Applied escaping across remediation, rollback, and capture handlers
- Fixed unquoted `rule` arg in `auditctl` command
- Added `strict_host_keys` param to `SSHSession` with CLI flag

### Next
- Evidence edge case fixes (became PR #3)

### Notes
- This was the first security-focused sweep of the codebase
