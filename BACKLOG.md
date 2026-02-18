# Backlog

Actionable work queue for Aegis. Pick the top unclaimed item. Each item has enough
context to start without additional preamble.

---

## Active

### P1 — Coverage Gaps

- [ ] **Create missing CIS RHEL 9 rule YAMLs (102 rules)**
  CIS RHEL 9 mapping references 102 rule IDs with no corresponding YAML in `rules/`.
  These are dangling references — the mapping says "section X is implemented by rule Y"
  but rule Y does not exist. Options: create rules where existing check handlers support
  it, move the rest to `unimplemented:` in the mapping.
  Run `aegis coverage --framework cis-rhel9-v2.0.0` to see the full list.
  Acceptance: zero missing rules in CIS RHEL 9 mapping.

- [ ] **Reach STIG RHEL 9 80% coverage (need 18 more implementations)**
  Currently at 76% (338/446). The P3-2 target was 80%. Need to identify the 18
  highest-value STIG findings not yet covered and create rule YAMLs + any new
  handlers needed.
  Acceptance: `aegis coverage --framework stig-rhel9-v2r7` shows >= 80%.

### P2 — Quality & Tooling

- [ ] **Add unit tests for check handlers**
  No test suite exists for the check handler functions. Start with the most critical
  handlers: `config_value`, `file_permission`, `sysctl_value`, `service_state`.
  Use mocked `SSHSession.run()` responses.

- [ ] **Add unit tests for remediation handlers**
  Same pattern as check handler tests — mock SSH, verify correct commands are built
  and evidence is captured.

- [ ] **Expand RHEL 8 framework coverage**
  CIS RHEL 8 at 52% (163/311), STIG RHEL 8 at 32% (116/366). Low priority but
  significant gap. Many RHEL 9 rules may apply with minor capability-gate adjustments.

- [ ] **Continue rule quality review — remaining categories**
  Systematic 5-dimension review (RULE_REVIEW_GUIDE_V0.md) of all rules by category.
  Completed: access-control (PRs #13-#20), audit (PRs #21-#28), services (PRs #29-#36),
  system (PRs #37-#42), filesystem (PRs #43-#48), network (PRs #49-#54).
  Remaining: kernel (19), logging (18).

---

## Completed

- [x] **Network category rule review — 42 rules, ~64 findings** _(2026-02-18)_
  6-phase fix across PRs #49-#54: corrected 5 wrong STIG vuln_ids, resolved 11 composite/granular
  duplicate pairs with conflicts_with (33 rules), removed wrong CIS refs from 22 granular rules,
  added unless guards to wireless-disabled and firewalld-loopback, widened platform scope for
  firewall-single-utility and 3 nftables rules, added missing STIG refs (log-martians, ipv6-forwarding),
  improved check accuracy for wireless-disabled and 3 nftables default implementations, added CIS
  RHEL 8 refs to 20 granular rules and activated them in mapping (coverage 46% → 52.4%).

- [x] **Filesystem category rule review — 51 rules, ~68 findings** _(2026-02-18)_
  6-phase fix across PRs #43-#48: fixed silently-ignored max_mode/missing_ok fields (5 rules),
  resolved 11 duplicate rule pairs with conflicts_with, corrected wrong CIS RHEL 8/9 section
  references (27 rules), fixed 4 wrong STIG vuln_ids, converted 4 backup-file rules from fragile
  command method to file_permission handler, added unless guard to sticky-bit remediation, added
  CIS RHEL 8 refs and widened platform scope for 3 banner rules.

- [x] **System category rule review — 56 rules, ~30 findings** _(2026-02-18)_
  6-phase fix across PRs #37-#42: fixed silently-ignored fields (state/mode/expected_pattern),
  fixed inverted check logic (grub-selinux, crypto-sha1), corrected 22 wrong STIG vuln_ids,
  fixed crypto-policy remediation dedup (3 rules), resolved duplicate pairs and wrong CIS refs,
  added missing CIS RHEL 8 v4.0.0 references to 17 rules. CIS RHEL 8 coverage: 46% (143/311).

- [x] **Services category rule review — 92 rules, ~139 findings** _(2026-02-18)_
  8-phase fix across PRs #29-#36: replaced silently-ignored `state:` fields (30 rules),
  fixed GDM always-pass defaults (9 rules), resolved 8 duplicate pairs, corrected
  wrong STIG/CIS references, widened platform scope to RHEL 8, added missing CIS
  RHEL 8 v4.0.0 references. CIS RHEL 8 Chapter 2 coverage went from 0 to 8.

- [x] **Audit category rule review — 92 rules, ~146 findings** _(2026-02-17)_
  8-phase fix across PRs #21-#28.

- [x] **Access-control category rule review — 114 rules, ~78 findings** _(2026-02-17)_
  8-phase fix across PRs #13-#20.


- [x] **FedRAMP Moderate Rev 5 baseline integration** _(2026-02-16)_
  Integrated the official FedRAMP Moderate Rev 5 baseline (323 controls, 18 families)
  from the GSA OSCAL profile. Created authoritative reference data
  (`context/fedramp/moderate-rev5-baseline.yaml`, `context/fedramp/FEDRAMP_MODERATE_REFERENCE.md`).
  Completed the mapping (`mappings/fedramp/moderate.yaml`) with `control_ids` manifest,
  9 new technical control entries, and 232 `unimplemented` entries — 100% accounted.
  Added dev-time validation (`scripts/fedramp_validate.py`), OSCAL parser
  (`scripts/parse_fedramp_oscal.py`), and `/fedramp` Claude Code slash command.
  PR: #8.
