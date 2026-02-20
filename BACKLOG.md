# Backlog

Actionable work queue for Kensa. Pick the top unclaimed item. Each item has enough
context to start without additional preamble.

---

## Active

### P1 — Coverage Gaps

- [x] **Create missing CIS RHEL 9 rule YAMLs (102 rules)**
  Resolved through quality review PRs #13-#59. Zero missing rules, 95.3% coverage.

- [x] **Reach STIG RHEL 9 80% coverage (need 18 more implementations)**
  PR #60: Created 24 new rules. Coverage: 75.8% → 81.2% (362/446).

### P1 — New Frameworks

- [ ] **Add HIPAA compliance coverage**
  HIPAA Security Rule maps heavily to NIST 800-53 controls (which Kensa already covers).
  Create `mappings/hipaa/security-rule.yaml` mapping HIPAA administrative, physical, and
  technical safeguards (§164.308, §164.310, §164.312) to existing Kensa rules via their
  NIST 800-53 cross-references. Many rules already satisfy HIPAA requirements through the
  NIST mapping — this is primarily a mapping exercise, not new rule creation. Add
  `context/hipaa/` with authoritative baseline and validation script.

### P2 — Quality & Tooling

- [ ] **Man pages for kensa**
  RPM-installed CLI tools should ship man pages. Create `man/kensa.1` (general usage,
  all 9 subcommands) using groff/mdoc format. Add to `kensa.spec` `%install` section
  (`install -Dm 644 man/kensa.1 %{buildroot}%{_mandir}/man1/kensa.1`) and `%files`
  (`%{_mandir}/man1/kensa.1*`). Consider generating from Click help text or maintaining
  manually. Also create `man/kensa.conf.5` for config file format (`defaults.yml`,
  `conf.d/`, variable precedence).

- [ ] **Test benchmark: RHEL 8 and RHEL 9 STIG end-to-end validation**
  Stand up test VMs (or containers) for RHEL 8 and RHEL 9, run `kensa check` against
  the full STIG rule set, and validate results against OpenSCAP STIG profiles for the
  same hosts. Compare pass/fail/error rates, identify false positives and false negatives,
  and document discrepancies. Use `scripts/gap_analysis.py` as a starting point — it
  already compares Kensa vs OpenSCAP results. Target: zero false passes (every OpenSCAP
  fail should also fail in Kensa).

- [ ] **Add `kensa rollback` command for on-demand remediation reversal**
  Currently rollback only triggers automatically during `--rollback-on-failure` when a
  step or post-check fails. Pre-state data is not persisted after the run, so there's no
  way to undo a successful remediation that later causes problems. Needs:
  1. Persist step_results + PreState snapshots to SQLite history during `remediate`
  2. New `kensa rollback --host <host> --rule <rule-id>` command that reads stored
     pre-state and executes the existing rollback handlers
  The capture/rollback handler infrastructure already covers all 18 mechanism types.

- [x] **Add unit tests for check handlers**
  All 21 check handler types now have unit tests (80 tests in test_engine_checks.py).
  Covers pass, fail, and edge cases using mocked SSHSession.run() responses.

- [ ] **Add unit tests for remediation handlers**
  Same pattern as check handler tests — mock SSH, verify correct commands are built
  and evidence is captured.

- [ ] **Expand RHEL 8 framework coverage**
  CIS RHEL 8 at 56.3% (175/311), STIG RHEL 8 at 32% (116/366). Low priority but
  significant gap. Many RHEL 9 rules may apply with minor capability-gate adjustments.

### P3 — UX & Distribution

- [ ] **Shell completion for bash/zsh/fish**
  Click has built-in shell completion support (`click.shell_completion`). Add
  `_KENSA_COMPLETE=bash_source kensa` generation and install completion scripts
  via RPM (`/etc/bash_completion.d/kensa`). Covers subcommands, `--framework` values
  (from `list-frameworks`), `--rules` path completion, and `--format` choices.

- [ ] **Systemd timer for scheduled compliance scans**
  Create `contrib/kensa-scan.service` and `kensa-scan.timer` for periodic unattended
  scans. Service runs `kensa check` with configurable args via
  `/etc/sysconfig/kensa`. Timer defaults to weekly. RPM installs to
  `%{_unitdir}/` but does not enable by default. Results persist to SQLite history
  for `kensa diff` drift detection between runs.

- [ ] **HTML output format**
  Add `--format html` to complement JSON/CSV/PDF. Self-contained single-file HTML
  report with collapsible rule details, pass/fail summary, and framework coverage
  charts. Useful for email distribution and browser viewing without PDF tooling.
  Lower dependency footprint than PDF (no reportlab needed).

- [x] **Complete rule quality review — all 8 categories**
  Systematic 5-dimension review (RULE_REVIEW_GUIDE_V0.md) of all 484 rules.
  Completed: access-control (PRs #13-#20), audit (PRs #21-#28), services (PRs #29-#36),
  system (PRs #37-#42), filesystem (PRs #43-#48), network (PRs #49-#54),
  kernel (PRs #55-#56), logging (PRs #57-#59).

---

## Completed

- [x] **Complete check handler unit tests — all 21 types** _(2026-02-18)_
  Added 43 tests for 13 untested handlers. 247 total tests. All check handler
  types now have pass/fail/edge-case coverage with mocked SSH responses.

- [x] **file_content check handler + banner drift detection** _(2026-02-18)_
  PR #63: New `file_content` check handler for exact content matching. Fixed PR #62 bug where
  `{{ banner_text }}` wasn't resolved in `content:` field (not in SAFE_SUBSTITUTION_FIELDS).
  Banner rules now detect drift and auto-remediate when `banner_text` is overridden. 204 tests.

- [x] **Customizable login banner text** _(2026-02-18)_
  PR #62: Replaced hardcoded DOD consent banner with `{{ banner_text }}` template variable.
  Updated `banner-dod-consent` and `issue-net-configured` to use `file_content` remediation
  with `{{ banner_text }}`. Added example override template `rules/rules.d/99-banner-example.yml.example`.

- [x] **Fix command handler expected_stdout="" false positive** _(2026-02-18)_
  PR #61: `expected_stdout: ""` always passed due to `"" in any_string` being True.
  19 rules affected (audit permissions, crypto-policy-no-sha1, file checks).
  Fixed with empty-string special case. Added 2 regression tests (200 total).

- [x] **STIG RHEL 9 80% coverage** _(2026-02-18)_
  PR #60: Created 24 new rule YAMLs (8 package/service, 12 auditd config, 4 filesystem).
  STIG RHEL 9 coverage: 75.8% → 81.2% (362/446). 508 rules total.

- [x] **Logging category rule review — 18 rules, ~28 findings** _(2026-02-18)_
  3-phase fix across PRs #57-#59: fixed silently-ignored `state: "running"` in rsyslog-enabled
  (added `active: true`), added bidirectional conflicts_with for 3 duplicate/contradictory pairs
  (journald-forward-syslog ↔ journald-no-forward-syslog, journald-storage ↔ journald-storage-persistent,
  rsyslog-default-permissions ↔ rsyslog-file-permissions), removed wrong CIS 6.2.2.2 ref from
  journald-forward-syslog, removed 2 fabricated STIG vuln_ids (V-258062, V-258065), corrected 3 wrong
  CIS RHEL 8 sections (4.2.x→6.2.x for v4.0.0 renumbering), fixed 3 wrong CIS levels (L2→L1),
  added depends_on for rsyslog-enabled and journald-upload-enabled, added restart directive for
  journald-to-rsyslog drop-in, added CIS RHEL 8 refs to 10 rules, widened 3 rules from RHEL 9 to
  RHEL 8+, activated 12 controls in CIS RHEL 8 mapping. CIS RHEL 8 coverage: 52.4% → 56.3%.

- [x] **Kernel category rule review — 19 rules, ~18 findings** _(2026-02-18)_
  2-phase fix across PRs #55-#56: corrected 8 wrong STIG vuln_ids (usb-storage, bluetooth, dccp,
  tipc, sctp, rds, firewire, ip-forward), fixed CIS RHEL 9 levels (L2→L1 for protocol modules),
  corrected CIS RHEL 8 sections (squashfs, udf, usb-storage, ip-forward), added missing STIG RHEL 8
  refs (firewire, usb-storage, bluetooth), added CIS RHEL 8 ref for firewire, widened hardlink/symlink
  protection from RHEL 9 to RHEL 8+. Low-priority items deferred: description quality, persist_file
  for ip-forward, CIS RHEL 9 mapping discrepancy.

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
