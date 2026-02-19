# CHANGELOG

<!-- version list -->

## v1.12.4 (2026-02-19)

### Bug Fixes

- **benchmark**: Filter PCI-DSS references from CIS section parser
  ([#72](https://github.com/Hanalyx/aegis/pull/72),
  [`b7d2138`](https://github.com/Hanalyx/aegis/commit/b7d213812dda04c0f91c4c6c8ddf5a458c15a9e4))


## v1.12.3 (2026-02-19)

### Bug Fixes

- **audit**: Normalize auditctl output and rewrite 5 audit rule checks
  ([#71](https://github.com/Hanalyx/aegis/pull/71),
  [`c366ebe`](https://github.com/Hanalyx/aegis/commit/c366ebed3146e8faa45051aaf9b0a7865a6345ef))


## v1.12.2 (2026-02-19)

### Bug Fixes

- **rules**: Tune scope for banner, pam-wheel, nologin, timeout, and aide checks
  ([#70](https://github.com/Hanalyx/aegis/pull/70),
  [`ea187dc`](https://github.com/Hanalyx/aegis/commit/ea187dc3ca6381d96d53e65ff28e3e91ae3a95e8))


## v1.12.1 (2026-02-19)

### Bug Fixes

- **rules**: Improve SSH check accuracy with algorithm validation and range checks
  ([#69](https://github.com/Hanalyx/aegis/pull/69),
  [`34b30cc`](https://github.com/Hanalyx/aegis/commit/34b30ccfc15a7da73fea36860b9f3cd8f5f0ff31))


## v1.12.0 (2026-02-19)

### Features

- **benchmark**: Add mapping error detection with allowlist and heuristic
  ([#68](https://github.com/Hanalyx/aegis/pull/68),
  [`a889ff0`](https://github.com/Hanalyx/aegis/commit/a889ff076953110d9a0ac7449a0f2cb5e9262678))


## v1.11.1 (2026-02-19)

### Bug Fixes

- **rules**: Correct 5 check bugs found via benchmark comparison
  ([`50cdd5f`](https://github.com/Hanalyx/aegis/commit/50cdd5ff4d8434e357accd08cb5a9dd6764d06c1))


## v1.11.0 (2026-02-19)

### Documentation

- Add PR workflow convention to CLAUDE.md
  ([`0774308`](https://github.com/Hanalyx/aegis/commit/07743080bb0fa6d91ba5c980da63a4e406e9725a))

### Features

- **benchmark**: Add multi-host comparison and coverage dimension (Phase 2)
  ([`76f8024`](https://github.com/Hanalyx/aegis/commit/76f80247230e7d0e83f11daf214a61ffeebf354c))


## v1.10.0 (2026-02-19)

### Documentation

- Update tracking docs for check handler test coverage
  ([`5285232`](https://github.com/Hanalyx/aegis/commit/528523288cbb78e4038c6de790bc89cab176ecda))

- Update tracking docs for PR #63 (file_content check handler)
  ([`7f7206c`](https://github.com/Hanalyx/aegis/commit/7f7206c0bc63983ac17d23a129bdd088d4380b27))

### Features

- **benchmark**: Add control-level multi-dimensional benchmarking framework (Phase 1)
  ([`74e28f5`](https://github.com/Hanalyx/aegis/commit/74e28f5b388e798203ffaa225202f641324aa777))

### Testing

- **checks**: Add unit tests for all 21 check handler types
  ([`9d3a007`](https://github.com/Hanalyx/aegis/commit/9d3a007a4b7102cae0b924458847d6a96f70b499))


## v1.9.0 (2026-02-18)

### Documentation

- Update session log and backlog for PR #62 (customizable banner)
  ([`16f654d`](https://github.com/Hanalyx/aegis/commit/16f654d183db47770de408c9eab7b6b9aabb902f))

### Features

- **checks**: Add file_content check handler for exact content matching
  ([#63](https://github.com/Hanalyx/aegis/pull/63),
  [`07f5bbb`](https://github.com/Hanalyx/aegis/commit/07f5bbb81f980f64aadf87e584bd696cfd6e231f))


## v1.8.0 (2026-02-18)

### Features

- **banner**: Make login banner text customizable via banner_text variable
  ([#62](https://github.com/Hanalyx/aegis/pull/62),
  [`8dbbeb0`](https://github.com/Hanalyx/aegis/commit/8dbbeb014f62f10adebca1781525b575cf88b25e))


## v1.7.1 (2026-02-18)

### Bug Fixes

- **checks**: Command handler expected_stdout="" always passed (false positive)
  ([`a5b2af1`](https://github.com/Hanalyx/aegis/commit/a5b2af13648a5bcaf02ebefd09e15f81ec2a0ae9))


## v1.7.0 (2026-02-18)

### Bug Fixes

- **logging**: Add CIS RHEL 8 v4.0.0 references to 10 rules, widen 3 to RHEL 8
  ([`f8b8370`](https://github.com/Hanalyx/aegis/commit/f8b83708d756cdc5f20af93762728bf180b5066a))

### Features

- **stig**: Add 24 STIG RHEL 9 rules to reach 80% coverage target
  ([`b6cf0ee`](https://github.com/Hanalyx/aegis/commit/b6cf0ee1a657c60129454b71ffadebd1b3ec091e))


## v1.6.46 (2026-02-18)

### Bug Fixes

- **logging**: Remove fabricated STIG refs, correct CIS sections/levels, add missing deps
  ([`21d794b`](https://github.com/Hanalyx/aegis/commit/21d794bc16f641c8985ada2525f0987978dcca6d))


## v1.6.45 (2026-02-18)

### Bug Fixes

- **logging**: Fix silently-ignored service state and add conflicts_with for duplicate pairs
  ([`f44f869`](https://github.com/Hanalyx/aegis/commit/f44f8690a7d2d2bad5e47223b68f2f7a088f8706))


## v1.6.44 (2026-02-18)

### Bug Fixes

- **kernel**: Add missing STIG/CIS refs, widen platform scope
  ([`4f2ca02`](https://github.com/Hanalyx/aegis/commit/4f2ca02d950d85a92f8ccd4796293d5cc8506fdf))


## v1.6.43 (2026-02-18)

### Bug Fixes

- **kernel**: Correct wrong STIG vuln_ids and CIS section references
  ([`2334617`](https://github.com/Hanalyx/aegis/commit/2334617f7ecf15d14f629c46250b7c0ce2118f0e))

### Documentation

- Update tracking for completed network rule review (PRs #49-#54)
  ([`cc82893`](https://github.com/Hanalyx/aegis/commit/cc8289369d1a5400f535ab8eaff968f8cb99defe))


## v1.6.42 (2026-02-18)

### Bug Fixes

- **network**: Add CIS RHEL 8 refs to 20 granular sysctl rules
  ([`046ec9c`](https://github.com/Hanalyx/aegis/commit/046ec9c369ba2f238bf4775f6196b7e90d49d910))


## v1.6.41 (2026-02-18)

### Bug Fixes

- **network**: Improve check accuracy for wireless and nftables rules
  ([`a2b03d0`](https://github.com/Hanalyx/aegis/commit/a2b03d0bd128c4e3fd98dca71eb24903c05c2aa9))


## v1.6.40 (2026-02-18)

### Bug Fixes

- **network**: Add missing STIG refs and widen nftables platform scope
  ([`8f281bc`](https://github.com/Hanalyx/aegis/commit/8f281bce8562021ba3138b0b899e09b26f14f700))


## v1.6.39 (2026-02-18)

### Bug Fixes

- **network**: Remove wrong CIS refs from granular rules, add remediation guards
  ([`c98d28d`](https://github.com/Hanalyx/aegis/commit/c98d28d89775c0247221ca691966a2eea59ed771))


## v1.6.38 (2026-02-18)

### Bug Fixes

- **network**: Add conflicts_with between 11 composite/granular sysctl rule pairs
  ([`3e66dc0`](https://github.com/Hanalyx/aegis/commit/3e66dc0e409daf5eae609b7b2d4398da1e04666a))


## v1.6.37 (2026-02-18)

### Bug Fixes

- **network**: Correct wrong STIG vuln_ids in 5 sysctl rules
  ([`ef176ef`](https://github.com/Hanalyx/aegis/commit/ef176ef727f99a9744e1c7c5437d1ca6bb3ff658))


## v1.6.36 (2026-02-18)

### Bug Fixes

- **filesystem**: Add CIS RHEL 8 refs and widen platform scope for banner rules
  ([`a79ebee`](https://github.com/Hanalyx/aegis/commit/a79ebeeda457e6f240bf9de02ba434e69352a400))


## v1.6.35 (2026-02-18)

### Bug Fixes

- **filesystem**: Improve check accuracy for backup file and sticky-bit rules
  ([`0455d55`](https://github.com/Hanalyx/aegis/commit/0455d55c677dc2237318d2cb56ad143edf9180e5))


## v1.6.34 (2026-02-18)

### Bug Fixes

- **filesystem**: Correct wrong STIG vuln_ids in 4 fs-permissions rules
  ([`1fcae5c`](https://github.com/Hanalyx/aegis/commit/1fcae5c0ca35874f0bb180c493015fd339d2ee40))


## v1.6.33 (2026-02-18)

### Bug Fixes

- **filesystem**: Correct wrong CIS section references in 27 rules
  ([`a18d303`](https://github.com/Hanalyx/aegis/commit/a18d303c6c0f5f0d1584973ba8ffec4b2e9794d7))


## v1.6.32 (2026-02-18)

### Bug Fixes

- **filesystem**: Add conflicts_with to 11 duplicate rule pairs
  ([`3159fa1`](https://github.com/Hanalyx/aegis/commit/3159fa12799f7f67d71bcd50d1b1e6c22e5158ae))


## v1.6.31 (2026-02-18)

### Bug Fixes

- **filesystem**: Replace silently-ignored max_mode/missing_ok with correct fields
  ([`8b57a28`](https://github.com/Hanalyx/aegis/commit/8b57a28fb832f94516de4bd94f8aca020d820a6a))


## v1.6.30 (2026-02-18)

### Bug Fixes

- **system**: Add missing CIS RHEL 8 v4.0.0 references to 17 system rules
  ([`319dfe0`](https://github.com/Hanalyx/aegis/commit/319dfe05eee6f4bebc05ea00a0a08320bb7a6578))


## v1.6.29 (2026-02-18)

### Bug Fixes

- **system**: Resolve duplicate rule pairs and remove wrong CIS ref
  ([`fd8b4ce`](https://github.com/Hanalyx/aegis/commit/fd8b4ced33fd56f181ba71f754ad8ad2cf20dd79))


## v1.6.28 (2026-02-18)

### Bug Fixes

- **system**: Add deduplication to crypto-policy remediations
  ([`1b614e8`](https://github.com/Hanalyx/aegis/commit/1b614e8f0144e42dbcfdaee6024bd919c73936ea))


## v1.6.27 (2026-02-18)

### Bug Fixes

- **system**: Correct STIG vuln_id references across 22 rules
  ([`071c49e`](https://github.com/Hanalyx/aegis/commit/071c49e1f2a53b74bf3ee3d3cadd99e0d3d9efef))


## v1.6.26 (2026-02-18)

### Bug Fixes

- **system**: Correct inverted check logic in 2 rules
  ([`40489f2`](https://github.com/Hanalyx/aegis/commit/40489f221871a3421e9097904735227ebb873a4c))


## v1.6.25 (2026-02-18)

### Bug Fixes

- **system**: Correct silently-ignored check fields in 3 rules
  ([`f3b21c5`](https://github.com/Hanalyx/aegis/commit/f3b21c5524c056a34d283ebe52d4b263aa385a0b))


## v1.6.24 (2026-02-18)

### Bug Fixes

- **services**: Add missing CIS RHEL 8 v4.0.0 references to 10 rules
  ([`5a532cc`](https://github.com/Hanalyx/aegis/commit/5a532cc12cdf46ada7997d1cc23fd866357dfe85))


## v1.6.23 (2026-02-18)

### Bug Fixes

- **services**: Widen platform scope from min_version 9 to 8
  ([`4d626c5`](https://github.com/Hanalyx/aegis/commit/4d626c5455c1dd86d4cab750308b495b78479b33))


## v1.6.22 (2026-02-18)

### Bug Fixes

- **services**: Correct CIS section references across 23 rules
  ([`e5bd2e1`](https://github.com/Hanalyx/aegis/commit/e5bd2e1c7ee4d2edaad6504548a88eee3ed17e31))


## v1.6.21 (2026-02-18)

### Bug Fixes

- **services**: Correct wrong STIG vuln_id/stig_id references
  ([`0d8305c`](https://github.com/Hanalyx/aegis/commit/0d8305c42a7b3d65d8144455dd7f4ec8d38f6f60))


## v1.6.20 (2026-02-18)

### Bug Fixes

- **services**: Resolve 8 duplicate rule pairs with conflicts_with/depends_on
  ([`c4072b6`](https://github.com/Hanalyx/aegis/commit/c4072b6a631f6dbb2999f614b0f578a81e0802a7))


## v1.6.19 (2026-02-18)

### Bug Fixes

- **services**: Fix chrony-user separator and debug-shell handler type
  ([`e45936d`](https://github.com/Hanalyx/aegis/commit/e45936dbdf6d78974c6ec55a214dd012d8bc0b18))


## v1.6.18 (2026-02-18)

### Bug Fixes

- **services**: Fix GDM default always-pass and add depends_on/conflicts_with
  ([`d7354fc`](https://github.com/Hanalyx/aegis/commit/d7354fc0906dcd4799357ecad20c60c6c66c1dd8))


## v1.6.17 (2026-02-18)

### Bug Fixes

- **services**: Replace state: stopped/running with active: false/true
  ([`b08d248`](https://github.com/Hanalyx/aegis/commit/b08d248f56d4963269d5426e7033cbd43dbabed8))

### Documentation

- Add services category review plan with 139 findings across 8 phases
  ([`be8115e`](https://github.com/Hanalyx/aegis/commit/be8115e56acc96c72d20a7fd8ac5d0d7692b11a1))

- Mark audit category as reviewed in CLAUDE.md
  ([`a499328`](https://github.com/Hanalyx/aegis/commit/a4993280fc6b83ea4cd1b82371a5066d21c5a33f))

- Update review tracking table with completed audit review
  ([`898ca7b`](https://github.com/Hanalyx/aegis/commit/898ca7b264c43d17eac17085fd8b6ca482d80c77))


## v1.6.16 (2026-02-18)

### Bug Fixes

- **audit**: Correct framework references across 36 audit rules
  ([`619cb74`](https://github.com/Hanalyx/aegis/commit/619cb748dbda204ed4d16c6f9b2d88b12843537a))


## v1.6.15 (2026-02-18)

### Bug Fixes

- **audit**: Add missing depends_on declarations to 9 rules
  ([`f4fcf5a`](https://github.com/Hanalyx/aegis/commit/f4fcf5aa3bf464e3accdd44ed0e4138e6619917f))


## v1.6.14 (2026-02-18)

### Bug Fixes

- **audit**: Add missing separator for auditd.conf and remove error-swallowing 2>/dev/null
  ([`48b5ab2`](https://github.com/Hanalyx/aegis/commit/48b5ab2dcbf782ec5f99ad8970861920ea540981))


## v1.6.13 (2026-02-18)

### Bug Fixes

- **audit**: Expand 5 incomplete multi-condition remediations to full steps
  ([`ce27916`](https://github.com/Hanalyx/aegis/commit/ce2791625da06614e78953385341c7a4ddc216a7))


## v1.6.12 (2026-02-18)

### Bug Fixes

- **audit**: Migrate 13 weak grep checks to audit_rule_exists handler
  ([`29993ca`](https://github.com/Hanalyx/aegis/commit/29993ca6500ed7b3f5fb0ed591908552b7743a12))


## v1.6.11 (2026-02-18)

### Bug Fixes

- **audit**: Resolve 14 duplicate rule pairs with supersedes/conflicts_with
  ([`0bd767f`](https://github.com/Hanalyx/aegis/commit/0bd767f6382b0dcf2cf8e4fb3c94d3f6676bfc57))


## v1.6.10 (2026-02-18)

### Bug Fixes

- **audit**: Correct check logic bugs in immutable and permissions rules
  ([`97dd7c6`](https://github.com/Hanalyx/aegis/commit/97dd7c626085f16e1694c773f93da54da7e6f15f))


## v1.6.9 (2026-02-18)

### Bug Fixes

- **audit**: Correct runtime-critical field and schema bugs
  ([`73045c6`](https://github.com/Hanalyx/aegis/commit/73045c6890d5d7d8dfc4f156201fa293c187de05))

### Chores

- **rules**: Add missing framework references to access-control rules
  ([`605844d`](https://github.com/Hanalyx/aegis/commit/605844d703e5e082da0b99f2dd942372e79289bf))

### Documentation

- Add audit category review plan
  ([`ee9c117`](https://github.com/Hanalyx/aegis/commit/ee9c1170237461f16d4cea17574003e778630bcc))

- Update CLAUDE.md and review guide after access-control review
  ([`65fa490`](https://github.com/Hanalyx/aegis/commit/65fa4909f912a979f4ef0518d27323d5dded1248))


## v1.6.8 (2026-02-18)

### Bug Fixes

- **rules**: Improve remediation quality and check coverage
  ([`602806c`](https://github.com/Hanalyx/aegis/commit/602806c19fe8c43baf33a10a324beabbddd2fd15))


## v1.6.7 (2026-02-18)

### Bug Fixes

- **rules**: Add capability gating, dependencies, and fix remaining field names
  ([`4a0fcee`](https://github.com/Hanalyx/aegis/commit/4a0fceeac54617c9f4206bfd26a9610218551ac7))


## v1.6.6 (2026-02-18)

### Bug Fixes

- **rules**: Migrate 23 SSH rules from static config to effective config
  ([`16f5c9f`](https://github.com/Hanalyx/aegis/commit/16f5c9f3b1805b5dec6d8afcbd679eb16210f738))


## v1.6.5 (2026-02-18)

### Bug Fixes

- **rules**: Correct logic bugs in root-umask, shell-timeout, pam-faillock-enabled
  ([`aaa6920`](https://github.com/Hanalyx/aegis/commit/aaa69209eddd2714acb32dcf089e9b78ce569459))


## v1.6.4 (2026-02-18)

### Bug Fixes

- **rules**: Consolidate 8 duplicate rule pairs
  ([`dfed23e`](https://github.com/Hanalyx/aegis/commit/dfed23ee4deb9d669322a9260915ce47bd6823d8))


## v1.6.3 (2026-02-18)

### Bug Fixes

- **rules**: Use canonical note: field for manual remediation text
  ([`47e54f0`](https://github.com/Hanalyx/aegis/commit/47e54f05e9ca8013e911c094b78d6407315dfe41))


## v1.6.2 (2026-02-18)

### Bug Fixes

- **rules**: Use canonical field names in command check definitions
  ([`825bec5`](https://github.com/Hanalyx/aegis/commit/825bec5b7c37c6ab716adfa03fd6f3315f899821))

### Documentation

- Add Rule Review Guide V0 for canonical rule quality criteria
  ([`438a89a`](https://github.com/Hanalyx/aegis/commit/438a89a41e7bc3aa1bcf7c16ab5ae9b45343d877))

### Refactoring

- **cli**: Extract host execution and rule selection into focused modules
  ([`26c2a4f`](https://github.com/Hanalyx/aegis/commit/26c2a4f9d25fa5ae692c44e925bf483ae1192d59))

- **mappings**: Unify YAML format to controls:/rules: across all frameworks
  ([`dffab97`](https://github.com/Hanalyx/aegis/commit/dffab971dea60f599faa83286cb21a8f6a765d37))


## v1.6.1 (2026-02-17)

### Bug Fixes

- **cis**: Correct RHEL 9 v2.0.0 section numbering for kernel module controls
  ([`ac98067`](https://github.com/Hanalyx/aegis/commit/ac98067bc1044211ac9f32b0dcf9b58bb1381930))


## v1.6.0 (2026-02-17)

### Features

- **cli**: Make --control resolution platform-aware
  ([`4848f4a`](https://github.com/Hanalyx/aegis/commit/4848f4aa705ef4f1d1fc924a61e76c1934255d38))


## v1.5.3 (2026-02-17)

### Bug Fixes

- **ssh**: Patch hashlib.md5 for FIPS-enabled systems
  ([`d2bb60b`](https://github.com/Hanalyx/aegis/commit/d2bb60b2cec648623b98d9deebbb6ce4d4ac74b3))


## v1.5.2 (2026-02-17)

### Bug Fixes

- **ssh**: Custom host key policy to avoid MD5 on RHEL 9+
  ([`7ce4b8e`](https://github.com/Hanalyx/aegis/commit/7ce4b8eda330be52a7fbf4382aec483ffa3f0b4c))


## v1.5.1 (2026-02-17)

### Bug Fixes

- **ssh**: Always load known_hosts and replace AutoAddPolicy with WarningPolicy
  ([`03e4e80`](https://github.com/Hanalyx/aegis/commit/03e4e80ddfeec8c3d89e4a3b053deaa2c5bc3ba2))

### Documentation

- Update rule count to 492 in README
  ([`7bd7d4d`](https://github.com/Hanalyx/aegis/commit/7bd7d4dfe437f6e9818c430289baf561b9cd3619))


## v1.5.0 (2026-02-17)

### Bug Fixes

- **cis**: Add 73 missing controls to CIS RHEL 9 v2.0.0 mapping
  ([`b7fcd7e`](https://github.com/Hanalyx/aegis/commit/b7fcd7ec2e899e0d5c499faa1d6f5244ccba5d0c))

- **rule**: Rewrite crypto-policy-no-sha1 to check effective policy state
  ([`cf7560e`](https://github.com/Hanalyx/aegis/commit/cf7560e7c6aa6156f2b1fd3f0c70b668da39f092))

### Documentation

- Resolve P1 CIS dangling references in TECH_DEBT.md
  ([`3e8c267`](https://github.com/Hanalyx/aegis/commit/3e8c2676dbefda984a70d0e9186b0c58c5e09b5c))

### Features

- **cli**: Add --control option to check/remediate commands
  ([`664bbf7`](https://github.com/Hanalyx/aegis/commit/664bbf711cc6a075175f41a060e488472bbab05b))


## v1.4.0 (2026-02-17)

### Chores

- Remove stale gap analysis scratch files ([#9](https://github.com/Hanalyx/aegis/pull/9),
  [`b5babdc`](https://github.com/Hanalyx/aegis/commit/b5babdc02db6a22a30d55919b3e83016cb990c77))

### Features

- Add CIS benchmark integration with 102 rule YAMLs and tooling
  ([#9](https://github.com/Hanalyx/aegis/pull/9),
  [`b5babdc`](https://github.com/Hanalyx/aegis/commit/b5babdc02db6a22a30d55919b3e83016cb990c77))


## v1.3.0 (2026-02-16)

### Chores

- Gitignore session continuity files (BACKLOG, SESSION_LOG, CLAUDE)
  ([`3b1e4f5`](https://github.com/Hanalyx/aegis/commit/3b1e4f5c1cda428565ebd0ebd17ed500d980844b))

### Documentation

- Update TECH_DEBT.md and PRDs to reflect current state
  ([#6](https://github.com/Hanalyx/aegis/pull/6),
  [`80e6c5e`](https://github.com/Hanalyx/aegis/commit/80e6c5e36601e6dcf4657071393743560660859d))

### Features

- Add FedRAMP Moderate Rev 5 baseline integration and tooling
  ([`f03b8a4`](https://github.com/Hanalyx/aegis/commit/f03b8a449a67baf47827d72a05f34fde4d4a8eed))


## v1.2.3 (2026-02-16)

### Bug Fixes

- Convert CIS RHEL 9 mapping to standard format and remove dead code
  ([#5](https://github.com/Hanalyx/aegis/pull/5),
  [`cc75055`](https://github.com/Hanalyx/aegis/commit/cc75055f503d9e1ef6bf3ca9d8fa43293332e625))


## v1.2.2 (2026-02-16)

### Bug Fixes

- Correct sed over-escaping and align test mocks with handlers
  ([#4](https://github.com/Hanalyx/aegis/pull/4),
  [`587490c`](https://github.com/Hanalyx/aegis/commit/587490cca7e6366f7db042d268e6f82ddaeb390f))


## v1.2.1 (2026-02-16)

### Bug Fixes

- Resolve P1/P2 tech debt items ([#3](https://github.com/Hanalyx/aegis/pull/3),
  [`75b6217`](https://github.com/Hanalyx/aegis/commit/75b6217f9aebaa83357d2c02343a263207deb411))


## v1.2.0 (2026-02-16)

### Bug Fixes

- Restore inventory neutral naming and docs from origin/main
  ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))

- Use dict.fromkeys() in ordering.py for ruff C420 compliance
  ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))

### Chores

- Add results/ and gap analysis scratch files to .gitignore
  ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))

- Add utility scripts and CIS comparison analysis docs
  ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))

- Move completed PRDs to prd/done/ ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))

### Features

- Add 55 new CIS rules and update existing rules with v2.0.0 mappings
  ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))

- Add SSH check handler module ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))

- CIS v2.0.0 rules, neutral inventory naming, and cleanup
  ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))

### Refactoring

- Adopt neutral inventory variable names, remove ansible_ prefix
  ([#2](https://github.com/Hanalyx/aegis/pull/2),
  [`82302e0`](https://github.com/Hanalyx/aegis/commit/82302e05dc6c25725708b4ba3717932b7c70cf56))


## v1.1.1 (2026-02-16)

### Bug Fixes

- Add type annotation to resolve mypy errors in inventory.py
  ([#1](https://github.com/Hanalyx/aegis/pull/1),
  [`e6bb48c`](https://github.com/Hanalyx/aegis/commit/e6bb48cc47b2256d044a18aa6936a00932ebc1ed))

- Escape sed/grep patterns and add strict host key verification
  ([#1](https://github.com/Hanalyx/aegis/pull/1),
  [`e6bb48c`](https://github.com/Hanalyx/aegis/commit/e6bb48cc47b2256d044a18aa6936a00932ebc1ed))

- Resolve CI failures in lint and schema validation ([#1](https://github.com/Hanalyx/aegis/pull/1),
  [`e6bb48c`](https://github.com/Hanalyx/aegis/commit/e6bb48cc47b2256d044a18aa6936a00932ebc1ed))

- Use str() coercion for mypy compatibility in inventory.py
  ([#1](https://github.com/Hanalyx/aegis/pull/1),
  [`e6bb48c`](https://github.com/Hanalyx/aegis/commit/e6bb48cc47b2256d044a18aa6936a00932ebc1ed))

### Documentation

- Add AEGIS Developer Guide v1.0.0 for OpenWatch integration
  ([#1](https://github.com/Hanalyx/aegis/pull/1),
  [`e6bb48c`](https://github.com/Hanalyx/aegis/commit/e6bb48cc47b2256d044a18aa6936a00932ebc1ed))

- Update README.md and CLAUDE.md to reflect current state
  ([#1](https://github.com/Hanalyx/aegis/pull/1),
  [`e6bb48c`](https://github.com/Hanalyx/aegis/commit/e6bb48cc47b2256d044a18aa6936a00932ebc1ed))

### Refactoring

- Adopt neutral inventory variable names, remove ansible_ prefix
  ([#1](https://github.com/Hanalyx/aegis/pull/1),
  [`e6bb48c`](https://github.com/Hanalyx/aegis/commit/e6bb48cc47b2256d044a18aa6936a00932ebc1ed))


## v1.1.0 (2026-02-10)

### Bug Fixes

- Search parent directories for defaults.yml
  ([`841787e`](https://github.com/Hanalyx/aegis/commit/841787e8596cca2636de7e78fd38c59fd54a79b9))

### Features

- Add lookup command and fix service static state handling
  ([`f16f902`](https://github.com/Hanalyx/aegis/commit/f16f90254560aac18084e546ad13c2ab9ab02a5d))


## v1.0.0 (2026-02-09)

### Features

- Add pip packaging with GitHub Actions auto-release
  ([`3504157`](https://github.com/Hanalyx/aegis/commit/3504157eefef42088d525301aaf05fcfc468a309))

- **P4-1**: Add OpenWatch integration with evidence capture
  ([`0bf674e`](https://github.com/Hanalyx/aegis/commit/0bf674ece0ae70bec45be4be57e6fde7bf899165))


## v0.1.0 (2026-02-08)

- Initial Release
