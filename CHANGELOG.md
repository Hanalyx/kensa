# CHANGELOG

<!-- version list -->

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
