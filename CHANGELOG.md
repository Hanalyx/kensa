# Changelog

All notable changes to Kensa are documented here. Most recent release first.

---

## v1.2.5 (2026-03-02)

### Fixed

- Fix release tag version mismatch when local and remote tags diverge (#126)

### Changed

- Remove `-r rules/` from CLI help examples to reflect auto-resolved defaults (#126)

---

## v1.2.4 (2026-03-02)

### Changed

- Handle locally-tagged releases in release workflow to prevent duplicate release attempts (#124)

---

## v1.2.3 (2026-02-28)

### Added

- Add minor version to platform detection and terminal display output (#122)
- Add Admin Guide and Auditor Guide documentation (#121)
- Add Compliance Philosophy and QuickStart Guide documentation (#120)

### Fixed

- Fix CLI help text accuracy, history UX, and list-frameworks command group (#123)

---

## v1.2.2 (2026-02-27)

### Added

- Auto-resolve default rules directory when `--rules` is omitted (#116)

### Changed

- Skip release when version tag already exists to prevent double-release (#117)

---

## v1.2.1 (2026-02-27)

### Added

- Add pytest and spec validation to CI matrix (Python 3.10, 3.11, 3.12) (#111)
- Add E2E result storage with full output capture to results/e2e/ (#112)
- Add run diagnostics: error distinction, timing, skip reasons, and schema v4 (#106)
- Add live host E2E tier and shared run_kensa helper (#105)
- Add isolated kensa_network for E2E container tests (#104)
- Add secure password prompt with optional-value behavior (#109)

### Fixed

- Fix E2E container tests: systemd, PAM, CLI invocation, and --yes flag (#114)
- Fix --password prompt to use prompt=True so click enables optional-value behavior (#110)

### Changed

- Display run duration in terminal summary lines (#107)

---

## v1.2.0 (2026-02-26)

### Added

- Add SDD (Specification-Driven Development) framework with YAML specs for all handlers (#88)
- Add spec-derived tests covering 199 ACs across all spec categories (#88)
- Add E2E container test infrastructure for systemd containers (#102)
- Add development pipeline workflow with spec lifecycle tracking (#100)

### Fixed

- Fix hardcoded rules/ path; support auto-resolution for installed deployments (#98)
- Fix release workflow blocked by branch protection on required status checks (#99)

### Changed

- Prepare repo for public release under BSL license (#75)

---

## v1.1.0 (2026-02-23)

### Added

- Add enterprise rollback with risk-based pre-state snapshot capture (#74)

### Changed

- Merge info and lookup into unified `kensa info` command (#74)

---

## v1.0.0 (2026-02-20)

Initial release of Kensa, SSH-based compliance test runner for RHEL systems. Connects to remote hosts, evaluates YAML compliance rules, captures machine-verifiable evidence, and maps results to CIS, STIG, NIST 800-53, PCI-DSS, and FedRAMP frameworks.
