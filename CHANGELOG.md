# CHANGELOG

<!-- version list -->

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
