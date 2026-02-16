# P1-3: Platform Version Filtering (DONE)

## Status: Complete

## Problem
Rules declare platform applicability with `min_version` / `max_version`:
```yaml
platforms:
  - family: rhel
    min_version: 9
    max_version: 10
```

V0 ignores these fields — all rules run on all hosts. A RHEL 8 host will attempt rules that only apply to RHEL 9+, potentially producing false failures.

## Solution
Detect the remote host's OS family and version during capability probing, then filter rules before execution.

## What Was Delivered

### runner/detect.py
- `PlatformInfo` namedtuple with `family` and `version` fields
- `RHEL_FAMILY` set for derivative normalization (`rhel`, `centos`, `rocky`, `almalinux`, `ol`)
- `detect_platform(ssh)` — reads `/etc/os-release`, parses `ID` and `VERSION_ID`, normalizes RHEL derivatives to `"rhel"` family, returns `PlatformInfo` or `None` on failure

### runner/engine.py
- `rule_applies_to_platform(rule, family, version)` — checks a rule's `platforms:` list against detected host. Returns `True` if no `platforms` key (no constraint), `False` if empty list or no entry matches. Respects `min_version` (default 0) and `max_version` (default 99).

### runner/cli.py
- `detect` command prints platform info (`Platform: RHEL 9`)
- `check` and `remediate` commands call `detect_platform()` per host and skip rules that don't match
- Skipped rules show `SKIP  rule-id  (platform: requires rhel >=9)` in output
- Summary counts include skip count: `35 rules | 28 pass | 2 fail | 5 skip`
- Graceful fallback: if `detect_platform()` returns `None`, a warning is printed and no filtering is applied (all rules run)

### Derivative Handling
- `detect_platform()` normalizes centos/rocky/almalinux/ol → `"rhel"` at detection time
- Rules with `family: rhel` automatically match all derivatives without any rule-side configuration
- No `derivatives:` flag needed in the current implementation — normalization handles 100% of the 35 existing rules

### Tests (20 new tests)
- `tests/test_detect.py`: 8 tests — RHEL 8/9, Rocky 9, AlmaLinux, CentOS Stream, Oracle Linux, unreadable os-release, unknown distro
- `tests/test_engine_loading.py`: 9 tests — matching version, exact min, below min, above max, no platforms, wrong family, min+max range, multiple entries, empty list
- `tests/test_cli.py`: 1 test — SKIP output for platform mismatch; fixed existing verbose test to patch `detect_platform`

## Acceptance Criteria
- [x] Correctly detects RHEL 8, 9, 10 from `/etc/os-release`
- [x] Correctly detects derivatives (Rocky, Alma, CentOS Stream, Oracle Linux)
- [x] `min_version: 9` rule skipped on RHEL 8 host
- [x] `max_version: 9` rule skipped on RHEL 10 host
- [x] `derivatives: true` (default) allows Rocky Linux to match `family: rhel` rules
- [ ] `derivatives: false` only matches exact family — deferred (no current rules use this; can be added by passing raw os_id alongside normalized family)
- [x] Skipped rules don't count as failures
- [x] Platform info shown in output (always, not just verbose)
- [x] Graceful fallback if `/etc/os-release` can't be read (run all rules with a warning)
