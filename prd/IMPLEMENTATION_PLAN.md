# P3 Implementation Plan

## Executive Summary

**Last updated:** 2026-02-16

| Metric | P3-2 Target | Current State | Status |
|--------|-------------|---------------|--------|
| Canonical rules | 180 | **390** (217%) | Done |
| CIS RHEL 9 coverage | 85% | **94%** (229/244) | Done |
| STIG RHEL 9 coverage | 80% | **76%** (338/446) | Needs 18 more |
| Check handlers | 17 | **20** | Done |
| Remediation handlers | 23 | **23** | Done |
| Framework-ordered output | — | Implemented | Done |
| Auto framework selection | — | Implemented | Done |
| Cross-reference queries | — | `aegis lookup` command | Done |
| NIST 800-53 mapping | — | 87/105 controls (83%) | Done |
| PCI-DSS v4.0 mapping | — | 45/45 (100%) | Done |
| FedRAMP Moderate mapping | — | 87/87 (100%) | Done |

---

## Phase Status

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Framework-ordered output | **Complete** — `order_results_by_section()` with semantic numeric sorting, section prefix in terminal, reordering for file output |
| **2** | Mapping gap analysis & completion | **Partially complete** — CIS 94% (exceeds 85% target), STIG 76% (needs 80%). 102 missing rule YAMLs in CIS mapping |
| **3** | Auto framework selection | **Complete** — `--framework auto` detects platform, `_apply_auto_framework()` in both check/remediate |
| **4** | Cross-reference queries | **Complete** — `FrameworkIndex` class, `aegis lookup` command with `--cis-section`, `--stig-id`, `--nist-control` |
| **5** | NIST control mapping | **Complete** — NIST 800-53 R5 (87/105), PCI-DSS v4.0 (45/45), FedRAMP Moderate (87/87) |

---

## Remaining Work: Phase 2 Completion

### Problem

The CIS RHEL 9 mapping references 102 rule IDs that have no corresponding rule YAML
in `rules/`. These are dangling references — the mapping says "section X is implemented
by rule Y" but rule Y does not exist. Additionally, STIG RHEL 9 is at 76% coverage
and needs 18 more implementations to reach the 80% target.

### Current Coverage

| Framework | Implemented | Total | Coverage | Missing Rules | Gap to Target |
|-----------|------------|-------|----------|---------------|---------------|
| CIS RHEL 9 v2.0.0 | 229 | 244 | 94% | 102 | Target met (85%) |
| STIG RHEL 9 V2R7 | 338 | 446 | 76% | 0 | Need 18 more (80%) |
| CIS RHEL 8 v4.0.0 | 120 | 311 | 39% | 0 | — |
| STIG RHEL 8 V2R6 | 116 | 366 | 32% | 0 | — |
| NIST 800-53 R5 | 87 | 105 | 83% | 0 | — |
| PCI-DSS v4.0 | 45 | 45 | 100% | 0 | — |
| FedRAMP Moderate | 87 | 87 | 100% | 0 | — |

### Options for the 102 Missing CIS Rules

1. **Create the missing rule YAMLs** — author rules like `aide-scheduled`, `cron-enabled`,
   `sysctl-ip-forward-disabled`, etc. using existing check handlers
2. **Remove dangling references** — change mapping entries from `rule: aide-scheduled` to
   `rule: null` and move to `unimplemented:` with a reason
3. **Hybrid** — create rules where the check handler already supports it, remove references
   for rules that would need new handlers

### Acceptance Criteria (remaining)

- [ ] CIS RHEL 9 has zero missing rules (all referenced rule IDs exist)
- [ ] STIG RHEL 9 coverage ≥ 80%
- [ ] Zero schema validation errors
