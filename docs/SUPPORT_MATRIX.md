# Kensa Support Matrix

**Last updated:** 2026-03-13

This document defines the supported platforms, frameworks, and operational scope for Kensa.

---

## Platform Support

### Supported OS Families

| OS Family | Versions | Support Tier | Notes |
|-----------|----------|-------------|-------|
| Red Hat Enterprise Linux | 8, 9 | **Production** | Primary target; all 630 rules tested |
| Rocky Linux | 8, 9 | **Production** | Normalizes to `rhel` family; binary-compatible |
| AlmaLinux | 8, 9 | **Production** | Normalizes to `rhel` family; binary-compatible |
| Oracle Linux | 8, 9 | **Community-tested** | Normalizes to `rhel` family; may diverge on UEK kernel |
| CentOS Stream | 8, 9 | **Community-tested** | Normalizes to `rhel` family; rolling release may drift |
| Fedora | 38+ | **Experimental** | Normalizes to `rhel` family; packages and paths may differ |

### Support tiers

- **Production** — Actively tested, CI-validated, supported for compliance engagements.
- **Community-tested** — Expected to work based on binary compatibility. Not CI-validated. Issues accepted but not prioritized.
- **Experimental** — May work due to shared package/config ancestry. No guarantees. Not recommended for compliance reporting.
- **Unsupported** — Debian, Ubuntu, SUSE, and other non-RHEL families are not supported. Kensa will detect the platform but will not execute rules.

### Platform detection

Kensa reads `/etc/os-release` (primary) or `/etc/redhat-release` (fallback) on the target host. RHEL derivatives are normalized to `family: rhel` with the detected major version. Rules gate their implementations on `family` and `min_version` constraints.

All 630 rules target `family: rhel`. Rules that require version-specific behavior use `min_version: 9` to gate RHEL 9-only implementations.

---

## Framework Coverage

### Production frameworks

| Framework | Mapping ID | Benchmark Edition | Total Controls | Mapped | Unimplemented | Coverage |
|-----------|-----------|-------------------|---------------|--------|---------------|----------|
| CIS RHEL 8 | `cis-rhel8` | v4.0.0 | 322 | 293 | 29 | **91.0%** |
| CIS RHEL 9 | `cis-rhel9` | v2.0.0 | 297 | 276 | 21 | **92.9%** |
| STIG RHEL 8 | `stig-rhel8` | V2R6 | 366 | 348 | 18 | **95.1%** |
| STIG RHEL 9 | `stig-rhel9` | V2R7 | 446 | 420 | 26 | **94.2%** |

### Cross-platform frameworks

| Framework | Mapping ID | Total Controls | Mapped Rules | Notes |
|-----------|-----------|---------------|-------------|-------|
| NIST 800-53 Rev 5 | `nist-800-53-r5` | — | 87 | Controls map to multiple rules; not a 1:1 coverage metric |
| PCI-DSS v4.0 | `pci-dss-v4.0` | — | 45 | Covers OS-level technical controls only |
| FedRAMP Moderate | `fedramp-moderate` | 323 | 91 | 28.2% — many controls are organizational/procedural, not OS-automatable |

### Coverage terminology

- **Total Controls** — Number of controls defined in the benchmark/standard baseline.
- **Mapped** — Controls with at least one Kensa rule implementing the check. The rule may use automated or manual checking.
- **Unimplemented** — Controls acknowledged in the mapping but not yet covered by a Kensa rule. Listed with title, severity, and reason.
- **Coverage %** — Mapped / Total Controls. Indicates mapping completeness, not full automation.

### What "manual" means

Some mapped controls use `mechanism: manual` for their remediation. This means:

- The **check** is automated — Kensa detects compliance state and collects evidence.
- The **remediation** requires human action — Kensa describes what to do but does not modify the system.
- The check result is machine-verifiable and suitable for audit evidence.

Manual remediations exist for controls that require organizational judgment (e.g., banner text content), physical access, or changes too dangerous to automate without site-specific review.

---

## Rule Corpus

### Summary

| Metric | Count |
|--------|-------|
| Total rules | 630 |
| Rule categories | 8 |
| Check handler types | 21 |
| Remediation mechanism types (registered) | 27 |
| Remediation mechanisms used in rules | 23 |
| Capability probes | 24 |

### Rules by category

| Category | Rules |
|----------|-------|
| access-control | 145 |
| audit | 115 |
| services | 114 |
| filesystem | 89 |
| system | 81 |
| network | 45 |
| kernel | 23 |
| logging | 18 |

### Remediation automation

| Category | Count | % of remediations |
|----------|-------|-------------------|
| Typed/declarative | 591 | 79.4% |
| Manual | 114 | 15.3% |
| command_exec | 39 | 5.2% |

Typed mechanisms have full pre-state capture, rollback, and dry-run support. See [Remediation Safety](REMEDIATION_SAFETY.md) for details.

---

## Connectivity Requirements

Kensa connects to target hosts via SSH. Requirements:

- SSH access (port 22 or custom) with key-based or password authentication
- Root or sudo-capable user on the target host
- Python is **not** required on the target — all checks execute via shell commands

Kensa runs from a control node (laptop, jump host, CI runner) and does not install agents on targets.

---

## Python Requirements

| Python Version | Status |
|---------------|--------|
| 3.10 | Supported (CI-tested) |
| 3.11 | Supported (CI-tested) |
| 3.12 | Supported (CI-tested) |
| 3.9 and below | Unsupported |

---

## What Kensa Does Not Cover

- **Non-RHEL operating systems** — No Debian, Ubuntu, SUSE, or Windows support.
- **Cloud-native controls** — AWS, Azure, GCP resource configuration is out of scope.
- **Application-layer compliance** — Database, web server, and application security controls are not covered.
- **Organizational/procedural controls** — Policy documents, training records, and governance processes are outside scope. Framework mappings mark these as unimplemented with reason.
- **Network device hardening** — Firewalls, switches, and routers are not targets.
