# Aegis — Claude Code Project Guide

SSH-based compliance test runner for RHEL systems. Connects to remote hosts, evaluates YAML compliance rules, captures machine-verifiable evidence, and maps results to frameworks (CIS, STIG, NIST 800-53, PCI-DSS, FedRAMP).

## Quick Reference

```bash
# Run tests
pytest tests/ -v

# Lint and format
ruff check runner/ schema/ tests/
ruff format runner/ schema/ tests/

# Type check
mypy runner/ schema/ --ignore-missing-imports

# Pre-commit (all hooks)
pre-commit run --all-files

# Framework coverage
./aegis coverage --framework cis-rhel9-v2.0.0
./aegis coverage --framework fedramp-moderate

# FedRAMP gap analysis
python scripts/fedramp_validate.py
python scripts/fedramp_validate.py --json
python scripts/fedramp_validate.py --family AC

# CIS gap analysis
python scripts/cis_validate.py
python scripts/cis_validate.py --mapping cis-rhel9-v2.0.0
python scripts/cis_validate.py --json
python scripts/cis_validate.py --chapter 5
```

## Project Structure

```
runner/                  # Core Python package
├── cli.py              # Main CLI (9 commands: detect, check, remediate, history, diff, coverage, list-frameworks, info, lookup)
├── engine.py           # Rule evaluation facade
├── ssh.py              # SSH connection management
├── detect.py           # 22 capability probes + platform detection
├── mappings.py         # Framework mapping loader (FrameworkMapping, FrameworkIndex)
├── inventory.py        # Host resolution (INI/YAML/host list)
├── shell_util.py       # Command escaping utilities
├── storage.py          # SQLite result persistence
├── ordering.py         # Framework-ordered output
├── handlers/           # Modular domain-specific handlers
│   ├── checks/         # 20 check handler types
│   ├── remediation/    # 23 remediation handler types
│   ├── capture/        # Pre-remediation state capture
│   └── rollback/       # State restoration
└── output/             # JSON, CSV, PDF, evidence export

rules/                   # 508 YAML compliance rules
├── access-control/     # 114 rules
├── audit/              # ~104 rules
├── services/           # ~100 rules
├── system/             # 56 rules
├── filesystem/         # ~55 rules
├── network/            # 42 rules
├── kernel/             # 19 rules
├── logging/            # 18 rules
├── defaults.yml        # Default values for all rules
└── rules.d/            # Optional rule overrides

mappings/                # Framework reference mappings
├── cis/                # CIS RHEL 8/9
├── stig/               # STIG RHEL 8/9
├── nist/               # NIST 800-53 Rev 5
├── pci-dss/            # PCI-DSS v4.0
└── fedramp/            # FedRAMP Moderate Rev 5

schema/                  # JSON Schema validation
├── rule.schema.json    # Rule YAML specification
├── validate.py         # Pre-commit validation script
└── validators/         # Domain-specific validators

context/fedramp/         # FedRAMP reference data
├── moderate-rev5-baseline.yaml   # 323 controls from OSCAL
└── FEDRAMP_MODERATE_REFERENCE.md # Human-readable reference

context/cis/             # CIS reference data
├── rhel9-v2.0.0-baseline.yaml   # 244 controls from CIS RHEL 9 v2.0.0
└── rhel8-v4.0.0-baseline.yaml   # 311 controls from CIS RHEL 8 v4.0.0

scripts/                 # Dev tooling
├── cis_validate.py     # CIS gap analysis and validation
├── gap_analysis.py     # AEGIS vs OpenSCAP comparison
├── fedramp_validate.py # FedRAMP gap analysis
└── parse_fedramp_oscal.py # OSCAL parser for baseline regen

tests/                   # 200 pytest tests

RULE_REVIEW_GUIDE_V0.md  # Rule review criteria (5 dimensions)
ACCESS_CONTROL_REVIEW_PLAN.md # Completed access-control review plan (PRs #13-#20)
AUDIT_REVIEW_PLAN.md     # Completed audit review plan (PRs #21-#28)
```

## Key Conventions

### Rule YAML Format
Rules live in `rules/<category>/<rule-id>.yml`. Each rule has:
- `id`, `title`, `severity`, `category`, `tags`
- `references` (CIS section, STIG ID, NIST controls)
- `platforms` with family/version constraints
- `implementations` with capability-gated check + remediation pairs

Check handlers: `config_value`, `sshd_effective_config`, `file_permission`, `command`, `file_exists`, `package_state`, `service_state`, `sysctl_value`, `kernel_module_state`, `mount_option`, `audit_rule_exists`, `grub_parameter`, `selinux_boolean`, `selinux_state`, `multi_check`, etc.

**Key field names (runtime-critical):**
- Check blocks: `run:` (not `command:`), `expected_exit:` (not `expected_exit_code:`)
- `expected_stdout: ""` means "expect empty output" (exact empty check, not substring)
- `expected_stdout: "text"` means "stdout contains text" (substring match)
- Manual remediation: `note:` (not `description:`)
- command_exec remediation: `run:` (not `command:`)
- SSH checks: use `sshd_effective_config` (runs `sshd -T`), not `config_value` on static file
- PAM rules: use `when: authselect` implementation when authselect manages PAM

### Framework Mappings
All mapping files use a unified format:
- **Top-level key:** `controls:` (all frameworks)
- **Entry format:** `rules: [list]` (always a list, even for single-rule entries like CIS/STIG)

All support `control_ids:` manifest and `unimplemented:` for completeness tracking. `mapping.is_complete` returns True when all `control_ids` are accounted for.

### Code Style
- Python 3.10+ with `from __future__ import annotations`
- Ruff: line-length 88, double quotes, LF endings
- Rules: E, F, W, I, B, C4, SIM, UP (ignores E501)
- Google-style docstrings (pydocstyle)
- mypy strict-ish (ignore-missing-imports)

### Pre-commit Hooks
1. File hygiene (trailing whitespace, end-of-file, YAML/JSON check, large files, merge conflicts, private keys, case conflicts)
2. Ruff lint + format
3. Mypy type checking
4. Pydocstyle (Google convention)
5. Rule YAML schema validation

## Slash Commands

- `/cis` — Interactive CIS benchmark gap analysis, rule creation, mapping validation
- `/fedramp` — Interactive FedRAMP gap analysis, rule creation, mapping validation

## Architecture Principles

1. **Pure measurement** — no persistent state, evidence-focused
2. **Evidence-first** — every check captures raw command output for audit trails
3. **Framework-agnostic** — one rule maps to multiple frameworks
4. **Capability-gated** — implementations adapt to host capabilities (22 probes)
5. **Modular handlers** — domain-specific check/remediation/capture/rollback

## Key Reference Docs

- `CANONICAL_RULE_SCHEMA_V0.md` — Rule YAML schema specification
- `TECHNICAL_REMEDIATION_MP_V0.md` — Three-layer architecture, remediation design principles
- `docs/AEGIS_Developer_Guide_v1.0.0.md` — Full API reference
- `TECH_DEBT.md` — Known issues and priorities
- `CHANGELOG.md` — Semantic versioning history
- `BACKLOG.md` — Current task backlog
- `SESSION_LOG.md` — Session continuity log
- `prd/IMPLEMENTATION_PLAN.md` — Current implementation tracking
