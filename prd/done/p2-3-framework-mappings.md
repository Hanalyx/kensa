# P2-3: Framework Mapping Layer

## Status: Complete

## Problem

The Technical Remediation Master Plan (Section 3.6) describes a key architectural feature: **framework identifiers are cross-references attached to rules as metadata, not the structure of the rule set**. Adding a new framework should mean adding a new mapping file, not modifying rules.

Currently, framework references are embedded directly in each rule's YAML:
```yaml
references:
  cis:
    rhel9_v2: { section: "5.2.3", level: "L1", type: "Automated" }
  stig:
    rhel9_v2r7: { id: "V-257947", severity: "medium" }
```

This has several problems:

1. **Adding a new framework version requires editing every rule file.** When CIS RHEL 10 v1.0 ships, we must add a `rhel10_v1` entry to every rule that maps to it.

2. **No framework-aware reporting.** We can't generate a report ordered by CIS section number, or produce a STIG checklist with Finding IDs as the primary key.

3. **No cross-reference queries.** "What rules map to NIST AC-6?" requires grepping all rule files.

4. **Benchmark structure leaks into rules.** When CIS renumbers a section (5.2.3 → 6.1.4 in a new version), we update the rule file even though the rule itself didn't change.

## Solution

Create a **separate mapping layer** that lives alongside rules. Each framework version gets its own mapping file that maps framework identifiers → canonical rule IDs.

```
kensa/
  mappings/
    cis/
      rhel8_v3.0.0.yaml
      rhel9_v2.0.0.yaml
      rhel10_v1.0.0.yaml
    stig/
      rhel8_v2r6.yaml
      rhel9_v2r7.yaml
    nist/
      800-53_r5.yaml
    pci-dss/
      v4.0.yaml
```

### Mapping File Format

```yaml
# mappings/cis/rhel9_v2.0.0.yaml
id: cis-rhel9-v2.0.0
framework: cis
title: "CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0"
published: 2024-06-28
platform:
  family: rhel
  min_version: 9

sections:
  "1.1.1.1":
    rule: fs-cramfs-disabled
    level: L1
    type: Automated
    title: "Ensure cramfs kernel module is not available"

  "5.2.3":
    rule: ssh-disable-root-login
    level: L1
    type: Automated
    title: "Ensure SSH root login is disabled"

  "5.2.4":
    rule: ssh-max-auth-tries
    level: L1
    type: Automated
    title: "Ensure SSH MaxAuthTries is set to 4 or less"

# Sections that have no canonical rule (manual, N/A, etc.)
unimplemented:
  "1.1.2.1":
    title: "Ensure /tmp is a separate partition"
    reason: "Site-specific partitioning decision"
    type: Manual
```

### STIG Mapping Format

```yaml
# mappings/stig/rhel9_v2r7.yaml
id: stig-rhel9-v2r7
framework: stig
title: "DISA STIG for Red Hat Enterprise Linux 9 V2R7"
published: 2024-12-06
platform:
  family: rhel
  min_version: 9

findings:
  "V-257947":
    rule: ssh-disable-root-login
    severity: medium
    title: "RHEL 9 must not permit direct logons to the root account using remote access via SSH"
    cci: ["CCI-000770"]

  "V-257948":
    rule: ssh-max-auth-tries
    severity: medium
    title: "RHEL 9 must limit the number of unsuccessful SSH login attempts"
    cci: ["CCI-000044"]
```

### NIST Control Mapping (Many-to-Many)

```yaml
# mappings/nist/800-53_r5.yaml
id: nist-800-53-r5
framework: nist_800_53
title: "NIST SP 800-53 Rev. 5"
published: 2020-09-23

controls:
  "AC-6(2)":
    title: "Least Privilege | Non-Privileged Access for Nonsecurity Functions"
    rules:
      - ssh-disable-root-login
      - sudo-require-auth
      - sudo-use-pty

  "AC-17(2)":
    title: "Remote Access | Protection of Confidentiality and Integrity Using Encryption"
    rules:
      - ssh-disable-root-login
      - ssh-crypto-policy
      - ssh-approved-ciphers
```

## CLI Integration

### Framework Selection

```bash
# Check against CIS RHEL 9 v2.0.0 specifically
./kensa check --host 192.168.1.211 --framework cis-rhel9-v2.0.0

# Check against all applicable frameworks (based on detected platform)
./kensa check --host 192.168.1.211 --framework auto

# Check specific STIG
./kensa check --host 192.168.1.211 --framework stig-rhel9-v2r7
```

### Framework-Ordered Output

```bash
# Output in CIS section order
./kensa check --host 192.168.1.211 --framework cis-rhel9-v2.0.0 --output table

Section   Title                              Status  Detail
────────────────────────────────────────────────────────────────────
1.1.1.1   Ensure cramfs module disabled      PASS    cramfs: blacklisted
1.1.1.2   Ensure freevxfs module disabled    PASS    freevxfs: blacklisted
...
5.2.3     Ensure SSH root login disabled     PASS    PermitRootLogin=no
5.2.4     Ensure SSH MaxAuthTries <= 4       FAIL    MaxAuthTries=6 (expected <=4)
```

### Coverage Report

```bash
# Show which framework sections have rules vs gaps
./kensa coverage --framework cis-rhel9-v2.0.0

CIS RHEL 9 v2.0.0 Coverage
──────────────────────────
Total sections: 287
Implemented:    241 (84%)
Unimplemented:   32 (11%)  # Marked in mapping as unimplemented
Missing:         14 (5%)   # No mapping and no unimplemented entry

Missing sections (need rules or explicit skip):
  2.1.3   Ensure chrony is configured (need chrony rule)
  3.4.2   Ensure iptables-services not installed (need package_absent)
  ...
```

### Cross-Reference Query

```bash
# Which rules satisfy NIST AC-6?
./kensa query --control "nist:AC-6"

NIST 800-53 AC-6 — Least Privilege
Rules implementing this control:
  - ssh-disable-root-login (also: CIS 5.2.3, STIG V-257947)
  - sudo-require-auth (also: CIS 5.3.4, STIG V-258012)
  - sudo-use-pty (also: CIS 5.3.5, STIG V-258013)
```

## Technical Approach

### New Module: `runner/mappings.py`

```python
@dataclass
class FrameworkMapping:
    id: str
    framework: str  # "cis", "stig", "nist_800_53", etc.
    title: str
    published: date | None
    platform: dict | None  # {family: "rhel", min_version: 9}
    sections: dict[str, MappingEntry]  # section_id -> entry
    unimplemented: dict[str, dict]  # section_id -> {title, reason}

@dataclass
class MappingEntry:
    rule_id: str
    title: str
    metadata: dict  # level, type, severity, cci, etc.

def load_mapping(path: str) -> FrameworkMapping: ...
def load_all_mappings(mappings_dir: str = "mappings/") -> dict[str, FrameworkMapping]: ...
def get_applicable_mappings(family: str, version: int) -> list[FrameworkMapping]: ...
def rules_for_framework(mapping: FrameworkMapping, rules: list[dict]) -> list[dict]: ...
```

### Integration Points

1. **`cli.py`**: Add `--framework` flag to `check` and `remediate` commands
2. **`engine.py`**: No changes — mappings are a layer above the engine
3. **Output formatters**: Framework-aware ordering in `p1-1-output-formats.md`

### Migration Path

The existing `references:` block in rules can remain for human readability and backward compatibility. The mapping layer becomes the source of truth for framework coverage. A validation script can check that mappings and rule references stay in sync.

## Acceptance Criteria

- [x] Mapping file schema defined and documented (YAML format in mappings/)
- [x] `load_mapping()` parses CIS, STIG, and NIST format mappings
- [x] `--framework <id>` filters rules to those in the mapping
- [ ] `--framework auto` selects mappings matching detected platform (deferred)
- [ ] Output respects framework section ordering (CIS 1.1.1 before 5.2.3) (deferred)
- [x] `./kensa coverage --framework <id>` shows implemented/unimplemented/missing
- [x] Adding CIS RHEL 10 requires only a new mapping file (no rule changes)
- [ ] Cross-reference queries work: "which rules map to NIST AC-6?" (deferred)
- [x] Mapping validation: warn if mapping references non-existent rule ID

## Future Extensions

- **STIG Checklist XML export**: Generate `.ckl` files for STIG Viewer
- **OSCAL export**: Map to NIST OSCAL format for FedRAMP
- **Benchmark diff**: Compare two framework versions, show section renumbering
