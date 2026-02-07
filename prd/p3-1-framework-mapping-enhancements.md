# P3-1: Framework Mapping Enhancements

## Status: Not Started

## Problem

P2-3 delivered core framework mapping functionality: loading mappings, filtering rules by framework, and coverage reports. However, three capabilities described in the Technical Remediation Master Plan (Section 3.6) remain unimplemented:

1. **Framework-ordered output**: Reports should display results in framework section order (CIS 1.1.1 before 5.2.3), not alphabetical by rule ID. Auditors expect results organized by the benchmark structure they're familiar with.

2. **Automatic framework selection**: Users must currently specify `--framework cis-rhel9-v2.0.0` explicitly. The system should auto-detect the platform and select applicable mappings automatically with `--framework auto`.

3. **Cross-reference queries**: No way to answer "which rules satisfy NIST AC-6?" or "what frameworks reference ssh-disable-root-login?" These queries are essential for compliance mapping and gap analysis.

## Solution

### 1. Framework-Ordered Output

Integrate `order_by_framework()` into the output pipeline so results display in framework section order.

#### CLI Behavior

```bash
# Current: results sorted by rule ID
./aegis check --host 192.168.1.100 --framework cis-rhel9-v2.0.0
  PASS  aide-installed
  PASS  crypto-policy-disable-sha1-signatures
  FAIL  ssh-disable-root-login
  PASS  ssh-max-auth-tries

# Enhanced: results sorted by CIS section number
./aegis check --host 192.168.1.100 --framework cis-rhel9-v2.0.0
  Section   Rule                              Status
  1.1.1.1   kmod-disable-cramfs               PASS
  3.1.1     sysctl-net-ipv4-ip-forward        PASS
  4.1.1     aide-installed                    PASS
  5.1.7     ssh-max-auth-tries                PASS
  5.1.12    ssh-disable-root-login            FAIL
```

#### Output Format Integration

- **Terminal**: Show section column when `--framework` is specified
- **JSON**: Include `section` field in each result when framework is active
- **CSV**: Add `section` column
- **PDF**: Group results by framework section with section headers

### 2. Automatic Framework Selection (`--framework auto`)

Auto-detect platform and select all applicable framework mappings.

#### CLI Behavior

```bash
# Explicit framework (current)
./aegis check --host 192.168.1.100 --framework cis-rhel9-v2.0.0

# Auto-select based on detected platform
./aegis check --host 192.168.1.100 --framework auto

# On RHEL 9 host, this would automatically select:
#   - cis-rhel9-v2.0.0 (if present in mappings/)
#   - stig-rhel9-v2r7 (if present in mappings/)
# And run the union of rules from all applicable mappings
```

#### Implementation

```python
def auto_select_frameworks(platform, mappings):
    """Select all mappings applicable to the detected platform."""
    applicable = get_applicable_mappings(
        mappings,
        family=platform.family,
        version=platform.version,
    )
    return applicable
```

#### Edge Cases

- **Multiple mappings**: Run union of rules from all applicable frameworks
- **No applicable mappings**: Warning + fall back to all rules (no framework filter)
- **Conflicting frameworks**: Same rule appears in multiple mappings — deduplicate by rule ID

### 3. Cross-Reference Queries

New `aegis query` command for framework cross-reference lookups.

#### CLI: Query by Control

```bash
# Which rules implement NIST AC-6?
./aegis query --control "nist:AC-6"

NIST 800-53 AC-6 — Least Privilege
Rules implementing this control:
  - ssh-disable-root-login
  - sudo-require-auth
  - pam-faillock-deny

# Which rules implement CIS RHEL 9 section 5.1?
./aegis query --control "cis-rhel9-v2.0.0:5.1"

CIS RHEL 9 v2.0.0 Section 5.1 — Configure SSH Server
Rules:
  - ssh-config-permissions      (5.1.1)
  - ssh-private-key-permissions (5.1.2)
  - ssh-public-key-permissions  (5.1.3)
  ...
```

#### CLI: Query by Rule

```bash
# What frameworks reference ssh-disable-root-login?
./aegis query --rule ssh-disable-root-login

Rule: ssh-disable-root-login
Title: Disable SSH root login

Framework References:
  CIS RHEL 9 v2.0.0:     Section 5.1.12 (L1, Automated)
  STIG RHEL 9 V2R7:      V-257947 (CAT II)
  NIST 800-53:           AC-6(2), AC-17(2), IA-2(5)
  PCI-DSS 4.0:           2.2.6, 8.6.1
```

#### CLI: List All Controls

```bash
# List all NIST controls and their rule counts
./aegis query --framework nist --list-controls

NIST 800-53 Rev 5 Controls:
  AC-2      Account Management                  3 rules
  AC-3      Access Enforcement                  5 rules
  AC-6      Least Privilege                     4 rules
  AC-6(2)   Least Privilege | Non-Privileged    2 rules
  ...
```

## Technical Approach

### Data Structures

```python
# Extend FrameworkMapping with reverse lookup
@dataclass
class FrameworkMapping:
    # ... existing fields ...

    def rules_for_section(self, section_prefix: str) -> list[MappingEntry]:
        """Get all rules under a section prefix (e.g., '5.1' gets 5.1.1, 5.1.2, etc.)"""
        return [
            entry for section_id, entry in self.sections.items()
            if section_id.startswith(section_prefix)
        ]

# Build cross-reference index
@dataclass
class FrameworkIndex:
    """Cross-reference index for all mappings."""

    # rule_id -> [(mapping_id, section_id, entry), ...]
    rules_to_frameworks: dict[str, list[tuple[str, str, MappingEntry]]]

    # For NIST-style many-to-many: control_id -> [rule_id, ...]
    controls_to_rules: dict[str, list[str]]

    @classmethod
    def build(cls, mappings: dict[str, FrameworkMapping]) -> "FrameworkIndex":
        """Build index from all loaded mappings."""
        ...
```

### Integration Points

1. **`runner/mappings.py`**: Add `FrameworkIndex` class and `build_index()` function
2. **`runner/cli.py`**: Add `query` command with `--control`, `--rule`, `--list-controls`
3. **`runner/output.py`**: Modify formatters to accept optional framework ordering
4. **`_run_checks()` / `_run_remediation()`**: Pass framework context to output

### Output Formatter Changes

```python
def write_output(
    run_result: RunResult,
    fmt: str,
    filepath: str | None,
    *,
    framework: FrameworkMapping | None = None,  # NEW
) -> str:
    """Write formatted output, optionally ordered by framework sections."""
    if framework:
        # Reorder results by framework section
        run_result = reorder_by_framework(run_result, framework)
    ...
```

## Acceptance Criteria

### Framework-Ordered Output
- [ ] Terminal output shows section column when `--framework` specified
- [ ] Results ordered by section number (1.1.1 < 1.1.2 < 1.2.1 < 5.1.1)
- [ ] JSON output includes `section` field per result
- [ ] CSV output includes `section` column
- [ ] PDF groups results by section with headers

### Automatic Framework Selection
- [ ] `--framework auto` detects platform and selects applicable mappings
- [ ] Multiple applicable mappings: runs union of rules (deduplicated)
- [ ] No applicable mappings: warns and runs without framework filter
- [ ] Works with both `check` and `remediate` commands

### Cross-Reference Queries
- [ ] `aegis query --control "nist:AC-6"` lists implementing rules
- [ ] `aegis query --control "cis-rhel9-v2.0.0:5.1"` lists section rules
- [ ] `aegis query --rule <id>` shows all framework references
- [ ] `aegis query --framework <id> --list-controls` shows control summary
- [ ] JSON output option for all queries

## Dependencies

- Requires P2-3 (Framework Mapping Layer) — Complete

## Future Extensions

- **STIG Checklist export**: Generate `.ckl` files for STIG Viewer from query results
- **Gap analysis**: Compare two frameworks, show rules in one but not the other
- **Compliance matrix**: Generate spreadsheet mapping rules to multiple frameworks
