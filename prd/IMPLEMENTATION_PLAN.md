# P3 Implementation Plan

## Executive Summary

**Key Finding:** The codebase is further along than the PRDs indicate.

| Metric | P3-2 Target | Current State |
|--------|-------------|---------------|
| Canonical rules | 180 | **194** (108%) |
| CIS RHEL 9 coverage | 90% | 53% (151/285 mapped) |
| STIG RHEL 9 coverage | 85% | 52% (232/446 mapped) |
| Check handlers | 17 | 18 (100%) |
| Remediation handlers | 23 | 23 (100%) |

**Revised Strategy:**
- P3-2's rule authoring is largely complete — refocus on mapping gap analysis
- P3-1 has three deferred features with varying effort levels
- Reorder priorities: P3-1.1 (framework output) → P3-2 (mapping completion) → P3-1.2/1.3 (queries)

---

## Phase 1: Framework-Ordered Output (P3-1.1)

**Effort:** Low (1-2 days)
**Impact:** High — immediate auditor value

### Problem
Results are sorted alphabetically by rule ID. Auditors expect CIS section order (1.1.1 < 1.1.2 < 5.2.3).

### Current State
- `order_by_framework()` helper exists in `runner/mappings.py:390-414`
- Output formatters already include `framework_section` field
- Just need to integrate ordering into output pipeline

### Implementation

#### 1.1 Modify CLI output pipeline

**File:** `runner/cli.py`

```python
# In _run_checks() after collecting results, before writing output
if framework_mapping:
    # Reorder results by framework section
    host_result.results = order_by_framework(framework_mapping, host_result.results)
```

#### 1.2 Update terminal output

Add section column to rich table when framework is active:

```python
# In _render_results_table()
if framework_section:
    table.add_column("Section", style="dim")
# Results rows include section as first data column
```

#### 1.3 Update order_by_framework for result objects

Current `order_by_framework()` works on rule dicts. Extend to work on `CheckResult` objects:

```python
def order_results_by_framework(
    mapping: FrameworkMapping,
    results: list[CheckResult],
) -> list[CheckResult]:
    """Order CheckResult objects by framework section."""
    rule_to_section = build_rule_to_section_map(mapping)

    def section_key(result: CheckResult) -> tuple:
        section = rule_to_section.get(result.rule_id, "zzz")
        # Parse section number for proper numeric ordering
        parts = section.split(".")
        return tuple(int(p) if p.isdigit() else p for p in parts)

    return sorted(results, key=section_key)
```

### Acceptance Criteria
- [ ] Terminal output shows Section column when `--framework` specified
- [ ] Results ordered by section number (1.1.1 < 1.1.2 < 1.2.1 < 5.1.1)
- [ ] JSON output results array ordered by section
- [ ] CSV rows ordered by section
- [ ] PDF table ordered by section

---

## Phase 2: Mapping Gap Analysis & Completion (P3-2 Revised)

**Effort:** Medium (1-2 weeks)
**Impact:** High — complete framework coverage

### Problem
194 rules exist but only ~53% of CIS and ~52% of STIG sections are mapped. Two causes:
1. Rules exist but aren't mapped to framework sections
2. Framework sections have no corresponding canonical rule

### Current State

From coverage analysis:

| Framework | Total Sections | Mapped | Unimplemented | Missing |
|-----------|---------------|--------|---------------|---------|
| CIS RHEL 9 v2.0.0 | 285 | 151 | 134 | 0 |
| STIG RHEL 9 V2R7 | 446 | 232 | 214 | 0 |

**Good news:** Zero "missing" entries — all mapped rules reference valid rule IDs.

### Implementation

#### 2.1 Generate mapping gap report

Create a script to identify unmapped rules and incomplete framework sections:

**File:** `scripts/mapping_gap_report.py`

```python
#!/usr/bin/env python3
"""Generate mapping gap analysis for frameworks."""

from pathlib import Path
from runner.mappings import load_all_mappings, check_coverage
from runner._loading import load_rules

def main():
    rules = load_rules(Path("rules"))
    mappings = load_all_mappings(Path("mappings"))

    for mapping_id, mapping in mappings.items():
        print(f"\n{'='*60}")
        print(f"Framework: {mapping.title}")
        print(f"{'='*60}")

        coverage = check_coverage(mapping, {r["id"] for r in rules})

        # Rules that exist but aren't in this mapping
        mapped_rules = {e.rule_id for e in mapping.sections.values()}
        unmapped_rules = {r["id"] for r in rules} - mapped_rules

        print(f"\nCoverage: {coverage.implemented}/{coverage.total} ({coverage.percent:.1f}%)")
        print(f"Unmapped canonical rules: {len(unmapped_rules)}")

        # Categorize unimplemented sections
        print(f"\nUnimplemented sections by reason:")
        reasons = {}
        for section_id, entry in mapping.unimplemented.items():
            reason = entry.reason or "unspecified"
            reasons.setdefault(reason, []).append(section_id)

        for reason, sections in sorted(reasons.items()):
            print(f"  {reason}: {len(sections)}")
```

#### 2.2 Audit unimplemented sections

Review `unimplemented` sections in each mapping to identify:
1. Sections marked manual that could be automated
2. Sections with existing rules not yet mapped
3. Sections genuinely requiring new rules

**Priority categories for CIS RHEL 9:**

| Section Range | Category | Est. Effort |
|--------------|----------|-------------|
| 1.x | Initial Setup | Low — mostly done |
| 2.x | Services | Medium — service checks |
| 3.x | Network | Medium — sysctl rules exist |
| 4.x | Logging/Audit | High — complex audit rules |
| 5.x | Access Control | Low — mostly done |
| 6.x | Maintenance | Medium — file audits |

#### 2.3 Add missing mappings

For each rule that exists but isn't mapped, add the appropriate section entry:

```yaml
sections:
  "5.2.16":  # Example: CIS section that maps to existing rule
    rule: ssh-ciphers-fips
    level: L1
    type: Automated
    title: "Ensure only strong ciphers are used"
```

#### 2.4 Create new rules where needed

For unimplemented sections that should be automated:
1. Identify the check method (config_value, sysctl_value, etc.)
2. Create canonical rule YAML
3. Add mapping entry
4. Validate with `python3 schema/validate.py`

### Acceptance Criteria
- [ ] Mapping gap report script created
- [ ] CIS RHEL 9 coverage ≥ 85%
- [ ] STIG RHEL 9 coverage ≥ 80%
- [ ] All unimplemented sections have explicit `reason` field
- [ ] Zero schema validation errors

---

## Phase 3: Automatic Framework Selection (P3-1.2)

**Effort:** Medium (2-3 days)
**Impact:** Medium — convenience feature

### Problem
Users must specify `--framework cis-rhel9-v2.0.0` explicitly. Auto-detection would improve UX.

### Current State
- `detect_platform()` returns `PlatformInfo(family, version)`
- `get_applicable_mappings()` filters by platform constraint
- Just need to wire them together

### Implementation

#### 3.1 Add `--framework auto` option

**File:** `runner/cli.py`

```python
@click.option(
    "--framework",
    help="Framework to filter rules. Use 'auto' for platform detection.",
)
def check(framework, ...):
    if framework == "auto":
        # Detect platform and select applicable mappings
        platform = detect_platform(ssh)
        if platform:
            applicable = get_applicable_mappings(
                all_mappings,
                family=platform.family,
                version=platform.version,
            )
            if applicable:
                console.print(f"[dim]Auto-selected frameworks: {', '.join(applicable.keys())}[/]")
                # Use union of rules from all applicable mappings
                framework_rules = set()
                for mapping in applicable.values():
                    framework_rules.update(e.rule_id for e in mapping.sections.values())
                # Filter rules to those in applicable frameworks
                rules = [r for r in rules if r["id"] in framework_rules]
            else:
                console.print("[yellow]Warning: No applicable frameworks for detected platform[/]")
```

#### 3.2 Handle multiple applicable frameworks

When multiple mappings match (e.g., CIS and STIG for RHEL 9):
- Run union of rules (deduplicated by rule ID)
- Track which framework each rule came from for reporting
- Allow `--framework auto:cis` to auto-select only CIS variants

#### 3.3 Update output to show selected frameworks

```python
# In JSON output metadata
{
    "auto_selected_frameworks": ["cis-rhel9-v2.0.0", "stig-rhel9-v2r7"],
    "detected_platform": {"family": "rhel", "version": 9},
    ...
}
```

### Acceptance Criteria
- [ ] `--framework auto` detects platform and selects applicable mappings
- [ ] Multiple applicable mappings: runs union of rules (deduplicated)
- [ ] No applicable mappings: warns and runs without framework filter
- [ ] Works with both `check` and `remediate` commands
- [ ] Output shows which frameworks were auto-selected

---

## Phase 4: Cross-Reference Queries (P3-1.3)

**Effort:** High (1 week)
**Impact:** Medium — compliance analysis feature

### Problem
No way to query:
- "Which rules satisfy NIST AC-6?"
- "What frameworks reference ssh-disable-root-login?"
- "List all CIS controls with rule counts"

### Implementation

#### 4.1 Create FrameworkIndex class

**File:** `runner/mappings.py`

```python
@dataclass
class FrameworkIndex:
    """Cross-reference index for all loaded mappings."""

    # rule_id -> [(mapping_id, section_id, entry), ...]
    rules_to_frameworks: dict[str, list[tuple[str, str, MappingEntry]]]

    # section/control ID -> [rule_id, ...]  (for NIST many-to-many)
    controls_to_rules: dict[str, list[str]]

    @classmethod
    def build(cls, mappings: dict[str, FrameworkMapping]) -> "FrameworkIndex":
        """Build cross-reference index from all mappings."""
        rules_to_frameworks = {}
        controls_to_rules = {}

        for mapping_id, mapping in mappings.items():
            for section_id, entry in mapping.sections.items():
                # Forward index: section -> rule
                controls_to_rules.setdefault(f"{mapping_id}:{section_id}", []).append(entry.rule_id)

                # Reverse index: rule -> sections
                rules_to_frameworks.setdefault(entry.rule_id, []).append(
                    (mapping_id, section_id, entry)
                )

        return cls(rules_to_frameworks, controls_to_rules)

    def query_by_rule(self, rule_id: str) -> list[tuple[str, str, MappingEntry]]:
        """Find all framework references for a rule."""
        return self.rules_to_frameworks.get(rule_id, [])

    def query_by_control(self, control_spec: str) -> list[str]:
        """Find rules implementing a control. Format: 'framework:section' or 'section'."""
        if ":" in control_spec:
            return self.controls_to_rules.get(control_spec, [])

        # Search all frameworks for matching section prefix
        results = []
        for key, rules in self.controls_to_rules.items():
            if key.endswith(f":{control_spec}") or f":{control_spec}." in key:
                results.extend(rules)
        return list(set(results))
```

#### 4.2 Add query command

**File:** `runner/cli.py`

```python
@cli.command()
@click.option("--control", help="Find rules implementing a control (e.g., 'nist:AC-6', 'cis-rhel9-v2.0.0:5.1')")
@click.option("--rule", help="Find framework references for a rule ID")
@click.option("--framework", help="Limit query to specific framework")
@click.option("--list-controls", is_flag=True, help="List all controls with rule counts")
@click.option("--json", "json_output", is_flag=True, help="JSON output")
def query(control, rule, framework, list_controls, json_output):
    """Query framework cross-references."""
    mappings = load_all_mappings(Path("mappings"))
    index = FrameworkIndex.build(mappings)

    if control:
        rules = index.query_by_control(control)
        # Display rules implementing this control
        ...

    if rule:
        refs = index.query_by_rule(rule)
        # Display framework references for this rule
        ...

    if list_controls:
        # Display all controls with rule counts
        ...
```

#### 4.3 Query output formats

**Terminal output:**
```
$ aegis query --rule ssh-disable-root-login

Rule: ssh-disable-root-login
Title: Disable SSH root login

Framework References:
  CIS RHEL 9 v2.0.0:     Section 5.1.12 (L1, Automated)
  STIG RHEL 9 V2R7:      V-257947 (CAT II)
```

**JSON output:**
```json
{
  "rule_id": "ssh-disable-root-login",
  "title": "Disable SSH root login",
  "references": [
    {
      "framework": "cis-rhel9-v2.0.0",
      "section": "5.1.12",
      "level": "L1",
      "type": "Automated"
    },
    {
      "framework": "stig-rhel9-v2r7",
      "section": "V-257947",
      "severity": "medium"
    }
  ]
}
```

### Acceptance Criteria
- [ ] `aegis query --control "cis-rhel9-v2.0.0:5.1"` lists section rules
- [ ] `aegis query --rule <id>` shows all framework references
- [ ] `aegis query --framework <id> --list-controls` shows control summary
- [ ] JSON output option for all queries
- [ ] Query results include framework metadata (level, severity, etc.)

---

## Phase 5: NIST Control Mapping (P3-1.3 Extension)

**Effort:** Medium (3-4 days)
**Impact:** Medium — federal compliance requirement

### Problem
NIST 800-53 controls are many-to-many: one control maps to multiple rules, one rule satisfies multiple controls. Current mapping format doesn't support this well.

### Implementation

#### 5.1 Add NIST mapping file

**File:** `mappings/nist/800-53_r5.yaml`

```yaml
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
      - su-require-wheel

  "AC-17(2)":
    title: "Remote Access | Protection of Confidentiality and Integrity Using Encryption"
    rules:
      - ssh-ciphers-fips
      - ssh-macs-fips
      - ssh-kex-fips
      - crypto-policy-fips
```

#### 5.2 Extend FrameworkIndex for many-to-many

The `FrameworkIndex.build()` method already handles the `controls` key format with multiple rules per control. Just need to ensure query methods work correctly.

### Acceptance Criteria
- [ ] NIST 800-53 r5 mapping file created with key controls
- [ ] `aegis query --control "nist:AC-6"` returns all implementing rules
- [ ] Coverage report shows NIST control coverage
- [ ] Rules can appear in multiple NIST controls

---

## Timeline Summary

| Phase | Focus | Effort | Dependencies |
|-------|-------|--------|--------------|
| **1** | Framework-ordered output | 1-2 days | None |
| **2** | Mapping gap completion | 1-2 weeks | Phase 1 |
| **3** | Auto framework selection | 2-3 days | Phase 2 |
| **4** | Cross-reference queries | 1 week | Phase 2 |
| **5** | NIST control mapping | 3-4 days | Phase 4 |

**Total estimated effort:** 4-5 weeks

---

## Priority Recommendation

**Immediate (Phase 1):** Framework-ordered output
- Lowest effort, highest auditor value
- Can ship independently

**Short-term (Phase 2):** Mapping completion
- Highest coverage impact
- Enables better P3-1 demos

**Medium-term (Phase 3-4):** Auto-selection and queries
- Convenience features
- Can be done in parallel

**Optional (Phase 5):** NIST mappings
- Important for federal customers
- Builds on Phase 4 infrastructure

---

## Files to Modify

| Phase | Files |
|-------|-------|
| 1 | `runner/cli.py`, `runner/mappings.py`, `runner/output/*.py` |
| 2 | `mappings/cis/*.yaml`, `mappings/stig/*.yaml`, `scripts/mapping_gap_report.py` |
| 3 | `runner/cli.py` |
| 4 | `runner/mappings.py`, `runner/cli.py` |
| 5 | `mappings/nist/800-53_r5.yaml`, `runner/mappings.py` |

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| CIS RHEL 9 coverage | 53% | 85% |
| STIG RHEL 9 coverage | 52% | 80% |
| Framework-ordered output | No | Yes |
| Auto framework selection | No | Yes |
| Query command | No | Yes |
| NIST 800-53 mapping | No | Yes |
