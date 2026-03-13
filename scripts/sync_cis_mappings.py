#!/usr/bin/env python3
"""Synchronize CIS mappings between canonical mapping file and KENSA rules.

This script uses the mapping file as the source of truth and:
1. Reports rules with incorrect CIS section references
2. Reports coverage gaps (CIS sections without KENSA rules)
3. Optionally fixes rule files with correct section numbers

Usage:
    # Report discrepancies
    python3 scripts/sync_cis_mappings.py --mapping mappings/cis/rhel9.yaml

    # Fix rule files
    python3 scripts/sync_cis_mappings.py --mapping mappings/cis/rhel9.yaml --fix

    # Verbose output
    python3 scripts/sync_cis_mappings.py --mapping mappings/cis/rhel9.yaml -v
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml


def load_mapping(mapping_path: str) -> dict:
    """Load canonical CIS mapping file."""
    with open(mapping_path) as f:
        data = yaml.safe_load(f)
    return data


def load_rules(rules_dir: str) -> dict[str, dict]:
    """Load all KENSA rules and extract CIS references."""
    rules = {}
    rules_path = Path(rules_dir)

    for rule_file in sorted(rules_path.rglob("*.yml")):
        if rule_file.name == "defaults.yml":
            continue

        try:
            with open(rule_file) as f:
                rule = yaml.safe_load(f)

            if not isinstance(rule, dict) or "id" not in rule:
                continue

            rules[rule["id"]] = {
                "path": str(rule_file),
                "title": rule.get("title", ""),
                "references": rule.get("references", {}),
                "raw": rule,
            }
        except Exception as e:
            print(f"  Warning: Failed to parse {rule_file}: {e}", file=sys.stderr)

    return rules


def analyze_mappings(
    mapping: dict,
    rules: dict[str, dict],
    ref_key: str,
    verbose: bool = False,
) -> dict:
    """Compare canonical mappings against actual rule references."""
    results = {
        "correct": [],
        "misaligned": [],
        "missing_in_rules": [],
        "extra_in_rules": [],
        "not_implemented": [],
    }

    controls = mapping.get("controls", {})

    # Build reverse lookup: rule -> expected CIS sections
    rule_to_sections: dict[str, list[str]] = {}
    for section, data in controls.items():
        if not isinstance(data, dict):
            continue
        for kensa_rule in data.get("rules", []):
            if kensa_rule:
                rule_to_sections.setdefault(kensa_rule, []).append(section)

    # Check each control
    for section, data in controls.items():
        if not isinstance(data, dict):
            continue

        rule_list = data.get("rules", [])
        title = data.get("title", "")
        control_type = data.get("type", "Automated")

        if not rule_list:
            results["not_implemented"].append({
                "section": section,
                "title": title,
                "type": control_type,
            })
            continue

        for kensa_rule in rule_list:
            if kensa_rule not in rules:
                results["missing_in_rules"].append({
                    "section": section,
                    "title": title,
                    "expected_rule": kensa_rule,
                })
                continue

            # Check if rule has correct CIS reference
            rule = rules[kensa_rule]
            cis_refs = rule["references"].get("cis", {})
            ref_data = cis_refs.get(ref_key, {})
            actual_section = ref_data.get("section", "") if isinstance(ref_data, dict) else ""

            if actual_section == section:
                results["correct"].append({
                    "section": section,
                    "rule": kensa_rule,
                })
            else:
                results["misaligned"].append({
                    "section": section,
                    "title": title,
                    "rule": kensa_rule,
                    "rule_path": rule["path"],
                    "expected_section": section,
                    "actual_section": actual_section or "(missing)",
                })

    # Check for extra references in rules (not in canonical mapping)
    for rule_id, rule in rules.items():
        cis_refs = rule["references"].get("cis", {})
        ref_data = cis_refs.get(ref_key, {})
        actual_section = ref_data.get("section", "") if isinstance(ref_data, dict) else ""

        if actual_section and actual_section not in controls:
            results["extra_in_rules"].append({
                "rule": rule_id,
                "rule_path": rule["path"],
                "section": actual_section,
            })

    return results


def fix_rule(rule_path: str, ref_key: str, old_section: str, new_section: str) -> bool:
    """Update a rule file with the correct CIS section."""
    try:
        with open(rule_path) as f:
            content = f.read()

        # Pattern to match the section line within the ref_key block
        # This handles: rhel9: { section: "X.X.X", ... }
        pattern = rf'({ref_key}:\s*\{{\s*section:\s*["\'])({re.escape(old_section)})(["\'])'
        replacement = rf'\g<1>{new_section}\g<3>'

        new_content, count = re.subn(pattern, replacement, content)

        if count == 0:
            # Try alternate format: section on separate line
            pattern2 = rf'(^\s+{ref_key}:.*?section:\s*["\'])({re.escape(old_section)})(["\'])'
            new_content, count = re.subn(pattern2, replacement, content, flags=re.MULTILINE)

        if count > 0:
            with open(rule_path, "w") as f:
                f.write(new_content)
            return True

        return False
    except Exception as e:
        print(f"  Error fixing {rule_path}: {e}", file=sys.stderr)
        return False


def print_report(results: dict, verbose: bool = False) -> None:
    """Print analysis report."""
    print("\n" + "=" * 70)
    print("CIS MAPPING ANALYSIS REPORT")
    print("=" * 70)

    # Summary
    print("\n## Summary\n")
    print(f"  Correct mappings:     {len(results['correct']):3d}")
    print(f"  Misaligned sections:  {len(results['misaligned']):3d}  <- FIX THESE")
    print(f"  Missing rules:        {len(results['missing_in_rules']):3d}  <- Rules referenced but not found")
    print(f"  Extra in rules:       {len(results['extra_in_rules']):3d}  <- Rules have sections not in mapping")
    print(f"  Not implemented:      {len(results['not_implemented']):3d}  <- CIS sections without KENSA rules")

    # Misaligned (most important)
    if results["misaligned"]:
        print("\n## Misaligned Sections (NEEDS FIX)\n")
        print(f"  {'Section':<12} {'Rule ID':<35} {'Actual':<12} {'Expected':<12}")
        print(f"  {'-'*12} {'-'*35} {'-'*12} {'-'*12}")
        for item in results["misaligned"]:
            print(f"  {item['expected_section']:<12} {item['rule']:<35} {item['actual_section']:<12} {item['expected_section']:<12}")
            if verbose:
                print(f"    File: {item['rule_path']}")

    # Extra in rules
    if results["extra_in_rules"]:
        print("\n## Extra Sections in Rules (not in canonical mapping)\n")
        for item in results["extra_in_rules"]:
            print(f"  {item['section']:<12} {item['rule']}")
            if verbose:
                print(f"    File: {item['rule_path']}")

    # Not implemented
    if results["not_implemented"] and verbose:
        print("\n## Not Implemented (CIS sections without KENSA rules)\n")
        for item in sorted(results["not_implemented"], key=lambda x: x["section"]):
            type_marker = "[M]" if item.get("type") == "Manual" else "[A]"
            print(f"  {item['section']:<12} {type_marker} {item['title'][:50]}")

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Sync CIS mappings with KENSA rules")
    parser.add_argument(
        "--mapping",
        required=True,
        help="Path to canonical CIS mapping YAML file",
    )
    parser.add_argument(
        "--rules",
        default="rules",
        help="Path to rules directory (default: rules)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Fix misaligned section references in rule files",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    args = parser.parse_args()

    print(f"Loading canonical mapping: {args.mapping}")
    mapping = load_mapping(args.mapping)
    ref_key = mapping.get("framework", {}).get("reference_key", "rhel9")
    print(f"  Reference key: {ref_key}")
    print(f"  Controls: {len(mapping.get('controls', {}))}")

    print(f"\nLoading rules from: {args.rules}")
    rules = load_rules(args.rules)
    print(f"  Rules found: {len(rules)}")

    print("\nAnalyzing mappings...")
    results = analyze_mappings(mapping, rules, ref_key, verbose=args.verbose)

    print_report(results, verbose=args.verbose)

    # Fix if requested
    if args.fix and results["misaligned"]:
        print("\n## Fixing misaligned sections...\n")
        fixed = 0
        for item in results["misaligned"]:
            if item["actual_section"] == "(missing)":
                print(f"  SKIP {item['rule']}: No existing section to update (needs manual add)")
                continue

            success = fix_rule(
                item["rule_path"],
                ref_key,
                item["actual_section"],
                item["expected_section"],
            )
            if success:
                print(f"  FIXED {item['rule']}: {item['actual_section']} -> {item['expected_section']}")
                fixed += 1
            else:
                print(f"  FAILED {item['rule']}: Could not update section")

        print(f"\n  Fixed {fixed} of {len(results['misaligned'])} rules")

    # Exit with error if there are issues
    if results["misaligned"] or results["missing_in_rules"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
