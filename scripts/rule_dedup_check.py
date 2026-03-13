#!/usr/bin/env python3
"""Rule duplication checker (pre-commit hook, Layer 1).

Scans all rule YAML files in rules/ and detects:
  1. Duplicate rule IDs across category directories
  2. Same framework control (CIS section / STIG vuln_id) in multiple rules
  3. Rules with conflicts_with (potential duplicates, warning only)

Usage:
    python scripts/rule_dedup_check.py                    # Scan all rules
    python scripts/rule_dedup_check.py --json              # Machine-readable
    python scripts/rule_dedup_check.py rules/foo.yml ...   # Pre-commit mode
    python scripts/rule_dedup_check.py --baseline FILE     # Only fail on NEW violations
    python scripts/rule_dedup_check.py --save-baseline FILE  # Save current state

When --baseline is provided, the script loads a JSON file of known violations
and only exits 1 if NEW violations are found beyond the baseline. This allows
the pre-commit hook and CI to pass while legacy duplicates are cleaned up
incrementally.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_BASELINE = PROJECT_ROOT / ".rule_dedup_baseline.json"


# ── Helpers ──────────────────────────────────────────────────────────────────


def load_rules() -> list[dict]:
    """Load all rule YAML files from rules/, skipping unparseable files."""
    rules = []
    for path in sorted(RULES_DIR.rglob("*.y*ml")):
        if path.suffix not in (".yml", ".yaml"):
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"  warning: failed to parse {path.relative_to(PROJECT_ROOT)}: {exc}", file=sys.stderr)
            continue
        if not isinstance(data, dict) or "id" not in data:
            continue
        data["_path"] = str(path.relative_to(PROJECT_ROOT))
        data["_category"] = path.parent.name
        rules.append(data)
    return rules


def _extract_control_refs(rule: dict) -> list[tuple[str, str, str]]:
    """Return list of (framework, os_version, control_id) from references."""
    refs = rule.get("references", {}) or {}
    results: list[tuple[str, str, str]] = []

    # CIS: references.cis.<os>.section
    cis = refs.get("cis") or {}
    for os_ver, entry in cis.items():
        if isinstance(entry, dict) and "section" in entry:
            results.append(("cis", str(os_ver), str(entry["section"])))

    # STIG: references.stig.<os>.vuln_id
    stig = refs.get("stig") or {}
    for os_ver, entry in stig.items():
        if isinstance(entry, dict) and "vuln_id" in entry:
            results.append(("stig", str(os_ver), str(entry["vuln_id"])))

    return results


def _get_conflicts(rule: dict) -> list[str]:
    """Return conflicts_with list (may be empty)."""
    val = rule.get("conflicts_with")
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [val]
    return []


def _get_supersedes(rule: dict) -> list[str]:
    """Return supersedes list (may be empty)."""
    val = rule.get("supersedes")
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [val]
    return []


def _is_known_pair(rule_a_id: str, rule_b_id: str, rules_by_id: dict[str, dict]) -> bool:
    """Check if two rules mutually reference each other via conflicts_with or supersedes."""
    a = rules_by_id.get(rule_a_id, {})
    b = rules_by_id.get(rule_b_id, {})

    a_refs = set(_get_conflicts(a)) | set(_get_supersedes(a))
    b_refs = set(_get_conflicts(b)) | set(_get_supersedes(b))

    # Either direction counts as "known"
    return rule_b_id in a_refs or rule_a_id in b_refs


# ── Analysis ─────────────────────────────────────────────────────────────────


def analyze(rules: list[dict]) -> dict:
    """Run all duplication checks. Returns structured results."""
    rules_by_id: dict[str, list[dict]] = {}
    for rule in rules:
        rid = rule["id"]
        rules_by_id.setdefault(rid, []).append(rule)

    # Flat lookup for known-pair checks
    rules_flat: dict[str, dict] = {}
    for rule in rules:
        rules_flat[rule["id"]] = rule

    # Check 1: Duplicate rule IDs across directories
    duplicate_ids = []
    for rid, copies in sorted(rules_by_id.items()):
        if len(copies) < 2:
            continue
        categories = [c["_category"] for c in copies]
        if len(set(categories)) > 1:
            duplicate_ids.append({
                "rule_id": rid,
                "files": [c["_path"] for c in copies],
            })

    # Check 2: Same framework control in multiple rules
    # Map (framework, os_version, control_id) -> [(rule_id, path)]
    control_map: dict[tuple[str, str, str], list[tuple[str, str]]] = {}
    for rule in rules:
        for key in _extract_control_refs(rule):
            control_map.setdefault(key, []).append((rule["id"], rule["_path"]))

    duplicate_controls = []
    seen_control_pairs: set[tuple[str, str, str, str, str]] = set()
    for (fw, os_ver, ctrl_id), entries in sorted(control_map.items()):
        # Deduplicate entries (same rule ID loaded once)
        unique = {}
        for rid, path in entries:
            unique.setdefault(rid, path)
        if len(unique) < 2:
            continue

        rule_ids = sorted(unique.keys())
        # Avoid duplicate pair reports
        pair_key = (fw, os_ver, ctrl_id, rule_ids[0], rule_ids[1])
        if pair_key in seen_control_pairs:
            continue
        seen_control_pairs.add(pair_key)

        known = _is_known_pair(rule_ids[0], rule_ids[1], rules_flat)
        duplicate_controls.append({
            "framework": fw,
            "os_version": os_ver,
            "control_id": ctrl_id,
            "rules": [{"id": rid, "file": unique[rid]} for rid in rule_ids],
            "known": known,
        })

    # Check 3: conflicts_with audit (warnings)
    conflicts_warnings = []
    for rule in sorted(rules, key=lambda r: r["id"]):
        cw = _get_conflicts(rule)
        if cw:
            conflicts_warnings.append({
                "rule_id": rule["id"],
                "file": rule["_path"],
                "conflicts_with": cw,
            })

    error_count = len(duplicate_ids) + len(duplicate_controls)
    warning_count = len(conflicts_warnings)

    return {
        "duplicate_ids": duplicate_ids,
        "duplicate_controls": duplicate_controls,
        "conflicts_with_warnings": conflicts_warnings,
        "summary": {"errors": error_count, "warnings": warning_count},
    }


# ── Output formatters ───────────────────────────────────────────────────────


def format_text(results: dict) -> str:
    """Format results as human-readable text."""
    lines: list[str] = []
    lines.append("RULE DUPLICATION CHECK")
    lines.append("======================")
    lines.append("")

    dup_ids = results["duplicate_ids"]
    dup_ctrls = results["duplicate_controls"]
    cw_warnings = results["conflicts_with_warnings"]
    summary = results["summary"]

    if summary["errors"] > 0:
        lines.append("ERRORS (block merge):")
        lines.append("")

        if dup_ids:
            lines.append("  Duplicate rule ID across directories:")
            for entry in dup_ids:
                files = ", ".join(entry["files"])
                lines.append(f"    \u2717 {entry['rule_id']}: {files}")
            lines.append("")

        if dup_ctrls:
            lines.append("  Same framework control in multiple rules:")
            for entry in dup_ctrls:
                fw = entry["framework"].upper()
                os_ver = entry["os_version"]
                ctrl = entry["control_id"]
                rule_parts = ", ".join(
                    f"{r['id']} ({r['file']})" for r in entry["rules"]
                )
                tag = " [known: conflicts_with]" if entry["known"] else ""
                lines.append(f"    \u2717 {fw} {os_ver} {ctrl}: {rule_parts}{tag}")
            lines.append("")
    else:
        lines.append("No errors found.")
        lines.append("")

    if cw_warnings:
        lines.append("WARNINGS:")
        lines.append("")
        lines.append("  Rules with conflicts_with (potential duplicates):")
        for entry in cw_warnings:
            cw_list = ", ".join(entry["conflicts_with"])
            lines.append(f"    \u26a0 {entry['rule_id']} conflicts_with: [{cw_list}]")
        lines.append("")

    lines.append(f"Summary: {summary['errors']} errors, {summary['warnings']} warnings")
    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────


def _load_baseline(path: Path) -> dict:
    """Load a baseline JSON file of known violations."""
    if not path.exists():
        return {"duplicate_ids": set(), "duplicate_controls": set()}
    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return {"duplicate_ids": set(), "duplicate_controls": set()}
        data = json.loads(text)
    except (json.JSONDecodeError, OSError):
        print(f"  warning: could not parse baseline {path}, treating as empty", file=sys.stderr)
        return {"duplicate_ids": set(), "duplicate_controls": set()}
    return {
        "duplicate_ids": set(data.get("duplicate_ids", [])),
        "duplicate_controls": set(data.get("duplicate_controls", [])),
    }


def _save_baseline(path: Path, results: dict) -> None:
    """Save current violations as the new baseline."""
    baseline = {
        "duplicate_ids": sorted(e["rule_id"] for e in results["duplicate_ids"]),
        "duplicate_controls": sorted(
            f"{e['framework']}:{e['os_version']}:{e['control_id']}"
            for e in results["duplicate_controls"]
        ),
    }
    path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def _count_new_errors(results: dict, baseline: dict) -> int:
    """Count errors not present in the baseline."""
    new_errors = 0
    bl_ids = baseline["duplicate_ids"]
    bl_ctrls = baseline["duplicate_controls"]

    for entry in results["duplicate_ids"]:
        if entry["rule_id"] not in bl_ids:
            new_errors += 1

    for entry in results["duplicate_controls"]:
        key = f"{entry['framework']}:{entry['os_version']}:{entry['control_id']}"
        if key not in bl_ctrls:
            new_errors += 1

    return new_errors


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Check for rule duplication violations."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        nargs="?",
        const=DEFAULT_BASELINE,
        default=None,
        help="Only fail on NEW violations beyond the baseline (default: .rule_dedup_baseline.json)",
    )
    parser.add_argument(
        "--save-baseline",
        type=Path,
        nargs="?",
        const=DEFAULT_BASELINE,
        default=None,
        dest="save_baseline",
        help="Save current violations as the new baseline",
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Print violations but always exit 0 (for pre-commit hooks)",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Rule files (pre-commit mode, ignored — always scans all rules)",
    )
    args = parser.parse_args()

    rules = load_rules()
    if not rules:
        print("No rule files found in rules/", file=sys.stderr)
        sys.exit(1)

    results = analyze(rules)

    if args.save_baseline:
        _save_baseline(args.save_baseline, results)
        print(f"Baseline saved to {args.save_baseline} ({results['summary']['errors']} known violations)")
        sys.exit(0)

    if args.json_output:
        print(json.dumps(results, indent=2))
    else:
        print(format_text(results))

    if args.baseline:
        baseline = _load_baseline(args.baseline)
        new_errors = _count_new_errors(results, baseline)
        if new_errors > 0:
            print(f"\n{new_errors} NEW violation(s) not in baseline — failing.")
            sys.exit(1)
        else:
            bl_total = len(baseline["duplicate_ids"]) + len(baseline["duplicate_controls"])
            print(f"\nAll {results['summary']['errors']} violations are in baseline ({bl_total} known). No new violations.")
            sys.exit(0)

    if args.warn_only:
        sys.exit(0)

    sys.exit(1 if results["summary"]["errors"] > 0 else 0)


if __name__ == "__main__":
    main()
