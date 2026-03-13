"""Deep rule duplication analysis for Kensa CI (Layer 2).

Performs four categories of analysis:

1. **Duplicate IDs** — two rule files with the same ``id:`` field.
2. **Same framework control** — two rules claiming the same CIS/STIG control.
3. **Same check target** — two rules checking the same system resource
   (config key, service, sysctl, file permission, kernel module, package).
4. **One-sided CIS references** — rules with CIS refs for RHEL 8 but not 9
   (or vice versa), suggesting the other half may live in a different rule.
5. **Orphaned rules** — rules not referenced by any mapping file.

Usage:
    python3 scripts/rule_dedup_validate.py          # Text report
    python3 scripts/rule_dedup_validate.py --json   # JSON output

Exit code:
    0 if no ERRORS (warnings alone are informational).
    1 if any ERRORS (duplicate IDs or same framework control).
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

# Project root is one level above scripts/
ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
MAPPINGS_DIR = ROOT / "mappings"


# ---------------------------------------------------------------------------
# YAML helpers
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> dict | None:
    """Load a YAML file, returning None on error."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return None


def _discover_rules() -> list[Path]:
    """Return all *.yml files under rules/."""
    return sorted(RULES_DIR.rglob("*.yml"))


def _discover_mappings() -> list[Path]:
    """Return all mapping YAML files under mappings/."""
    paths: list[Path] = []
    for ext in ("*.yaml", "*.yml"):
        paths.extend(MAPPINGS_DIR.rglob(ext))
    return sorted(paths)


# ---------------------------------------------------------------------------
# Check 4 (Layer 1): Duplicate IDs and same framework control
# ---------------------------------------------------------------------------

def _check_duplicate_ids(
    rules: dict[str, tuple[dict, Path]],
) -> list[dict]:
    """Find rule files that share the same id: value."""
    id_to_files: dict[str, list[Path]] = defaultdict(list)
    for rule_path in RULES_DIR.rglob("*.yml"):
        data = _load_yaml(rule_path)
        if data and "id" in data:
            id_to_files[data["id"]].append(rule_path)

    errors: list[dict] = []
    for rule_id, paths in sorted(id_to_files.items()):
        if len(paths) > 1:
            errors.append({
                "type": "duplicate_id",
                "rule_id": rule_id,
                "files": [str(p.relative_to(ROOT)) for p in paths],
            })
    return errors


def _check_same_framework_control(
    rules: dict[str, tuple[dict, Path]],
) -> list[dict]:
    """Find rules that claim the same CIS/STIG control."""
    # Map (framework, version, control_id) -> [(rule_id, path)]
    control_map: dict[tuple[str, str, str], list[tuple[str, Path]]] = defaultdict(list)

    for rule_id, (data, path) in rules.items():
        refs = data.get("references", {})
        if not isinstance(refs, dict):
            continue

        # CIS references
        cis = refs.get("cis", {})
        if isinstance(cis, dict):
            for version_key, ref_data in cis.items():
                if isinstance(ref_data, dict):
                    section = ref_data.get("section", "")
                    if section:
                        control_map[("cis", str(version_key), str(section))].append(
                            (rule_id, path)
                        )

        # STIG references
        stig = refs.get("stig", {})
        if isinstance(stig, dict):
            for version_key, ref_data in stig.items():
                if isinstance(ref_data, dict):
                    vuln_id = ref_data.get("vuln_id", "")
                    if vuln_id:
                        control_map[("stig", str(version_key), str(vuln_id))].append(
                            (rule_id, path)
                        )

    errors: list[dict] = []
    for (fw, ver, ctrl), entries in sorted(control_map.items()):
        if len(entries) > 1:
            errors.append({
                "type": "same_framework_control",
                "framework": fw,
                "version": ver,
                "control": ctrl,
                "rules": [
                    {"id": rid, "file": str(p.relative_to(ROOT))}
                    for rid, p in entries
                ],
            })
    return errors


# ---------------------------------------------------------------------------
# Check 1: Same check target detection
# ---------------------------------------------------------------------------

def _extract_check_targets(
    check: dict,
) -> list[tuple[str, str]]:
    """Extract (target_type, target_key) pairs from a check block.

    Returns a list because multi_check or command checks may yield
    multiple targets.
    """
    targets: list[tuple[str, str]] = []
    method = check.get("method", "")

    if method in ("config_value", "sshd_effective_config"):
        key = check.get("key", "")
        if key:
            # Include the path for config_value to distinguish different files
            if method == "config_value":
                path = check.get("path", "")
                targets.append(("config_key", f"{path}:{key}"))
            else:
                targets.append(("sshd_config_key", key))

    elif method == "service_state":
        name = check.get("name", "")
        if name:
            targets.append(("service", name))

    elif method == "sysctl_value":
        key = check.get("key", "")
        if key:
            targets.append(("sysctl_key", key))

    elif method == "file_permission":
        path = check.get("path", "")
        if path:
            targets.append(("file_permission", path))

    elif method == "kernel_module_state":
        name = check.get("name", "")
        if name:
            targets.append(("kernel_module", name))

    elif method == "package_state":
        name = check.get("name", "")
        if name:
            targets.append(("package", name))

    elif method == "multi_check":
        for sub_check in check.get("checks", []):
            if isinstance(sub_check, dict):
                targets.extend(_extract_check_targets(sub_check))

    elif method == "command":
        # Best-effort extraction from run: field
        run_cmd = check.get("run", "")
        if isinstance(run_cmd, str):
            targets.extend(_extract_command_targets(run_cmd))

    return targets


def _extract_command_targets(cmd: str) -> list[tuple[str, str]]:
    """Best-effort extraction of check targets from a command string."""
    targets: list[tuple[str, str]] = []

    # Look for sysctl key patterns
    sysctl_match = re.search(r"sysctl\s+(?:-[a-zA-Z]\s+)*([a-z][a-z0-9_.]+)", cmd)
    if sysctl_match:
        targets.append(("sysctl_key", sysctl_match.group(1)))

    # Look for systemctl status/is-enabled/is-active <service>
    systemctl_match = re.search(
        r"systemctl\s+(?:status|is-enabled|is-active)\s+(\S+)", cmd
    )
    if systemctl_match:
        svc = systemctl_match.group(1).strip("'\"")
        targets.append(("service", svc))

    # Look for rpm -q / dnf list / yum list <package>
    pkg_match = re.search(
        r"(?:rpm\s+-q|dnf\s+list|yum\s+list)\s+(\S+)", cmd
    )
    if pkg_match:
        pkg = pkg_match.group(1).strip("'\"")
        if not pkg.startswith("-"):
            targets.append(("package", pkg))

    return targets


def _check_same_target(
    rules: dict[str, tuple[dict, Path]],
) -> list[dict]:
    """Find rules that check the same system resource."""
    # Build depends_on graph (bidirectional)
    depends_on_pairs: set[frozenset[str]] = set()
    for rule_id, (data, _) in rules.items():
        deps = data.get("depends_on", [])
        if isinstance(deps, list):
            for dep in deps:
                depends_on_pairs.add(frozenset([rule_id, str(dep)]))

    # Map (target_type, target_key) -> [(rule_id, path)]
    target_map: dict[tuple[str, str], list[tuple[str, Path]]] = defaultdict(list)

    for rule_id, (data, path) in rules.items():
        implementations = data.get("implementations", [])
        if not isinstance(implementations, list):
            continue
        for impl in implementations:
            if not isinstance(impl, dict):
                continue
            check = impl.get("check", {})
            if not isinstance(check, dict):
                continue
            for target in _extract_check_targets(check):
                target_map[target].append((rule_id, path))

    warnings: list[dict] = []
    for (target_type, target_key), entries in sorted(target_map.items()):
        if len(entries) < 2:
            continue

        # Deduplicate — same rule_id might appear from multiple implementations
        seen_ids: set[str] = set()
        unique_entries: list[tuple[str, Path]] = []
        for rid, p in entries:
            if rid not in seen_ids:
                seen_ids.add(rid)
                unique_entries.append((rid, p))

        if len(unique_entries) < 2:
            continue

        # Filter out depends_on pairs
        rule_ids = [rid for rid, _ in unique_entries]
        # Only flag if at least one pair is NOT related by depends_on
        all_related = True
        for i in range(len(rule_ids)):
            for j in range(i + 1, len(rule_ids)):
                if frozenset([rule_ids[i], rule_ids[j]]) not in depends_on_pairs:
                    all_related = False
                    break
            if not all_related:
                break

        if all_related:
            continue

        warnings.append({
            "type": "same_check_target",
            "target_type": target_type,
            "target_key": target_key,
            "rules": [
                {"id": rid, "file": str(p.relative_to(ROOT))}
                for rid, p in unique_entries
            ],
        })

    return warnings


# ---------------------------------------------------------------------------
# Check 2: One-sided CIS references
# ---------------------------------------------------------------------------

def _check_one_sided_cis(
    rules: dict[str, tuple[dict, Path]],
) -> list[dict]:
    """Find rules with CIS refs for one RHEL version but not the other."""
    warnings: list[dict] = []

    for rule_id, (data, path) in sorted(rules.items()):
        refs = data.get("references", {})
        if not isinstance(refs, dict):
            continue

        cis = refs.get("cis", {})
        if not isinstance(cis, dict):
            continue

        has_rhel8 = "rhel8" in cis
        has_rhel9 = "rhel9" in cis

        if has_rhel8 == has_rhel9:
            # Either both or neither — no issue
            continue

        # Check for max_version exception
        platforms = data.get("platforms", [])
        has_max_version = False
        if isinstance(platforms, list):
            for plat in platforms:
                if isinstance(plat, dict) and "max_version" in plat:
                    has_max_version = True
                    break

        if has_max_version:
            continue

        if has_rhel8 and not has_rhel9:
            rhel8_ref = cis["rhel8"]
            section = rhel8_ref.get("section", "?") if isinstance(rhel8_ref, dict) else "?"
            warnings.append({
                "type": "one_sided_cis",
                "rule_id": rule_id,
                "file": str(path.relative_to(ROOT)),
                "has": "rhel8",
                "missing": "rhel9",
                "section": str(section),
            })
        elif has_rhel9 and not has_rhel8:
            rhel9_ref = cis["rhel9"]
            section = rhel9_ref.get("section", "?") if isinstance(rhel9_ref, dict) else "?"
            warnings.append({
                "type": "one_sided_cis",
                "rule_id": rule_id,
                "file": str(path.relative_to(ROOT)),
                "has": "rhel9",
                "missing": "rhel8",
                "section": str(section),
            })

    return warnings


# ---------------------------------------------------------------------------
# Check 3: Orphaned rules
# ---------------------------------------------------------------------------

def _collect_mapping_rule_ids() -> set[str]:
    """Collect all rule IDs referenced in mapping files."""
    rule_ids: set[str] = set()
    for mapping_path in _discover_mappings():
        data = _load_yaml(mapping_path)
        if not data:
            continue
        controls = data.get("controls", {})
        if not isinstance(controls, dict):
            continue
        for _ctrl_id, ctrl_data in controls.items():
            if not isinstance(ctrl_data, dict):
                continue
            rules_list = ctrl_data.get("rules", [])
            if isinstance(rules_list, list):
                for r in rules_list:
                    rule_ids.add(str(r))
    return rule_ids


def _collect_depends_on_targets(
    rules: dict[str, tuple[dict, Path]],
) -> set[str]:
    """Collect all rule IDs that appear as depends_on targets."""
    targets: set[str] = set()
    for _rule_id, (data, _path) in rules.items():
        deps = data.get("depends_on", [])
        if isinstance(deps, list):
            for dep in deps:
                targets.add(str(dep))
    return targets


def _check_orphaned_rules(
    rules: dict[str, tuple[dict, Path]],
) -> list[dict]:
    """Find rules not referenced by any mapping file or depends_on."""
    mapping_ids = _collect_mapping_rule_ids()
    dep_targets = _collect_depends_on_targets(rules)
    referenced = mapping_ids | dep_targets

    warnings: list[dict] = []
    for rule_id, (_data, path) in sorted(rules.items()):
        if rule_id not in referenced:
            warnings.append({
                "type": "orphaned_rule",
                "rule_id": rule_id,
                "file": str(path.relative_to(ROOT)),
            })
    return warnings


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

_TARGET_LABELS = {
    "config_key": "config file+key",
    "sshd_config_key": "sshd config key",
    "service": "service",
    "sysctl_key": "sysctl key",
    "file_permission": "file permissions path",
    "kernel_module": "kernel module",
    "package": "package",
}


def _print_text(
    errors: list[dict],
    warnings: list[dict],
    summary: dict,
) -> None:
    """Print a text-based deep analysis report."""
    print("RULE DUPLICATION DEEP ANALYSIS")
    print("=" * 32)
    print()

    # Errors
    dup_id_errors = [e for e in errors if e["type"] == "duplicate_id"]
    fw_errors = [e for e in errors if e["type"] == "same_framework_control"]

    if errors:
        print("ERRORS:")
        print()
        if dup_id_errors:
            print("  Duplicate rule IDs:")
            for e in dup_id_errors:
                files = ", ".join(e["files"])
                print(f"    \u2717 {e['rule_id']}: {files}")
            print()

        if fw_errors:
            print("  Same framework control mapped to multiple rules:")
            for e in fw_errors:
                rule_list = ", ".join(r["id"] for r in e["rules"])
                print(
                    f"    \u2717 {e['framework'].upper()} {e['version']} "
                    f"{e['control']}: {rule_list}"
                )
            print()
    else:
        print("ERRORS: (none)")
        print()

    # Warnings
    same_target = [w for w in warnings if w["type"] == "same_check_target"]
    one_sided = [w for w in warnings if w["type"] == "one_sided_cis"]
    orphaned = [w for w in warnings if w["type"] == "orphaned_rule"]

    if warnings:
        print("WARNINGS:")
        print()

        if same_target:
            print("  Same check target (potential semantic duplicates):")
            for w in same_target:
                label = _TARGET_LABELS.get(w["target_type"], w["target_type"])
                print(f"    \u26a0 {label} '{w['target_key']}':")
                for r in w["rules"]:
                    print(f"      - {r['id']} ({r['file']})")
            print()

        if one_sided:
            print("  One-sided CIS references (missing cross-version ref):")
            for w in one_sided:
                print(
                    f"    \u26a0 {w['rule_id']}: has CIS {w['has']} "
                    f"({w['section']}) but no {w['missing']}"
                )
            print()

        if orphaned:
            print("  Orphaned rules (not in any mapping):")
            for w in orphaned:
                print(f"    \u26a0 {w['rule_id']} ({w['file']})")
            print()
    else:
        print("WARNINGS: (none)")
        print()

    # Summary
    error_count = len(errors)
    warning_count = len(warnings)
    print(f"Summary: {error_count} errors, {warning_count} warnings")
    print(f"  - Duplicate IDs: {len(dup_id_errors)}")
    print(f"  - Same framework control: {len(fw_errors)}")
    print(f"  - Same check target: {len(same_target)}")
    print(f"  - One-sided CIS refs: {len(one_sided)}")
    print(f"  - Orphaned rules: {len(orphaned)}")


def _print_json(
    errors: list[dict],
    warnings: list[dict],
    summary: dict,
) -> None:
    """Print a JSON-formatted report."""
    output = {
        "errors": errors,
        "warnings": warnings,
        "summary": summary,
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_all_rules() -> dict[str, tuple[dict, Path]]:
    """Load all rule YAML files, keyed by rule ID.

    Returns {rule_id: (data_dict, file_path)}.
    """
    rules: dict[str, tuple[dict, Path]] = {}
    for rule_path in _discover_rules():
        data = _load_yaml(rule_path)
        if data and "id" in data:
            rules[data["id"]] = (data, rule_path)
    return rules


def main() -> int:
    """Run deep rule duplication analysis and print report."""
    use_json = "--json" in sys.argv

    rules = _load_all_rules()

    # Errors (fail CI)
    dup_id_errors = _check_duplicate_ids(rules)
    fw_errors = _check_same_framework_control(rules)
    all_errors = dup_id_errors + fw_errors

    # Warnings (informational)
    same_target_warnings = _check_same_target(rules)
    one_sided_warnings = _check_one_sided_cis(rules)
    orphaned_warnings = _check_orphaned_rules(rules)
    all_warnings = same_target_warnings + one_sided_warnings + orphaned_warnings

    summary = {
        "total_rules": len(rules),
        "error_count": len(all_errors),
        "warning_count": len(all_warnings),
        "duplicate_ids": len(dup_id_errors),
        "same_framework_control": len(fw_errors),
        "same_check_target": len(same_target_warnings),
        "one_sided_cis_refs": len(one_sided_warnings),
        "orphaned_rules": len(orphaned_warnings),
    }

    if use_json:
        _print_json(all_errors, all_warnings, summary)
    else:
        _print_text(all_errors, all_warnings, summary)

    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main())
