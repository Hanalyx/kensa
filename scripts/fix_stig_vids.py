#!/usr/bin/env python3
"""Fix wrong STIG V-IDs in rule YAML files.

Cross-references rule files against authoritative STIG mapping files
to find and correct mismatched vuln_id references.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"
MAPPINGS_DIR = PROJECT_ROOT / "mappings"


def build_mapping_rule_to_vids(mapping_path: Path) -> dict[str, list[str]]:
    """Build rule -> [V-IDs] map from a STIG mapping file."""
    data = yaml.safe_load(mapping_path.read_text())
    controls = data.get("controls", {})
    result: dict[str, list[str]] = {}
    for vid, entry in controls.items():
        if isinstance(entry, dict) and "rules" in entry:
            for rule in entry["rules"]:
                result.setdefault(rule, []).append(str(vid))
    return result


def build_mapping_vid_to_rule(mapping_path: Path) -> dict[str, str]:
    """Build V-ID -> rule map from a STIG mapping file."""
    data = yaml.safe_load(mapping_path.read_text())
    controls = data.get("controls", {})
    result: dict[str, str] = {}
    for vid, entry in controls.items():
        if isinstance(entry, dict) and "rules" in entry:
            for rule in entry["rules"]:
                result[str(vid)] = rule
    return result


def find_rule_file(rule_id: str) -> Path | None:
    """Find a rule YAML file by ID."""
    for path in RULES_DIR.rglob(f"{rule_id}.yml"):
        return path
    return None


def _clean_empty_sections(text: str) -> str:
    """Remove empty YAML mapping keys left after block removal."""
    lines = text.split("\n")
    result: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        # Check if this is a key-only line (e.g., "  stig:", "  cis:", "references:")
        if stripped.endswith(":") and stripped.strip() in ("stig:", "cis:", "references:"):
            indent = len(line) - len(line.lstrip())
            # Check if next non-blank line is a child (deeper indented)
            has_children = False
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    child_indent = len(lines[j]) - len(lines[j].lstrip())
                    has_children = child_indent > indent
                    break
            if not has_children:
                i += 1
                continue
        result.append(lines[i])
        i += 1
    return "\n".join(result)


def fix_stig_vid(
    rule_path: Path, os_ver: str, old_vid: str, new_vid: str | None
) -> bool:
    """Fix a STIG V-ID in a rule file. If new_vid is None, remove the entry."""
    text = rule_path.read_text()

    if new_vid:
        # Replace V-ID
        new_text = text.replace(old_vid, new_vid)
        if new_text != text:
            rule_path.write_text(new_text)
            return True
    else:
        # Remove the entire OS version block from stig references.
        # Find the os_ver key line under stig:, then remove it and all
        # child lines (lines indented deeper than the os_ver key).
        lines = text.split("\n")
        vid_unquoted = old_vid
        new_lines: list[str] = []
        i = 0
        removed = False
        while i < len(lines):
            line = lines[i]
            stripped = line.lstrip()
            # Match "    rhel8:" or "    rhel9:" (block or inline)
            if stripped.startswith(f"{os_ver}:") and not removed:
                indent = len(line) - len(stripped)
                # Check if this block contains the target V-ID
                # Inline format: rhel8: { vuln_id: V-XXXXX, ... }
                if "{" in line and vid_unquoted in line:
                    removed = True
                    i += 1
                    continue
                # Block format: collect child lines
                block_lines = [line]
                j = i + 1
                while j < len(lines):
                    child = lines[j]
                    if child.strip() == "":
                        j += 1
                        continue
                    child_indent = len(child) - len(child.lstrip())
                    if child_indent > indent:
                        block_lines.append(child)
                        j += 1
                    else:
                        break
                block_text = "\n".join(block_lines)
                if vid_unquoted in block_text:
                    removed = True
                    i = j
                    continue
            new_lines.append(line)
            i += 1

        if removed:
            new_text = "\n".join(new_lines)
            new_text = _clean_empty_sections(new_text)
            rule_path.write_text(new_text)
            return True

    return False


def main() -> None:
    dry_run = "--dry-run" in sys.argv

    # Load mappings
    rhel9_rule_to_vids = build_mapping_rule_to_vids(
        MAPPINGS_DIR / "stig" / "rhel9.yaml"
    )
    rhel8_rule_to_vids = build_mapping_rule_to_vids(
        MAPPINGS_DIR / "stig" / "rhel8.yaml"
    )
    rhel9_vid_to_rule = build_mapping_vid_to_rule(
        MAPPINGS_DIR / "stig" / "rhel9.yaml"
    )
    rhel8_vid_to_rule = build_mapping_vid_to_rule(
        MAPPINGS_DIR / "stig" / "rhel8.yaml"
    )

    # Scan all rules for STIG references
    fixes: list[tuple[str, str, str, str, str | None]] = []
    # (rule_id, os_ver, old_vid, reason, new_vid_or_none)

    for path in sorted(RULES_DIR.rglob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text())
        except Exception:
            continue
        if not isinstance(data, dict) or "id" not in data:
            continue

        rule_id = data["id"]
        refs = data.get("references", {}) or {}
        stig = refs.get("stig", {}) or {}

        for os_ver, entry in stig.items():
            if not isinstance(entry, dict) or "vuln_id" not in entry:
                continue
            vid = str(entry["vuln_id"])

            # Determine mapping and lookup tables
            if os_ver == "rhel9":
                rule_to_vids = rhel9_rule_to_vids
                vid_to_rule = rhel9_vid_to_rule
            elif os_ver == "rhel8":
                rule_to_vids = rhel8_rule_to_vids
                vid_to_rule = rhel8_vid_to_rule
            else:
                continue

            # Check if this V-ID belongs to a different rule in the mapping
            mapped_rule = vid_to_rule.get(vid)
            if mapped_rule and mapped_rule != rule_id:
                # Wrong V-ID — belongs to another rule
                correct_vids = rule_to_vids.get(rule_id, [])
                if correct_vids:
                    new_vid = correct_vids[0]
                    fixes.append(
                        (
                            rule_id,
                            os_ver,
                            vid,
                            f"belongs to {mapped_rule}, replace with {new_vid}",
                            new_vid,
                        )
                    )
                else:
                    fixes.append(
                        (
                            rule_id,
                            os_ver,
                            vid,
                            f"belongs to {mapped_rule}, rule not in {os_ver} mapping",
                            None,
                        )
                    )

    # Also check CIS wrong sections
    cis_fixes: list[tuple[str, str, str, str]] = []
    # Check ssh-ciphers-fips and ssh-macs-fips CIS RHEL 8 sections
    for rule_id, wrong_section in [
        ("ssh-ciphers-fips", "5.1.7"),
        ("ssh-macs-fips", "5.1.9"),
    ]:
        path = find_rule_file(rule_id)
        if path:
            data = yaml.safe_load(path.read_text())
            cis = (data.get("references", {}) or {}).get("cis", {}) or {}
            if "rhel8" in cis:
                rhel8_cis = cis["rhel8"]
                if isinstance(rhel8_cis, dict) and str(rhel8_cis.get("section")) == wrong_section:
                    cis_fixes.append(
                        (rule_id, "rhel8", wrong_section, "wrong CIS section (belongs to different SSH rule)")
                    )

    # Report
    print(f"STIG V-ID corrections: {len(fixes)}")
    print(f"CIS section corrections: {len(cis_fixes)}")
    print()

    replaced = 0
    removed = 0
    cis_removed = 0

    for rule_id, os_ver, old_vid, reason, new_vid in sorted(fixes):
        action = f"REPLACE {old_vid} → {new_vid}" if new_vid else f"REMOVE {old_vid}"
        print(f"  {rule_id} ({os_ver}): {action}")
        print(f"    Reason: {reason}")

        if not dry_run:
            path = find_rule_file(rule_id)
            if path and fix_stig_vid(path, os_ver, old_vid, new_vid):
                if new_vid:
                    replaced += 1
                else:
                    removed += 1
            else:
                print(f"    ! FAILED to apply fix")

    print()
    for rule_id, os_ver, section, reason in sorted(cis_fixes):
        print(f"  {rule_id} ({os_ver}): REMOVE CIS section {section}")
        print(f"    Reason: {reason}")

        if not dry_run:
            path = find_rule_file(rule_id)
            if path:
                text = path.read_text()
                # Remove the rhel8 CIS block
                patterns = [
                    re.compile(
                        rf"^\s+{os_ver}:\s*\{{[^}}]*\}}\s*\n",
                        re.MULTILINE,
                    ),
                    re.compile(
                        rf"^\s+{os_ver}:\s*\n"
                        rf"(?:\s+\w+:.*\n)*",
                        re.MULTILINE,
                    ),
                ]
                for pattern in patterns:
                    new_text = pattern.sub("", text)
                    if new_text != text:
                        new_text = _clean_empty_sections(new_text)
                        path.write_text(new_text)
                        cis_removed += 1
                        break

    print()
    if dry_run:
        print("DRY RUN — no changes made")
    else:
        print(f"Applied: {replaced} replaced, {removed} removed, {cis_removed} CIS removed")


if __name__ == "__main__":
    main()
