"""Rule discovery helpers for the unified info command.

Provides rule indexing, query classification, and reference-based search
to support ``kensa info`` lookups by rule ID, CIS section, STIG ID, or
NIST control.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml


def build_rule_index(rules_path: str | Path) -> dict[str, dict]:
    """Load all rules and return a dict keyed by rule ID.

    Args:
        rules_path: Path to the rules directory.

    Returns:
        Dict mapping rule_id to the full rule dict.

    """
    rules_path = Path(rules_path)
    if not rules_path.exists():
        return {}

    index: dict[str, dict] = {}
    for p in sorted(rules_path.rglob("*.yml")):
        try:
            data = yaml.safe_load(p.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "id" not in data:
            continue
        index[data["id"]] = data

    for p in sorted(rules_path.rglob("*.yaml")):
        try:
            data = yaml.safe_load(p.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "id" not in data:
            continue
        if data["id"] not in index:
            index[data["id"]] = data

    return index


def classify_query(
    query: str, known_rule_ids: set[str] | None = None
) -> tuple[str, str]:
    """Auto-detect the type of a positional query.

    Returns:
        Tuple of (query_type, normalized_value) where query_type is one of:
        "rule", "stig", "nist", "cis".

    """
    if known_rule_ids and query in known_rule_ids:
        return ("rule", query)

    upper = query.upper()

    if upper.startswith("V-"):
        return ("stig", upper)

    if re.match(r"^[A-Z]{2}-\d+", upper):
        return ("nist", upper)

    if re.match(r"^\d+(\.\d+)*$", query):
        return ("cis", query)

    return ("rule", query)


def search_rules_by_reference(
    rules_by_id: dict[str, dict],
    search_type: str,
    value: str,
    rhel_version: str | None = None,
) -> list[dict]:
    """Search rules by framework reference (CIS, STIG, NIST).

    Args:
        rules_by_id: Dict mapping rule_id to rule dict.
        search_type: One of "cis", "stig", "nist".
        value: The search value (e.g., "5.2.2", "V-258036", "AC-3").
        rhel_version: Optional RHEL version filter ("8", "9", "10").

    Returns:
        List of match dicts with rule_id, title, severity, refs.

    """
    matches = []

    for rule in rules_by_id.values():
        refs = rule.get("references", {})
        rule_id = rule["id"]
        title = rule.get("title", "")
        severity = rule.get("severity", "")

        matched_refs: list[dict] = []

        if search_type == "cis":
            cis_refs = refs.get("cis", {})
            for ref_key, ref_data in cis_refs.items():
                ref_section = ref_data.get("section", "")
                if ref_section == value or ref_section.startswith(value + "."):
                    if rhel_version and f"rhel{rhel_version}" not in ref_key:
                        continue
                    matched_refs.append(
                        {
                            "framework": ref_key,
                            "section": ref_section,
                            "level": ref_data.get("level", ""),
                            "type": ref_data.get("type", ""),
                        }
                    )

        elif search_type == "stig":
            stig_refs = refs.get("stig", {})
            for ref_key, ref_data in stig_refs.items():
                vuln_id = ref_data.get("vuln_id", "")
                stig_rule_id = ref_data.get("stig_id", "")
                if vuln_id.upper() == value or stig_rule_id.upper() == value:
                    if rhel_version and f"rhel{rhel_version}" not in ref_key:
                        continue
                    matched_refs.append(
                        {
                            "framework": ref_key,
                            "vuln_id": vuln_id,
                            "stig_id": stig_rule_id,
                            "severity": ref_data.get("severity", ""),
                        }
                    )

        elif search_type == "nist":
            nist_refs = refs.get("nist_800_53", [])
            if isinstance(nist_refs, list):
                for ctrl in nist_refs:
                    if ctrl.upper() == value or ctrl.upper().startswith(value):
                        matched_refs.append({"control": ctrl})

        if matched_refs:
            matches.append(
                {
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "refs": matched_refs,
                }
            )

    return matches
