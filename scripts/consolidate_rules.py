#!/usr/bin/env python3
"""Rule consolidation script.

Discovers duplicate rule pairs (via conflicts_with / supersedes fields),
scores them to pick a keeper, generates a manifest, and can execute the
consolidation (merge references, update mappings, delete losers).

Usage:
    # Discover pairs and print manifest
    python3 scripts/consolidate_rules.py --discover
    python3 scripts/consolidate_rules.py --discover --json
    python3 scripts/consolidate_rules.py --discover -o consolidate_manifest.yaml

    # Preview changes
    python3 scripts/consolidate_rules.py --dry-run consolidate_manifest.yaml

    # Execute consolidation
    python3 scripts/consolidate_rules.py --execute consolidate_manifest.yaml
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"
MAPPINGS_DIR = PROJECT_ROOT / "mappings"


# ── Rule loading (reuses pattern from rule_dedup_check.py) ──────────────────


def load_rules() -> dict[str, dict]:
    """Load all rule YAML files from rules/. Returns {rule_id: data}."""
    rules: dict[str, dict] = {}
    for path in sorted(RULES_DIR.rglob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(data, dict) or "id" not in data:
            continue
        data["_path"] = str(path.relative_to(PROJECT_ROOT))
        data["_abspath"] = str(path)
        rules[data["id"]] = data
    return rules


def _get_list_field(rule: dict, field: str) -> list[str]:
    """Return a list field from a rule (normalises str to list)."""
    val = rule.get(field)
    if isinstance(val, list):
        return [str(v) for v in val]
    if isinstance(val, str):
        return [val]
    return []


# ── Pair discovery ──────────────────────────────────────────────────────────


def discover_pairs(rules: dict[str, dict]) -> list[set[str]]:
    """Discover true duplicate pairs from conflicts_with and supersedes edges.

    Only forms pairs between rules that are genuine duplicates — they share
    the same check target (same sysctl key, same service, same file path) or
    the same framework control (same CIS section or STIG vuln_id).

    Rules that merely have a mutual exclusion relationship (e.g., all GDM
    config rules vs gdm-removed, or granular SSH crypto rules vs
    ssh-crypto-policy) are NOT grouped together.
    """
    # Build edges only between true duplicate pairs
    edges: set[tuple[str, str]] = set()

    for rid, rule in rules.items():
        neighbours = set(
            _get_list_field(rule, "conflicts_with")
            + _get_list_field(rule, "supersedes")
        )
        neighbours = {n for n in neighbours if n in rules}
        for n in neighbours:
            pair = tuple(sorted([rid, n]))
            if pair not in edges and _is_true_duplicate_pair(rid, n, rules):
                edges.add(pair)  # type: ignore[arg-type]

    # Build adjacency from validated edges
    adj: dict[str, set[str]] = {}
    for a, b in edges:
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)

    # BFS to find connected components
    visited: set[str] = set()
    components: list[set[str]] = []
    for node in adj:
        if node in visited:
            continue
        component: set[str] = set()
        queue = [node]
        while queue:
            current = queue.pop()
            if current in visited:
                continue
            visited.add(current)
            component.add(current)
            for neighbour in adj.get(current, set()):
                if neighbour not in visited:
                    queue.append(neighbour)
        if len(component) >= 2:
            components.append(component)

    return components


def _is_true_duplicate_pair(a_id: str, b_id: str, rules: dict[str, dict]) -> bool:
    """Determine if two rules are true duplicates (same control) vs just mutually exclusive.

    True duplicates share at least one of:
    - Same CIS section number (for any RHEL version)
    - Same STIG vuln_id (for any RHEL version)
    - Same primary check target (sysctl key, service name, file path, etc.)
    - One supersedes the other (explicit replacement)

    Mutual exclusion only (NOT duplicates):
    - All GDM config rules vs gdm-removed (different controls, just can't coexist)
    - ssh-ciphers-fips vs ssh-crypto-policy (different granularity)
    """
    a = rules[a_id]
    b = rules[b_id]

    # supersedes is always a true duplicate signal
    if b_id in _get_list_field(a, "supersedes") or a_id in _get_list_field(b, "supersedes"):
        return True

    # Bidirectional conflicts_with is a strong duplicate signal
    # (A conflicts_with B AND B conflicts_with A = they replace each other)
    a_conflicts = set(_get_list_field(a, "conflicts_with"))
    b_conflicts = set(_get_list_field(b, "conflicts_with"))
    if b_id in a_conflicts and a_id in b_conflicts:
        return True

    # Same CIS section (any version)?
    a_cis = _extract_cis_sections(a)
    b_cis = _extract_cis_sections(b)
    if a_cis & b_cis:
        return True

    # Same STIG vuln_id (any version)?
    a_stig = _extract_stig_vulns(a)
    b_stig = _extract_stig_vulns(b)
    if a_stig & b_stig:
        return True

    # Same primary check target?
    a_targets = _extract_check_targets(a)
    b_targets = _extract_check_targets(b)
    if a_targets & b_targets:
        return True

    return False


def _extract_cis_sections(rule: dict) -> set[str]:
    """Extract all CIS section numbers from a rule."""
    sections: set[str] = set()
    cis = (rule.get("references") or {}).get("cis") or {}
    for _os_ver, entry in cis.items():
        if isinstance(entry, dict) and "section" in entry:
            sections.add(str(entry["section"]))
    return sections


def _extract_stig_vulns(rule: dict) -> set[str]:
    """Extract all STIG vuln_ids from a rule."""
    vulns: set[str] = set()
    stig = (rule.get("references") or {}).get("stig") or {}
    for _os_ver, entry in stig.items():
        if isinstance(entry, dict) and "vuln_id" in entry:
            vulns.add(str(entry["vuln_id"]))
    return vulns


def _extract_check_targets(rule: dict) -> set[str]:
    """Extract primary check targets (service name, sysctl key, file path, etc.)."""
    targets: set[str] = set()
    for impl in rule.get("implementations", []):
        chk = impl.get("check")
        if not chk:
            continue
        # Direct check
        _extract_targets_from_check(chk, targets)
        # multi_check
        for sub in chk.get("checks", []):
            _extract_targets_from_check(sub, targets)
    return targets


def _extract_targets_from_check(chk: dict, targets: set[str]) -> None:
    """Extract target identifiers from a single check block."""
    method = chk.get("method", "")
    if method == "sysctl_value":
        key = chk.get("key")
        if key:
            targets.add(f"sysctl:{key}")
    elif method == "service_state":
        svc = chk.get("service")
        if svc:
            targets.add(f"service:{svc}")
    elif method == "file_permission":
        path = chk.get("path")
        if path:
            targets.add(f"file:{path}")
    elif method in ("config_value", "sshd_effective_config"):
        key = chk.get("key")
        if key:
            targets.add(f"config:{key}")
    elif method == "kernel_module_state":
        mod = chk.get("module")
        if mod:
            targets.add(f"kmod:{mod}")
    elif method == "package_state":
        pkg = chk.get("package")
        if pkg:
            targets.add(f"pkg:{pkg}")
    elif method == "audit_rule_exists":
        # Use the syscall or key as target
        key = chk.get("key") or chk.get("syscall")
        if key:
            targets.add(f"audit:{key}")


# ── Scoring ─────────────────────────────────────────────────────────────────


def _extract_remediation_mechanisms(rule: dict) -> list[str]:
    """Extract all remediation mechanisms from a rule's implementations."""
    mechanisms: list[str] = []
    for impl in rule.get("implementations", []):
        rem = impl.get("remediation")
        if not rem:
            continue
        # Single-step remediation
        if "mechanism" in rem:
            mechanisms.append(rem["mechanism"])
        # Multi-step remediation
        for step in rem.get("steps", []):
            if "mechanism" in step:
                mechanisms.append(step["mechanism"])
    return mechanisms


def _extract_check_methods(rule: dict) -> list[str]:
    """Extract all check methods from a rule's implementations."""
    methods: list[str] = []
    for impl in rule.get("implementations", []):
        chk = impl.get("check")
        if not chk:
            continue
        if "method" in chk:
            methods.append(chk["method"])
        # multi_check
        for sub in chk.get("checks", []):
            if "method" in sub:
                methods.append(sub["method"])
    return methods


def count_mapping_references(rule_id: str, _cache: dict[str, dict[str, int]] | None = None) -> int:
    """Count how many mapping files reference this rule ID."""
    if _cache is not None and rule_id in _cache:
        return _cache[rule_id]
    # Build cache on first call
    if _cache is not None and "__loaded__" in _cache:
        return _cache.get(rule_id, 0)
    return _count_mapping_refs_uncached(rule_id)


def _build_mapping_ref_cache() -> dict[str, int]:
    """Scan all mapping files and count references per rule ID."""
    counts: dict[str, int] = {}
    for path in sorted(MAPPINGS_DIR.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        # Quick regex to find all rule references in `- rule-id` lines
        for m in re.finditer(r"^\s+-\s+(\S+)\s*$", text, re.MULTILINE):
            rid = m.group(1)
            counts[rid] = counts.get(rid, 0) + 1
    return counts


def _count_mapping_refs_uncached(rule_id: str) -> int:
    """Count mapping references without cache (fallback)."""
    count = 0
    for path in MAPPINGS_DIR.rglob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        if re.search(rf"^\s+-\s+{re.escape(rule_id)}\s*$", text, re.MULTILINE):
            count += 1
    return count


def score_rule(rule: dict, mapping_counts: dict[str, int]) -> int:
    """Compute a quality score for a rule. Higher = better keeper candidate."""
    score = 0
    rid = rule["id"]

    # 1. Remediation quality
    for mech in _extract_remediation_mechanisms(rule):
        if mech not in ("manual", "command_exec"):
            score += 3
        elif mech == "command_exec":
            score += 1

    # 2. Check quality
    for method in _extract_check_methods(rule):
        if method != "command":
            score += 2

    # 3. Framework reference count
    refs = rule.get("references", {}) or {}
    cis_count = len(refs.get("cis", {}) or {})
    stig_count = len(refs.get("stig", {}) or {})
    nist_count = len(refs.get("nist_800_53", []) or [])
    pci_count = len(refs.get("pci_dss", []) or [])
    fedramp_count = len(refs.get("fedramp", []) or [])
    score += cis_count + stig_count + (nist_count // 2) + pci_count + fedramp_count

    # 4. Mapping file references
    score += mapping_counts.get(rid, 0)

    # 5. Name quality (tiebreaker)
    if len(rid) <= 25:
        score += 1
    if not rid.startswith("fs-permissions-"):
        score += 1

    return score


# ── Manifest generation ─────────────────────────────────────────────────────


def generate_manifest(rules: dict[str, dict]) -> dict:
    """Discover pairs, score them, return a manifest dict."""
    components = discover_pairs(rules)
    mapping_counts = _build_mapping_ref_cache()

    pairs: list[dict] = []
    for component in sorted(components, key=lambda c: min(c)):
        scored = []
        for rid in component:
            rule = rules[rid]
            s = score_rule(rule, mapping_counts)
            scored.append((s, rid, rule))

        # Sort descending by score, then alphabetically for ties
        scored.sort(key=lambda t: (-t[0], t[1]))
        keeper_score, keeper_id, keeper_rule = scored[0]
        losers = scored[1:]

        if len(losers) == 1:
            loser_score, loser_id, loser_rule = losers[0]
            entry: dict = {
                "keep": keeper_id,
                "keep_file": keeper_rule["_path"],
                "keep_score": keeper_score,
                "delete": loser_id,
                "delete_file": loser_rule["_path"],
                "delete_score": loser_score,
                "reason": _generate_reason(keeper_rule, loser_rule, keeper_score, loser_score),
                "actions": _determine_actions(keeper_rule, loser_rule),
            }
        else:
            delete_ids = [lid for _, lid, _ in losers]
            entry = {
                "keep": keeper_id,
                "keep_file": keeper_rule["_path"],
                "keep_score": keeper_score,
                "delete": delete_ids,
                "delete_file": [r["_path"] for _, _, r in losers],
                "delete_score": [s for s, _, _ in losers],
                "reason": f"Consolidated rule covers {len(losers)} separate rules",
                "actions": ["merge_references", "clean_metadata", "update_mappings", "delete_rule"],
            }

        pairs.append(entry)

    return {
        "generated": str(date.today()),
        "pairs": pairs,
    }


def _generate_reason(keeper: dict, loser: dict, k_score: int, l_score: int) -> str:
    """Generate a human-readable reason for the keep decision."""
    parts: list[str] = []

    k_mechs = _extract_remediation_mechanisms(keeper)
    l_mechs = _extract_remediation_mechanisms(loser)
    k_typed = [m for m in k_mechs if m not in ("manual", "command_exec")]
    l_typed = [m for m in l_mechs if m not in ("manual", "command_exec")]

    if len(k_typed) > len(l_typed):
        parts.append(f"typed remediation ({', '.join(k_typed[:2])})")
    elif len(k_typed) == len(l_typed) and k_typed:
        parts.append("equal remediation quality")

    k_refs = keeper.get("references", {}) or {}
    l_refs = loser.get("references", {}) or {}
    k_fw = len(k_refs.get("cis", {})) + len(k_refs.get("stig", {}))
    l_fw = len(l_refs.get("cis", {})) + len(l_refs.get("stig", {}))
    if k_fw > l_fw:
        parts.append("more framework refs")

    if not parts:
        parts.append(f"higher score ({k_score} vs {l_score})")

    return "; ".join(parts)


def _determine_actions(keeper: dict, loser: dict) -> list[str]:
    """Determine which actions are needed for this pair."""
    actions = ["merge_references"]

    # Check if loser has better remediation
    k_mechs = _extract_remediation_mechanisms(keeper)
    l_mechs = _extract_remediation_mechanisms(loser)
    k_typed = sum(1 for m in k_mechs if m not in ("manual", "command_exec"))
    l_typed = sum(1 for m in l_mechs if m not in ("manual", "command_exec"))
    if l_typed > k_typed:
        actions.append("upgrade_remediation")

    actions.extend(["clean_metadata", "update_mappings", "delete_rule"])
    return actions


# ── Manifest output ─────────────────────────────────────────────────────────


def format_manifest_yaml(manifest: dict) -> str:
    """Format manifest as YAML with a header comment."""
    lines = [
        "# Auto-generated by: python3 scripts/consolidate_rules.py --discover",
        "# Review and adjust before executing with --execute",
        "",
    ]
    lines.append(yaml.dump(manifest, default_flow_style=False, sort_keys=False))
    return "\n".join(lines)


def format_manifest_text(manifest: dict) -> str:
    """Format manifest as human-readable summary."""
    pairs = manifest["pairs"]
    lines = [
        f"RULE CONSOLIDATION MANIFEST ({manifest['generated']})",
        "=" * 60,
        f"Total pairs: {len(pairs)}",
        "",
    ]

    for i, pair in enumerate(pairs, 1):
        keep = pair["keep"]
        delete = pair["delete"]
        if isinstance(delete, list):
            delete_str = ", ".join(delete)
            lines.append(f"  [{i:2d}] {keep} <- [{delete_str}]")
        else:
            lines.append(
                f"  [{i:2d}] {keep} (score {pair['keep_score']}) "
                f"<- {delete} (score {pair.get('delete_score', '?')})"
            )
        lines.append(f"       Reason: {pair['reason']}")
        lines.append(f"       Actions: {', '.join(pair['actions'])}")
        lines.append("")

    return "\n".join(lines)


# ── Dry-run ─────────────────────────────────────────────────────────────────


def dry_run(manifest: dict) -> None:
    """Show what changes would be made without modifying files."""
    pairs = manifest["pairs"]
    rules = load_rules()

    print(f"DRY RUN — {len(pairs)} pairs")
    print("=" * 60)
    print()

    total_mappings = 0
    total_refs_merged = 0

    for i, pair in enumerate(pairs, 1):
        keep_id = pair["keep"]
        delete_ids = pair["delete"] if isinstance(pair["delete"], list) else [pair["delete"]]
        delete_files = pair.get("delete_file", [])
        if isinstance(delete_files, str):
            delete_files = [delete_files]

        print(f"[{i}/{len(pairs)}] {keep_id} <- {', '.join(delete_ids)}")

        keep_rule = rules.get(keep_id)
        if not keep_rule:
            print(f"  ! Keeper rule {keep_id} not found (already consolidated?)")
            print()
            continue

        for did in delete_ids:
            delete_rule = rules.get(did)
            if not delete_rule:
                print(f"  ! Delete rule {did} not found (already removed?)")
                continue

            # Show what references would be merged
            refs_added = _preview_merge_references(keep_rule, delete_rule)
            if refs_added:
                for ref in refs_added:
                    print(f"  + Would merge reference: {ref}")
                total_refs_merged += len(refs_added)

        # Show mapping files affected
        for did in delete_ids:
            affected = _find_mapping_files_with_rule(did)
            if affected:
                for mf in affected:
                    print(f"  ~ Would update mapping: {mf}")
                total_mappings += len(affected)

        # Show actions
        actions = pair.get("actions", [])
        if "upgrade_remediation" in actions:
            print("  ! Would UPGRADE remediation from delete rule (review recommended)")

        for did, df in zip(delete_ids, delete_files):
            path = PROJECT_ROOT / df if df else None
            if path and path.exists():
                print(f"  - Would delete: {df}")
            else:
                print(f"  - Already deleted: {df}")

        print()

    print(f"Summary: {len(pairs)} pairs, ~{total_refs_merged} refs to merge, ~{total_mappings} mapping updates")


def _preview_merge_references(keep: dict, delete: dict) -> list[str]:
    """Preview which references would be added during merge."""
    added: list[str] = []
    k_refs = keep.get("references", {}) or {}
    d_refs = delete.get("references", {}) or {}

    # CIS
    k_cis = k_refs.get("cis", {}) or {}
    d_cis = d_refs.get("cis", {}) or {}
    for os_ver in d_cis:
        if os_ver not in k_cis:
            section = d_cis[os_ver].get("section", "?") if isinstance(d_cis[os_ver], dict) else "?"
            added.append(f"CIS {os_ver} section {section}")

    # STIG
    k_stig = k_refs.get("stig", {}) or {}
    d_stig = d_refs.get("stig", {}) or {}
    for os_ver in d_stig:
        if os_ver not in k_stig:
            vid = d_stig[os_ver].get("vuln_id", "?") if isinstance(d_stig[os_ver], dict) else "?"
            added.append(f"STIG {os_ver} {vid}")

    # NIST
    k_nist = set(k_refs.get("nist_800_53", []) or [])
    d_nist = set(d_refs.get("nist_800_53", []) or [])
    new_nist = d_nist - k_nist
    if new_nist:
        added.append(f"NIST 800-53: {', '.join(sorted(new_nist))}")

    # PCI-DSS
    k_pci = set(k_refs.get("pci_dss", []) or [])
    d_pci = set(d_refs.get("pci_dss", []) or [])
    new_pci = d_pci - k_pci
    if new_pci:
        added.append(f"PCI-DSS: {', '.join(sorted(new_pci))}")

    # FedRAMP
    k_fed = set(k_refs.get("fedramp", []) or [])
    d_fed = set(d_refs.get("fedramp", []) or [])
    new_fed = d_fed - k_fed
    if new_fed:
        added.append(f"FedRAMP: {', '.join(sorted(new_fed))}")

    return added


def _find_mapping_files_with_rule(rule_id: str) -> list[str]:
    """Find mapping files that reference a given rule ID."""
    matches: list[str] = []
    pattern = re.compile(rf"^\s+-\s+{re.escape(rule_id)}\s*$", re.MULTILINE)
    for path in sorted(MAPPINGS_DIR.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if pattern.search(text):
            matches.append(str(path.relative_to(PROJECT_ROOT)))
    return matches


# ── Execution ───────────────────────────────────────────────────────────────


def execute(manifest: dict) -> None:
    """Execute the consolidation described in the manifest."""
    pairs = manifest["pairs"]

    total_deleted = 0
    total_mapping_updates = 0

    for i, pair in enumerate(pairs, 1):
        keep_id = pair["keep"]
        delete_ids = pair["delete"] if isinstance(pair["delete"], list) else [pair["delete"]]
        delete_files = pair.get("delete_file", [])
        if isinstance(delete_files, str):
            delete_files = [delete_files]
        actions = set(pair.get("actions", []))

        keep_path = PROJECT_ROOT / pair["keep_file"]
        if not keep_path.exists():
            print(f"[{i}/{len(pairs)}] SKIP {keep_id} — keeper file not found")
            continue

        keep_rule = yaml.safe_load(keep_path.read_text(encoding="utf-8"))
        if not isinstance(keep_rule, dict):
            print(f"[{i}/{len(pairs)}] SKIP {keep_id} — keeper file invalid")
            continue

        header = f"[{i}/{len(pairs)}] {keep_id} <- {', '.join(delete_ids)}"
        print(header)

        refs_merged = 0
        remediation_upgraded = False

        for did in delete_ids:
            # Find delete file path
            dfile = None
            for df in delete_files:
                if did in df:
                    dfile = df
                    break
            if dfile is None:
                # Try to find it in the rules directory
                candidates = list(RULES_DIR.rglob(f"{did}.yml"))
                if candidates:
                    dfile = str(candidates[0].relative_to(PROJECT_ROOT))

            if dfile is None:
                print(f"  ! Cannot find file for {did}, skipping")
                continue

            delete_path = PROJECT_ROOT / dfile
            if not delete_path.exists():
                print(f"  - Already deleted: {dfile}")
                continue

            delete_rule = yaml.safe_load(delete_path.read_text(encoding="utf-8"))
            if not isinstance(delete_rule, dict):
                continue

            # merge_references
            if "merge_references" in actions:
                n = _merge_references(keep_rule, delete_rule)
                if n > 0:
                    refs_merged += n
                    print(f"  + Merged {n} reference(s) from {did}")

            # upgrade_remediation
            if "upgrade_remediation" in actions:
                if _should_upgrade_remediation(keep_rule, delete_rule):
                    keep_rule["implementations"] = delete_rule["implementations"]
                    remediation_upgraded = True
                    print(f"  ! Upgraded remediation from {did} (REVIEW RECOMMENDED)")

        # clean_metadata
        if "clean_metadata" in actions:
            cleaned = _clean_metadata(keep_rule, set(delete_ids))
            if cleaned:
                print(f"  + Cleaned {', '.join(cleaned)}")

        # Write the updated keeper
        # Remove internal fields before writing
        write_rule = {k: v for k, v in keep_rule.items() if not k.startswith("_")}
        keep_path.write_text(
            yaml.dump(write_rule, default_flow_style=False, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

        # update_mappings
        if "update_mappings" in actions:
            for did in delete_ids:
                n = _update_mappings(did, keep_id)
                if n > 0:
                    total_mapping_updates += n
                    print(f"  + Updated {n} mapping file(s) ({did} -> {keep_id})")

        # delete_rule
        if "delete_rule" in actions:
            for dfile in delete_files:
                delete_path = PROJECT_ROOT / dfile
                if delete_path.exists():
                    delete_path.unlink()
                    total_deleted += 1
                    print(f"  - Deleted {dfile}")

        if remediation_upgraded:
            print("  *** REMEDIATION UPGRADED — manual review recommended ***")

        print()

    # Post-execution summary
    print("=" * 60)
    print("Consolidation complete:")
    print(f"  {len(pairs)} pairs processed")
    print(f"  {total_deleted} rules deleted")
    print(f"  {total_mapping_updates} mapping file references updated")
    print()
    print("Run validation:")
    print("  python3 -m schema.validate rules/")
    print("  python3 scripts/cis_validate.py")
    print("  python3 scripts/rule_dedup_check.py --save-baseline")
    print("  pytest tests/ -x -q")


def _merge_references(keep: dict, delete: dict) -> int:
    """Merge references from delete into keep. Returns count of refs added."""
    k_refs = keep.setdefault("references", {})
    d_refs = delete.get("references", {}) or {}
    added = 0

    # CIS
    d_cis = d_refs.get("cis", {}) or {}
    if d_cis:
        k_cis = k_refs.setdefault("cis", {})
        for os_ver, entry in d_cis.items():
            if os_ver not in k_cis:
                k_cis[os_ver] = entry
                added += 1

    # STIG
    d_stig = d_refs.get("stig", {}) or {}
    if d_stig:
        k_stig = k_refs.setdefault("stig", {})
        for os_ver, entry in d_stig.items():
            if os_ver not in k_stig:
                k_stig[os_ver] = entry
                added += 1

    # NIST 800-53
    d_nist = d_refs.get("nist_800_53", []) or []
    if d_nist:
        k_nist = k_refs.setdefault("nist_800_53", [])
        existing = set(k_nist)
        for ctrl in d_nist:
            if ctrl not in existing:
                k_nist.append(ctrl)
                existing.add(ctrl)
                added += 1

    # PCI-DSS
    d_pci = d_refs.get("pci_dss", []) or []
    if d_pci:
        k_pci = k_refs.setdefault("pci_dss", [])
        existing = set(k_pci)
        for ctrl in d_pci:
            if ctrl not in existing:
                k_pci.append(ctrl)
                existing.add(ctrl)
                added += 1

    # FedRAMP
    d_fed = d_refs.get("fedramp", []) or []
    if d_fed:
        k_fed = k_refs.setdefault("fedramp", [])
        existing = set(k_fed)
        for ctrl in d_fed:
            if ctrl not in existing:
                k_fed.append(ctrl)
                existing.add(ctrl)
                added += 1

    return added


def _should_upgrade_remediation(keep: dict, delete: dict) -> bool:
    """Check if the delete rule has strictly better remediation."""
    k_mechs = _extract_remediation_mechanisms(keep)
    d_mechs = _extract_remediation_mechanisms(delete)
    k_typed = sum(1 for m in k_mechs if m not in ("manual", "command_exec"))
    d_typed = sum(1 for m in d_mechs if m not in ("manual", "command_exec"))
    return d_typed > k_typed


def _clean_metadata(rule: dict, delete_ids: set[str]) -> list[str]:
    """Remove conflicts_with/supersedes entries referencing deleted rules."""
    cleaned: list[str] = []

    for field in ("conflicts_with", "supersedes"):
        val = rule.get(field)
        if val is None:
            continue
        if isinstance(val, str):
            val = [val]
        if isinstance(val, list):
            filtered = [v for v in val if v not in delete_ids]
            if len(filtered) < len(val):
                if filtered:
                    rule[field] = filtered
                else:
                    del rule[field]
                cleaned.append(field)

    return cleaned


def _update_mappings(old_id: str, new_id: str) -> int:
    """Replace old_id with new_id in all mapping files. Returns files updated."""
    pattern = re.compile(
        rf"^(\s+-\s+){re.escape(old_id)}(\s*)$",
        re.MULTILINE,
    )
    updated = 0

    for path in sorted(MAPPINGS_DIR.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if not pattern.search(text):
            continue

        # Replace old ID with new ID
        new_text = pattern.sub(rf"\g<1>{new_id}\2", text)

        # Deduplicate: if a rules list now has the same rule twice, remove one
        new_text = _deduplicate_rules_lists(new_text, new_id)

        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
            updated += 1

    return updated


def _deduplicate_rules_lists(text: str, rule_id: str) -> str:
    """Remove duplicate entries of rule_id in YAML rules: lists.

    Handles the pattern where a rules: list has the same rule ID on
    consecutive or nearby lines after a replacement.
    """
    # Find all occurrences of the rule_id in rules lists
    lines = text.split("\n")
    # Track which lines to remove (duplicates within the same rules: block)
    remove_indices: set[int] = set()

    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == "rules:":
            # Collect all rule entries in this block
            indent_level = len(lines[i]) - len(lines[i].lstrip())
            entry_indent = indent_level + 2  # expected indent for `- rule-id`
            j = i + 1
            seen_ids: dict[str, int] = {}
            while j < len(lines):
                line = lines[j]
                if not line.strip():
                    j += 1
                    continue
                current_indent = len(line) - len(line.lstrip())
                if current_indent < entry_indent and line.strip():
                    break
                m = re.match(r"^(\s+-\s+)(\S+)\s*$", line)
                if m and m.group(2) == rule_id:
                    if rule_id in seen_ids:
                        remove_indices.add(j)
                    else:
                        seen_ids[rule_id] = j
                elif m:
                    seen_ids[m.group(2)] = j
                j += 1
            i = j
        else:
            i += 1

    if not remove_indices:
        return text

    result_lines = [line for idx, line in enumerate(lines) if idx not in remove_indices]
    return "\n".join(result_lines)


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Rule consolidation: discover duplicates, score, and merge.",
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--discover",
        action="store_true",
        help="Discover duplicate pairs and generate a manifest",
    )
    mode.add_argument(
        "--dry-run",
        metavar="MANIFEST",
        type=Path,
        help="Preview changes from a manifest without modifying files",
    )
    mode.add_argument(
        "--execute",
        metavar="MANIFEST",
        type=Path,
        help="Execute consolidation from a manifest",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output in JSON format (with --discover)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="Write manifest to file (with --discover)",
    )

    args = parser.parse_args()

    if args.discover:
        rules = load_rules()
        if not rules:
            print("No rule files found in rules/", file=sys.stderr)
            sys.exit(1)

        manifest = generate_manifest(rules)

        if args.json_output:
            output = json.dumps(manifest, indent=2)
        elif args.output:
            output = format_manifest_yaml(manifest)
        else:
            output = format_manifest_text(manifest)

        if args.output:
            yaml_output = format_manifest_yaml(manifest)
            args.output.write_text(yaml_output, encoding="utf-8")
            print(f"Manifest written to {args.output} ({len(manifest['pairs'])} pairs)")
            # Also print summary to stdout
            print()
            print(format_manifest_text(manifest))
        else:
            print(output)

    elif args.dry_run:
        if not args.dry_run.exists():
            print(f"Manifest file not found: {args.dry_run}", file=sys.stderr)
            sys.exit(1)
        manifest = yaml.safe_load(args.dry_run.read_text(encoding="utf-8"))
        dry_run(manifest)

    elif args.execute:
        if not args.execute.exists():
            print(f"Manifest file not found: {args.execute}", file=sys.stderr)
            sys.exit(1)
        manifest = yaml.safe_load(args.execute.read_text(encoding="utf-8"))
        execute(manifest)


if __name__ == "__main__":
    main()
