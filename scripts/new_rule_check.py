#!/usr/bin/env python3
"""Rule authoring helper — check for existing coverage before creating a new rule.

Searches existing rules and framework mappings for overlap with a proposed
new rule.  Helps prevent duplicates at authoring time.

Usage:
    python3 scripts/new_rule_check.py --cis rhel9:7.1.11
    python3 scripts/new_rule_check.py --stig rhel9:V-257895
    python3 scripts/new_rule_check.py --target sysctl:net.ipv4.conf.all.send_redirects
    python3 scripts/new_rule_check.py --target service:avahi-daemon
    python3 scripts/new_rule_check.py --target file:/etc/passwd
    python3 scripts/new_rule_check.py --target config:/etc/ssh/sshd_config:PermitRootLogin
    python3 scripts/new_rule_check.py --target package:aide
    python3 scripts/new_rule_check.py --name disable-samba
    python3 scripts/new_rule_check.py --cis rhel9:2.1.6 --target service:smb --name disable-smb
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

# Project root (assumes script is in scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"
MAPPINGS_DIR = PROJECT_ROOT / "mappings"

# Synonym groups for fuzzy name matching
SYNONYMS: list[set[str]] = [
    {"disable", "disabled"},
    {"enable", "enabled"},
    {"remove", "removed", "absent"},
    {"install", "installed", "present"},
    {"service", "svc"},
    {"package", "pkg"},
]


# ── YAML loading helpers ────────────────────────────────────────────────────


def load_yaml(path: Path) -> Any:
    """Load a YAML file, returning None on parse errors."""
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def load_all_rules() -> list[tuple[Path, dict[str, Any]]]:
    """Load all rule YAML files under rules/."""
    rules: list[tuple[Path, dict[str, Any]]] = []
    for yml in sorted(RULES_DIR.rglob("*.yml")):
        data = load_yaml(yml)
        if isinstance(data, dict) and "id" in data:
            rules.append((yml, data))
    return rules


def load_all_mappings(framework: str) -> list[tuple[Path, dict[str, Any]]]:
    """Load all mapping YAML files for the given framework."""
    fw_dir = MAPPINGS_DIR / framework
    if not fw_dir.is_dir():
        return []
    mappings: list[tuple[Path, dict[str, Any]]] = []
    for yml in sorted(fw_dir.rglob("*.yaml")):
        data = load_yaml(yml)
        if isinstance(data, dict):
            mappings.append((yml, data))
    return mappings


# ── Check implementations ───────────────────────────────────────────────────


class Finding:
    """A single coverage hit."""

    def __init__(self, category: str, detail: str, rule_id: str, path: Path, *, note: str = ""):
        self.category = category
        self.detail = detail
        self.rule_id = rule_id
        self.path = path
        self.note = note

    def __str__(self) -> str:
        rel = self.path.relative_to(PROJECT_ROOT)
        line = f"    \u2192 Already covered by '{self.rule_id}' ({rel})"
        if self.note:
            line += f"\n      (note: {self.note})"
        return line


def _relpath(p: Path) -> str:
    return str(p.relative_to(PROJECT_ROOT))


# ── CIS check ───────────────────────────────────────────────────────────────


def check_cis(
    osver: str,
    section: str,
    rules: list[tuple[Path, dict[str, Any]]],
) -> list[Finding]:
    """Search rules and CIS mappings for an existing CIS section reference."""
    findings: list[Finding] = []
    label = f"CIS {osver} section {section}"

    # Search rule references
    for path, rule in rules:
        refs = rule.get("references", {})
        cis = refs.get("cis", {})
        osver_ref = cis.get(osver, {})
        if isinstance(osver_ref, dict) and str(osver_ref.get("section", "")) == section:
            findings.append(Finding(label, label, rule["id"], path))

    # Search CIS mapping files
    for mpath, mdata in load_all_mappings("cis"):
        controls = mdata.get("controls", {})
        if not isinstance(controls, dict):
            continue
        # Match mapping file to osver by checking the id/platform
        mid = str(mdata.get("id", ""))
        mplatform = mdata.get("platform", {})
        mfamily = str(mplatform.get("family", ""))
        mver = str(mplatform.get("min_version", ""))
        # Derive osver label from mapping (e.g. "rhel9")
        mapping_osver = f"{mfamily}{mver}" if mfamily and mver else mid
        if osver not in (mapping_osver, mid):
            # Also try partial match: "rhel9" in "cis-rhel9"
            if osver not in mid and mapping_osver != osver:
                continue

        if section in controls:
            entry = controls[section]
            if isinstance(entry, dict):
                rule_list = entry.get("rules", [])
                for rid in rule_list:
                    # Avoid duplicating findings already found in rule files
                    if not any(f.rule_id == rid for f in findings):
                        findings.append(
                            Finding(label, label, rid, mpath, note="from mapping file")
                        )

    return findings


# ── STIG check ───────────────────────────────────────────────────────────────


def check_stig(
    osver: str,
    vuln_id: str,
    rules: list[tuple[Path, dict[str, Any]]],
) -> list[Finding]:
    """Search rules and STIG mappings for an existing STIG vuln_id reference."""
    findings: list[Finding] = []
    label = f"STIG {osver} {vuln_id}"

    # Search rule references
    for path, rule in rules:
        refs = rule.get("references", {})
        stig = refs.get("stig", {})
        osver_ref = stig.get(osver, {})
        if isinstance(osver_ref, dict) and str(osver_ref.get("vuln_id", "")) == vuln_id:
            findings.append(Finding(label, label, rule["id"], path))

    # Search STIG mapping files
    for mpath, mdata in load_all_mappings("stig"):
        controls = mdata.get("controls", {})
        if not isinstance(controls, dict):
            continue
        # Match mapping file to osver
        mplatform = mdata.get("platform", {})
        mfamily = str(mplatform.get("family", ""))
        mver = str(mplatform.get("min_version", ""))
        mapping_osver = f"{mfamily}{mver}" if mfamily and mver else ""
        mid = str(mdata.get("id", ""))
        if osver not in (mapping_osver, mid) and osver not in mid:
            continue

        # STIG controls use V-IDs as keys (may be string or int-coerced)
        for cid, entry in controls.items():
            if str(cid) == vuln_id:
                if isinstance(entry, dict):
                    rule_list = entry.get("rules", [])
                    for rid in rule_list:
                        if not any(f.rule_id == rid for f in findings):
                            findings.append(
                                Finding(label, label, rid, mpath, note="from mapping file")
                            )

    return findings


# ── Target check ─────────────────────────────────────────────────────────────


def _iter_checks(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract all check blocks from a rule (including multi_check children)."""
    checks: list[dict[str, Any]] = []
    for impl in rule.get("implementations", []):
        check = impl.get("check", {})
        if not isinstance(check, dict):
            continue
        method = check.get("method", "")
        if method == "multi_check" or "checks" in check:
            # Multi-check: iterate sub-checks
            for sub in check.get("checks", []):
                if isinstance(sub, dict):
                    checks.append(sub)
        else:
            checks.append(check)
    return checks


def check_target_sysctl(
    key: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Find rules with sysctl_value checks matching the given key."""
    findings: list[Finding] = []
    label = f"sysctl:{key}"
    for path, rule in rules:
        for check in _iter_checks(rule):
            if check.get("method") == "sysctl_value" and check.get("key") == key:
                findings.append(Finding(label, label, rule["id"], path))
                break
    return findings


def check_target_service(
    name: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Find rules with service_state checks matching the given service name."""
    findings: list[Finding] = []
    label = f"service:{name}"
    for path, rule in rules:
        for check in _iter_checks(rule):
            if check.get("method") == "service_state" and check.get("name") == name:
                findings.append(Finding(label, label, rule["id"], path))
                break
    return findings


def check_target_file(
    filepath: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Find rules with file_permission/file_exists/file_content checks on a path."""
    findings: list[Finding] = []
    label = f"file:{filepath}"
    file_methods = {"file_permission", "file_exists", "file_content"}
    for path, rule in rules:
        for check in _iter_checks(rule):
            if check.get("method") in file_methods and check.get("path") == filepath:
                findings.append(Finding(label, label, rule["id"], path))
                break
    return findings


def check_target_config(
    filepath: str, key: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Find rules with config_value or sshd_effective_config checks on path+key."""
    findings: list[Finding] = []
    label = f"config:{filepath}:{key}"
    config_methods = {"config_value", "sshd_effective_config"}
    for path, rule in rules:
        for check in _iter_checks(rule):
            method = check.get("method", "")
            if method in config_methods:
                if check.get("path") == filepath and check.get("key") == key:
                    findings.append(Finding(label, label, rule["id"], path))
                    break
                # sshd_effective_config may not have path, just key
                if method == "sshd_effective_config" and check.get("key") == key:
                    if filepath in ("/etc/ssh/sshd_config", "sshd_config"):
                        findings.append(Finding(label, label, rule["id"], path))
                        break
    return findings


def check_target_package(
    name: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Find rules with package_state checks matching the given package name."""
    findings: list[Finding] = []
    label = f"package:{name}"
    for path, rule in rules:
        for check in _iter_checks(rule):
            if check.get("method") == "package_state" and check.get("name") == name:
                findings.append(Finding(label, label, rule["id"], path))
                break
    return findings


def check_target_kernel_module(
    name: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Find rules with kernel_module_state checks for the given module."""
    findings: list[Finding] = []
    label = f"kernel_module:{name}"
    for path, rule in rules:
        for check in _iter_checks(rule):
            if check.get("method") == "kernel_module_state" and check.get("name") == name:
                findings.append(Finding(label, label, rule["id"], path))
                break
    return findings


def check_target_command_grep(
    value: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Best-effort search in command-type checks for the given value in the run field."""
    findings: list[Finding] = []
    label = f"command containing '{value}'"
    for path, rule in rules:
        for check in _iter_checks(rule):
            if check.get("method") == "command":
                run_field = str(check.get("run", ""))
                if value in run_field:
                    findings.append(Finding(label, label, rule["id"], path))
                    break
    return findings


def check_target(
    target_str: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Dispatch target check based on TYPE:VALUE format."""
    parts = target_str.split(":", 1)
    if len(parts) < 2:
        print(f"Error: --target must be TYPE:VALUE, got '{target_str}'", file=sys.stderr)
        sys.exit(2)

    target_type = parts[0].lower()
    target_value = parts[1]
    findings: list[Finding] = []

    if target_type == "sysctl":
        findings.extend(check_target_sysctl(target_value, rules))
    elif target_type == "service":
        findings.extend(check_target_service(target_value, rules))
    elif target_type == "file":
        findings.extend(check_target_file(target_value, rules))
    elif target_type == "config":
        # config:PATH:KEY — split further
        config_parts = target_value.split(":", 1)
        if len(config_parts) < 2:
            print(
                f"Error: config target must be config:PATH:KEY, got '{target_str}'",
                file=sys.stderr,
            )
            sys.exit(2)
        findings.extend(check_target_config(config_parts[0], config_parts[1], rules))
    elif target_type == "package":
        findings.extend(check_target_package(target_value, rules))
    elif target_type in ("kernel_module", "kmod"):
        findings.extend(check_target_kernel_module(target_value, rules))
    else:
        print(
            f"Error: unknown target type '{target_type}'. "
            "Supported: sysctl, service, file, config, package, kernel_module",
            file=sys.stderr,
        )
        sys.exit(2)

    # Also do best-effort command grep for the core value
    core_value = target_value.split(":")[-1]  # innermost value
    cmd_findings = check_target_command_grep(core_value, rules)
    # Avoid duplicates with typed findings
    existing_ids = {f.rule_id for f in findings}
    for cf in cmd_findings:
        if cf.rule_id not in existing_ids:
            cf.category = f"Check target '{target_str}'"
            cf.note = "matched in command check run field"
            findings.append(cf)

    # Fix category for typed findings
    for f in findings:
        if not f.note:
            f.category = f"Check target '{target_str}'"

    return findings


# ── Name fuzzy match ─────────────────────────────────────────────────────────


def _expand_synonyms(token: str) -> set[str]:
    """Return a set of synonyms for a token (including the token itself)."""
    result = {token}
    for group in SYNONYMS:
        if token in group:
            result.update(group)
    return result


def _token_match(query_tokens: list[str], rule_id: str) -> bool:
    """Check if all query tokens (or their synonyms) appear in the rule ID."""
    for token in query_tokens:
        expanded = _expand_synonyms(token)
        if not any(syn in rule_id for syn in expanded):
            return False
    return True


def check_name(
    partial_name: str, rules: list[tuple[Path, dict[str, Any]]]
) -> list[Finding]:
    """Fuzzy-match a proposed rule name against existing rule IDs."""
    findings: list[Finding] = []
    label = f"Similar rule names matching '{partial_name}'"
    query_lower = partial_name.lower()
    query_tokens = query_lower.split("-")
    # Identify "content" tokens (not generic action words)
    action_words = {"disable", "disabled", "enable", "enabled", "remove", "removed",
                    "absent", "install", "installed", "present", "ensure", "set",
                    "check", "verify", "configure", "service", "package", "config"}
    content_tokens = [t for t in query_tokens if t not in action_words and len(t) >= 3]

    for path, rule in rules:
        rule_id = rule["id"].lower()
        matched = False

        # Direct substring match (query in rule or rule in query)
        if query_lower in rule_id or rule_id in query_lower:
            matched = True

        # Token match: ALL tokens from the query appear in the rule ID
        if not matched and len(query_tokens) >= 2 and _token_match(query_tokens, rule_id):
            matched = True

        # Content token match: all content (non-action) tokens appear in rule ID
        # This catches "disable-samba" matching "service-disable-samba" via "samba"
        if not matched and content_tokens:
            if all(token in rule_id for token in content_tokens):
                matched = True
            # Also try synonym expansion on content tokens
            if not matched:
                expanded_match = True
                for token in content_tokens:
                    expanded = _expand_synonyms(token)
                    if not any(syn in rule_id for syn in expanded):
                        expanded_match = False
                        break
                if expanded_match:
                    matched = True

        if matched:
            note = ""
            # Check for conflicts_with or supersedes references
            conflicts = rule.get("conflicts_with", [])
            supersedes = rule.get("supersedes", [])
            notes_parts = []
            if conflicts:
                notes_parts.append(f"conflicts_with {', '.join(conflicts)}")
            if supersedes:
                notes_parts.append(f"supersedes {', '.join(supersedes)}")
            if notes_parts:
                note = "; ".join(notes_parts)
            findings.append(Finding(label, label, rule["id"], path, note=note))

    return findings


# ── Output formatting ────────────────────────────────────────────────────────


def format_output(all_findings: list[Finding]) -> str:
    """Format findings into a human-readable report."""
    if not all_findings:
        return "\u2713 No existing coverage found for the specified checks. Safe to create a new rule."

    lines: list[str] = []
    lines.append(
        "\u26a0 EXISTING COVERAGE FOUND \u2014 "
        "consider adding references to existing rules instead of creating a new one."
    )
    lines.append("")

    # Group findings by category
    categories: dict[str, list[Finding]] = {}
    for f in all_findings:
        categories.setdefault(f.category, []).append(f)

    for category, findings in categories.items():
        lines.append(f"  {category}:")
        # Deduplicate by rule_id within a category
        seen: set[str] = set()
        for f in findings:
            if f.rule_id not in seen:
                seen.add(f.rule_id)
                lines.append(str(f))
        lines.append("")

    # Generate recommendation based on most-referenced rule
    rule_counts: dict[str, int] = {}
    for f in all_findings:
        rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1
    if rule_counts:
        top_rule = max(rule_counts, key=lambda r: rule_counts[r])
        lines.append(
            f"Recommendation: Add your framework reference to '{top_rule}' "
            "rather than creating a new rule."
        )

    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Check for existing rule coverage before creating a new rule.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s --cis rhel9:7.1.11
  %(prog)s --stig rhel9:V-257895
  %(prog)s --target sysctl:net.ipv4.conf.all.send_redirects
  %(prog)s --target service:avahi-daemon
  %(prog)s --target file:/etc/passwd
  %(prog)s --target config:/etc/ssh/sshd_config:PermitRootLogin
  %(prog)s --target package:aide
  %(prog)s --name disable-samba
  %(prog)s --cis rhel9:2.1.6 --target service:smb --name disable-smb
""",
    )
    parser.add_argument(
        "--cis",
        metavar="OSVER:SECTION",
        help="Check CIS section coverage (e.g. rhel9:7.1.11)",
    )
    parser.add_argument(
        "--stig",
        metavar="OSVER:VULNID",
        help="Check STIG vuln_id coverage (e.g. rhel9:V-257895)",
    )
    parser.add_argument(
        "--target",
        metavar="TYPE:VALUE",
        action="append",
        help="Check target coverage (e.g. sysctl:KEY, service:NAME, file:PATH, "
        "config:PATH:KEY, package:NAME, kernel_module:NAME). Can be repeated.",
    )
    parser.add_argument(
        "--name",
        metavar="PARTIAL_NAME",
        help="Fuzzy-match against existing rule IDs (e.g. disable-samba)",
    )
    args = parser.parse_args()

    if not any([args.cis, args.stig, args.target, args.name]):
        parser.error("At least one of --cis, --stig, --target, or --name is required.")

    return args


def main() -> None:
    """Entry point."""
    args = parse_args()
    rules = load_all_rules()
    all_findings: list[Finding] = []

    # --cis OSVER:SECTION
    if args.cis:
        parts = args.cis.split(":", 1)
        if len(parts) != 2:
            print("Error: --cis must be OSVER:SECTION (e.g. rhel9:7.1.11)", file=sys.stderr)
            sys.exit(2)
        all_findings.extend(check_cis(parts[0], parts[1], rules))

    # --stig OSVER:VULNID
    if args.stig:
        parts = args.stig.split(":", 1)
        if len(parts) != 2:
            print("Error: --stig must be OSVER:VULNID (e.g. rhel9:V-257895)", file=sys.stderr)
            sys.exit(2)
        all_findings.extend(check_stig(parts[0], parts[1], rules))

    # --target TYPE:VALUE (may be repeated)
    if args.target:
        for target_str in args.target:
            all_findings.extend(check_target(target_str, rules))

    # --name PARTIAL_NAME
    if args.name:
        all_findings.extend(check_name(args.name, rules))

    print(format_output(all_findings))
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
