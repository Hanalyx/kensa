"""Spec-to-test traceability validator for Kensa SDD infrastructure.

Parses each spec's acceptance criteria (AC-1, AC-2, ...) and verifies that
every AC has a corresponding test method with a matching "AC-N:" docstring
reference.  Reports unmapped ACs (no test) and extra test references (test
cites an AC not in the spec).

Usage:
    python3 scripts/spec_traceability.py          # Per-spec text report
    python3 scripts/spec_traceability.py --json   # JSON output

Exit code:
    0 if all ACs are mapped, 1 if any gaps exist.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

import yaml

# Project root is one level above scripts/
ROOT = Path(__file__).resolve().parent.parent
SPECS_DIR = ROOT / "specs"


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------

def _discover_specs() -> list[Path]:
    """Return all *.spec.yaml files under specs/."""
    return sorted(SPECS_DIR.rglob("*.spec.yaml"))


def _parse_acceptance_criteria(spec_path: Path) -> dict[str, str]:
    """Extract acceptance_criteria keys from a spec file.

    Returns a mapping like {"AC-1": "description ...", "AC-2": "..."}.
    """
    with open(spec_path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return {}

    objective = data.get("objective", {})
    if not isinstance(objective, dict):
        return {}

    ac = objective.get("acceptance_criteria", {})
    if not isinstance(ac, dict):
        return {}

    return {str(k): str(v) for k, v in ac.items()}


def _parse_testing_section(spec_path: Path) -> tuple[str | None, list[str]]:
    """Extract testing.spec_derived.file and classes from a spec.

    Returns (test_file_path, [class_names]).
    """
    with open(spec_path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        return None, []

    testing = data.get("testing", {})
    if not isinstance(testing, dict):
        return None, []

    spec_derived = testing.get("spec_derived", {})
    if not isinstance(spec_derived, dict):
        return None, []

    file_path = spec_derived.get("file")
    classes = spec_derived.get("classes", [])
    if not isinstance(classes, list):
        classes = []

    return file_path, [str(c) for c in classes]


# ---------------------------------------------------------------------------
# Test file scanning
# ---------------------------------------------------------------------------

_AC_PATTERN = re.compile(r"\bAC-(\d+)\b")


def _scan_test_file(
    test_file: Path,
    class_names: list[str],
) -> dict[str, set[str]]:
    """Scan a test file for AC references in method docstrings.

    Returns a mapping of class_name -> set of AC keys found (e.g. {"AC-1", "AC-3"}).
    Also returns a special "__all__" key with the union of all found ACs.
    """
    if not test_file.is_file():
        return {}

    try:
        source = test_file.read_text()
        tree = ast.parse(source, filename=str(test_file))
    except (SyntaxError, UnicodeDecodeError):
        return {}

    result: dict[str, set[str]] = {"__all__": set()}
    target_classes = set(class_names) if class_names else None

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        if target_classes and node.name not in target_classes:
            continue

        class_acs: set[str] = set()
        for item in ast.walk(node):
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not item.name.startswith("test_"):
                continue

            docstring = ast.get_docstring(item)
            if not docstring:
                continue

            for match in _AC_PATTERN.finditer(docstring):
                ac_key = f"AC-{match.group(1)}"
                class_acs.add(ac_key)

        result[node.name] = class_acs
        result["__all__"] |= class_acs

    return result


# ---------------------------------------------------------------------------
# Traceability analysis
# ---------------------------------------------------------------------------

def _analyze_spec(spec_path: Path) -> dict | None:
    """Analyze one spec file for AC-to-test traceability.

    Returns a report dict, or None if the spec has no ACs or no testing section.
    """
    acceptance_criteria = _parse_acceptance_criteria(spec_path)
    if not acceptance_criteria:
        return None

    test_file_rel, class_names = _parse_testing_section(spec_path)
    if not test_file_rel:
        # Spec has ACs but no testing section -- all ACs are unmapped
        return {
            "spec": str(spec_path.relative_to(ROOT)),
            "total_acs": len(acceptance_criteria),
            "mapped_acs": [],
            "unmapped_acs": sorted(acceptance_criteria.keys(), key=_ac_sort_key),
            "extra_test_refs": [],
            "test_file": None,
            "classes": [],
            "status": "no_testing_section",
        }

    test_file = ROOT / test_file_rel
    found_acs = _scan_test_file(test_file, class_names)
    all_found = found_acs.get("__all__", set())

    ac_keys = set(acceptance_criteria.keys())
    mapped = sorted(ac_keys & all_found, key=_ac_sort_key)
    unmapped = sorted(ac_keys - all_found, key=_ac_sort_key)
    extra = sorted(all_found - ac_keys, key=_ac_sort_key)

    status = "pass" if not unmapped and not extra else "gaps"
    if not test_file.is_file():
        status = "test_file_missing"

    return {
        "spec": str(spec_path.relative_to(ROOT)),
        "total_acs": len(acceptance_criteria),
        "mapped_acs": mapped,
        "unmapped_acs": unmapped,
        "extra_test_refs": extra,
        "test_file": test_file_rel,
        "classes": class_names,
        "status": status,
    }


def _ac_sort_key(ac: str) -> tuple[str, int]:
    """Sort AC keys numerically (AC-1 before AC-10)."""
    m = re.match(r"AC-(\d+)", ac)
    if m:
        return ("AC", int(m.group(1)))
    return (ac, 0)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _print_text(reports: list[dict], summary: dict) -> None:
    """Print a text-based traceability report."""
    print("# Spec Traceability Report\n")

    for r in reports:
        mapped_count = len(r["mapped_acs"])
        total = r["total_acs"]
        status_icon = "PASS" if r["status"] == "pass" else "GAPS"
        print(f"## {r['spec']}  [{status_icon}]")
        print(f"   ACs: {mapped_count}/{total} mapped")

        if r["test_file"]:
            print(f"   Test file: {r['test_file']}")
            print(f"   Classes: {', '.join(r['classes'])}")
        else:
            print("   Test file: (none)")

        if r["mapped_acs"]:
            print(f"   Mapped: {', '.join(r['mapped_acs'])}")
        if r["unmapped_acs"]:
            print(f"   UNMAPPED: {', '.join(r['unmapped_acs'])}")
        if r["extra_test_refs"]:
            print(f"   EXTRA: {', '.join(r['extra_test_refs'])}")
        print()

    # Summary
    print("---")
    print(f"Total specs analyzed: {summary['total_specs']}")
    print(f"Specs with full coverage: {summary['specs_pass']}")
    print(f"Specs with gaps: {summary['specs_gaps']}")
    print(f"Total ACs: {summary['total_acs']}")
    print(f"Mapped ACs: {summary['mapped_acs']}")
    print(f"Unmapped ACs: {summary['unmapped_acs']}")
    print(f"Extra test refs: {summary['extra_refs']}")

    if summary["unmapped_acs"] > 0 or summary["extra_refs"] > 0:
        print(
            f"\nFAILED: {summary['unmapped_acs']} unmapped AC(s), "
            f"{summary['extra_refs']} extra test ref(s)."
        )
    else:
        print("\nPASSED: All acceptance criteria have corresponding tests.")


def _print_json(reports: list[dict], summary: dict) -> None:
    """Print a JSON-formatted traceability report."""
    output = {
        "reports": reports,
        "summary": summary,
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """Run spec traceability analysis and print report."""
    use_json = "--json" in sys.argv

    specs = _discover_specs()
    reports: list[dict] = []

    for spec_path in specs:
        report = _analyze_spec(spec_path)
        if report is not None:
            reports.append(report)

    # Compute summary
    total_acs = sum(r["total_acs"] for r in reports)
    mapped_acs = sum(len(r["mapped_acs"]) for r in reports)
    unmapped_acs = sum(len(r["unmapped_acs"]) for r in reports)
    extra_refs = sum(len(r["extra_test_refs"]) for r in reports)
    specs_pass = sum(1 for r in reports if r["status"] == "pass")
    specs_gaps = sum(1 for r in reports if r["status"] != "pass")

    summary = {
        "total_specs": len(reports),
        "specs_pass": specs_pass,
        "specs_gaps": specs_gaps,
        "total_acs": total_acs,
        "mapped_acs": mapped_acs,
        "unmapped_acs": unmapped_acs,
        "extra_refs": extra_refs,
    }

    if use_json:
        _print_json(reports, summary)
    else:
        _print_text(reports, summary)

    # Exit 1 if gaps exist, 0 if all ACs are mapped
    if unmapped_acs > 0 or extra_refs > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
