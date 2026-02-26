"""Spec coverage report for Kensa handler registries.

Walks all handler registries (checks, remediation, capture, rollback) and
compares against spec files in the specs/ directory.  Reports which handlers
have a corresponding spec and which do not.

Usage:
    python3 scripts/spec_coverage.py          # Markdown table output
    python3 scripts/spec_coverage.py --json   # JSON output
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Project root is one level above scripts/
ROOT = Path(__file__).resolve().parent.parent
SPECS_DIR = ROOT / "specs"


# ---------------------------------------------------------------------------
# Registry loading
# ---------------------------------------------------------------------------

def _load_check_handlers() -> dict[str, object]:
    """Import and return the CHECK_HANDLERS registry."""
    sys.path.insert(0, str(ROOT))
    from runner.handlers.checks import CHECK_HANDLERS

    return dict(CHECK_HANDLERS)


def _load_remediation_handlers() -> dict[str, object]:
    """Import and return the REMEDIATION_HANDLERS registry."""
    sys.path.insert(0, str(ROOT))
    from runner.handlers.remediation import REMEDIATION_HANDLERS

    return dict(REMEDIATION_HANDLERS)


def _load_capture_handlers() -> dict[str, object]:
    """Import and return the CAPTURE_HANDLERS registry."""
    sys.path.insert(0, str(ROOT))
    try:
        from runner.handlers.capture import CAPTURE_HANDLERS

        return dict(CAPTURE_HANDLERS)
    except (ImportError, ModuleNotFoundError):
        return {}


def _load_rollback_handlers() -> dict[str, object]:
    """Import and return the ROLLBACK_HANDLERS registry."""
    sys.path.insert(0, str(ROOT))
    try:
        from runner.handlers.rollback import ROLLBACK_HANDLERS

        return dict(ROLLBACK_HANDLERS)
    except (ImportError, ModuleNotFoundError):
        return {}


# ---------------------------------------------------------------------------
# Spec file discovery
# ---------------------------------------------------------------------------

def _find_specs(subdir: str) -> dict[str, Path]:
    """Return a mapping of handler-name -> spec path for a specs subdirectory."""
    d = SPECS_DIR / subdir
    if not d.is_dir():
        return {}
    specs: dict[str, Path] = {}
    for p in sorted(d.glob("*.spec.yaml")):
        name = p.stem.replace(".spec", "")
        specs[name] = p
    return specs


def _find_all_specs() -> dict[str, dict[str, Path]]:
    """Return spec files organized by category."""
    return {
        "handlers/checks": _find_specs("handlers/checks"),
        "handlers/remediation": _find_specs("handlers/remediation"),
        "handlers/capture": _find_specs("handlers/capture"),
        "handlers/rollback": _find_specs("handlers/rollback"),
        "cli": _find_specs("cli"),
        "orchestration": _find_specs("orchestration"),
        "internal": _find_specs("internal"),
        "data": _find_specs("data"),
    }


# ---------------------------------------------------------------------------
# Coverage analysis
# ---------------------------------------------------------------------------

def _analyze_registry(
    registry_name: str,
    handlers: dict[str, object],
    specs: dict[str, Path],
) -> list[dict]:
    """Compare a handler registry against available specs.

    Returns a list of row dicts: {handler, has_spec, spec_path, registry}.
    """
    rows: list[dict] = []
    for name in sorted(handlers):
        spec_path = specs.get(name)
        rows.append(
            {
                "registry": registry_name,
                "handler": name,
                "has_spec": spec_path is not None,
                "spec_path": str(spec_path.relative_to(ROOT)) if spec_path else "",
            }
        )
    return rows


def _collect_extra_specs(
    all_specs: dict[str, dict[str, Path]],
) -> list[dict]:
    """Collect specs not tied to a handler registry (cli, orchestration, etc.)."""
    rows: list[dict] = []
    for category in ("cli", "orchestration", "internal", "data"):
        for name, path in sorted(all_specs.get(category, {}).items()):
            rows.append(
                {
                    "registry": category,
                    "handler": name,
                    "has_spec": True,
                    "spec_path": str(path.relative_to(ROOT)),
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _print_markdown(
    rows: list[dict],
    extra_rows: list[dict],
    summary: dict,
) -> None:
    """Print a markdown-formatted coverage report."""
    print("# Spec Coverage Report\n")

    # Handler registries
    print("## Handler Registries\n")
    print("| Registry | Handler | Has Spec | Spec Path |")
    print("|----------|---------|----------|-----------|")
    for row in rows:
        has = "yes" if row["has_spec"] else "**no**"
        print(
            f"| {row['registry']} | {row['handler']} | {has} | {row['spec_path']} |"
        )

    # Extra specs
    if extra_rows:
        print("\n## Additional Specs (non-handler)\n")
        print("| Category | Name | Spec Path |")
        print("|----------|------|-----------|")
        for row in extra_rows:
            print(f"| {row['registry']} | {row['handler']} | {row['spec_path']} |")

    # Summary
    print("\n## Summary\n")
    print(f"- **Total handlers:** {summary['total_handlers']}")
    print(f"- **Specced handlers:** {summary['specced_handlers']}")
    print(f"- **Unspecced handlers:** {summary['unspecced_handlers']}")
    print(f"- **Coverage:** {summary['coverage_pct']:.1f}%")
    print(f"- **Additional specs:** {summary['extra_specs']}")

    if summary["unspecced_handlers"] > 0:
        print(
            f"\nWARNING: {summary['unspecced_handlers']} handler(s) lack a spec file."
        )


def _print_json(
    rows: list[dict],
    extra_rows: list[dict],
    summary: dict,
) -> None:
    """Print a JSON-formatted coverage report."""
    output = {
        "handler_coverage": rows,
        "additional_specs": extra_rows,
        "summary": summary,
    }
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """Run spec coverage analysis and print report."""
    use_json = "--json" in sys.argv

    # Load registries
    checks = _load_check_handlers()
    remediation = _load_remediation_handlers()
    capture = _load_capture_handlers()
    rollback = _load_rollback_handlers()

    # Discover specs
    all_specs = _find_all_specs()

    # Analyze each registry
    rows: list[dict] = []
    rows.extend(
        _analyze_registry("checks", checks, all_specs["handlers/checks"])
    )
    rows.extend(
        _analyze_registry(
            "remediation", remediation, all_specs["handlers/remediation"]
        )
    )
    rows.extend(
        _analyze_registry("capture", capture, all_specs["handlers/capture"])
    )
    rows.extend(
        _analyze_registry("rollback", rollback, all_specs["handlers/rollback"])
    )

    # Extra specs (non-handler)
    extra_rows = _collect_extra_specs(all_specs)

    # Summary
    total = len(rows)
    specced = sum(1 for r in rows if r["has_spec"])
    unspecced = total - specced
    pct = (specced / total * 100) if total else 0.0

    summary = {
        "total_handlers": total,
        "specced_handlers": specced,
        "unspecced_handlers": unspecced,
        "coverage_pct": round(pct, 1),
        "extra_specs": len(extra_rows),
    }

    if use_json:
        _print_json(rows, extra_rows, summary)
    else:
        _print_markdown(rows, extra_rows, summary)

    if unspecced > 0:
        print(file=sys.stderr)
        print(
            f"spec_coverage: {unspecced} handler(s) without specs",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
