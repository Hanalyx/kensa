#!/usr/bin/env python3
"""Parse FedRAMP OSCAL profile to generate baseline reference YAML.

One-time/maintenance script to regenerate the baseline reference from
the official OSCAL source. Run when FedRAMP publishes a new revision.

Downloads and parses:
1. FedRAMP Moderate Rev 5 OSCAL profile (control selections)
2. NIST SP 800-53 Rev 5 OSCAL catalog (control titles)

Outputs a curated YAML reference file for use by Kensa.

Usage:
    # From local files:
    python scripts/parse_fedramp_oscal.py \
        --profile path/to/FedRAMP_rev5_MODERATE-baseline_profile.json \
        --catalog path/to/NIST_SP-800-53_rev5_catalog.json \
        --output context/fedramp/moderate-rev5-baseline.yaml

    # Download from GitHub:
    python scripts/parse_fedramp_oscal.py --download \
        --output context/fedramp/moderate-rev5-baseline.yaml
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path
from urllib.request import urlopen

import yaml

# ── URLs for official OSCAL sources ──────────────────────────────────────────

FEDRAMP_PROFILE_URL = (
    "https://raw.githubusercontent.com/GSA/fedramp-automation/master/"
    "dist/content/rev5/baselines/json/"
    "FedRAMP_rev5_MODERATE-baseline_profile.json"
)

NIST_CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/"
    "NIST_SP-800-53_rev5_catalog.json"
)

# ── Applicability classification ─────────────────────────────────────────────

# Controls that can be enforced via SSH checks on a RHEL host
TECHNICAL_CONTROLS = {
    "ac-2", "ac-2.1", "ac-2.2", "ac-2.3", "ac-2.4", "ac-2.5",
    "ac-3", "ac-4", "ac-6", "ac-6.1", "ac-6.2", "ac-6.5", "ac-6.9", "ac-6.10",
    "ac-7", "ac-8", "ac-11", "ac-11.1", "ac-12",
    "ac-17", "ac-17.1", "ac-17.2", "ac-17.4",
    "ac-18", "ac-18.1", "ac-18.3",
    "au-2", "au-3", "au-3.1", "au-4", "au-5", "au-8", "au-9", "au-9.4", "au-12",
    "cm-5", "cm-5.1", "cm-6", "cm-6.1", "cm-7", "cm-7.2",
    "ia-2", "ia-2.1", "ia-2.2", "ia-2.5", "ia-2.8", "ia-2.12",
    "ia-3", "ia-4.4", "ia-5", "ia-5.1", "ia-5.2", "ia-6", "ia-7", "ia-11",
    "sc-2", "sc-4", "sc-5", "sc-7", "sc-7.4", "sc-7.5",
    "sc-8", "sc-8.1", "sc-10", "sc-12", "sc-13", "sc-23",
    "sc-28", "sc-28.1", "sc-39", "sc-45",
    "si-3", "si-4", "si-4.2", "si-4.4", "si-4.5",
    "si-6", "si-7", "si-7.1", "si-7.7", "si-10", "si-11", "si-16",
}

# Controls that are partially automatable
SEMI_TECHNICAL_CONTROLS = {
    "ac-2.7", "ac-2.9", "ac-2.12", "ac-4.21", "ac-5",
    "ac-17.3", "ac-19.5", "ac-20.2",
    "au-6", "au-6.1", "au-6.3", "au-7", "au-7.1", "au-11",
    "ca-7", "ca-9",
    "cm-2", "cm-2.2", "cm-2.3", "cm-2.7", "cm-3", "cm-5.5",
    "cm-7.1", "cm-7.5", "cm-8", "cm-8.1", "cm-8.3", "cm-11", "cm-12", "cm-12.1",
    "ia-2.6", "ia-4",
    "ra-5", "ra-5.2", "ra-5.3", "ra-5.5",
    "sc-7.3", "sc-7.7", "sc-7.8", "sc-7.12", "sc-7.18",
    "sc-15", "sc-17", "sc-20", "sc-21", "sc-22", "sc-45.1",
    "si-2", "si-2.2", "si-2.3", "si-4.1", "si-4.16", "si-4.18", "si-4.23",
    "si-8", "si-8.2",
}


def oscal_id_to_conventional(oscal_id: str) -> str:
    """Convert OSCAL ID (ac-2.1) to conventional format (AC-2(1))."""
    # Remove leading hash if present
    oscal_id = oscal_id.lstrip("#")
    parts = oscal_id.split(".")
    base = parts[0].upper()
    if len(parts) > 1:
        return f"{base}({parts[1]})"
    return base


def conventional_to_oscal(control_id: str) -> str:
    """Convert conventional ID (AC-2(1)) to OSCAL format (ac-2.1)."""
    match = re.match(r"([A-Z]{2}-\d+)(?:\((\d+)\))?", control_id)
    if not match:
        return control_id.lower()
    base = match.group(1).lower()
    enhancement = match.group(2)
    if enhancement:
        return f"{base}.{enhancement}"
    return base


def extract_control_ids_from_profile(profile_data: dict) -> set[str]:
    """Extract included control IDs from OSCAL profile JSON.

    Returns set of OSCAL-format IDs (e.g., 'ac-2', 'ac-2.1').
    """
    control_ids = set()

    imports = profile_data.get("profile", {}).get("imports", [])
    for imp in imports:
        for selection in imp.get("include-controls", []):
            for with_id in selection.get("with-ids", []):
                control_ids.add(with_id.lstrip("#"))

    return control_ids


def extract_catalog_titles(catalog_data: dict) -> dict[str, str]:
    """Extract control titles from NIST SP 800-53 Rev 5 OSCAL catalog.

    Returns dict mapping OSCAL ID to title.
    """
    titles = {}

    def _walk_controls(controls: list[dict], prefix: str = "") -> None:
        for ctrl in controls:
            ctrl_id = ctrl.get("id", "")
            title = ctrl.get("title", "")
            if ctrl_id:
                titles[ctrl_id] = title
            # Recurse into sub-controls (enhancements)
            for sub in ctrl.get("controls", []):
                sub_id = sub.get("id", "")
                sub_title = sub.get("title", "")
                if sub_id:
                    titles[sub_id] = sub_title

    catalog = catalog_data.get("catalog", {})
    for group in catalog.get("groups", []):
        _walk_controls(group.get("controls", []))

    return titles


def classify_applicability(oscal_id: str) -> str:
    """Classify a control as technical, semi-technical, or procedural."""
    if oscal_id in TECHNICAL_CONTROLS:
        return "technical"
    elif oscal_id in SEMI_TECHNICAL_CONTROLS:
        return "semi-technical"
    return "procedural"


def build_baseline_yaml(
    control_ids: set[str],
    titles: dict[str, str],
) -> dict:
    """Build the baseline reference YAML structure."""
    # Group controls by family
    families: dict[str, list[dict]] = defaultdict(list)

    for oscal_id in sorted(control_ids):
        conventional_id = oscal_id_to_conventional(oscal_id)
        family = conventional_id.split("-")[0]

        title = titles.get(oscal_id, "")
        applicability = classify_applicability(oscal_id)

        entry = {
            "id": conventional_id,
            "title": title,
            "applicability": applicability,
        }
        families[family].append(entry)

    # Build final structure
    family_titles = {
        "AC": "Access Control",
        "AT": "Awareness and Training",
        "AU": "Audit and Accountability",
        "CA": "Assessment, Authorization, and Monitoring",
        "CM": "Configuration Management",
        "CP": "Contingency Planning",
        "IA": "Identification and Authentication",
        "IR": "Incident Response",
        "MA": "Maintenance",
        "MP": "Media Protection",
        "PE": "Physical and Environmental Protection",
        "PL": "Planning",
        "PS": "Personnel Security",
        "RA": "Risk Assessment",
        "SA": "System and Services Acquisition",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "SR": "Supply Chain Risk Management",
    }

    yaml_families = {}
    for family_id in sorted(families):
        yaml_families[family_id] = {
            "title": family_titles.get(family_id, family_id),
            "controls": families[family_id],
        }

    total = sum(len(f) for f in families.values())

    return {
        "id": "fedramp-moderate-rev5",
        "total_controls": total,
        "source_url": FEDRAMP_PROFILE_URL,
        "families": yaml_families,
    }


def download_json(url: str) -> dict:
    """Download and parse a JSON file from a URL."""
    print(f"  Downloading: {url[:80]}...")
    with urlopen(url) as response:
        return json.loads(response.read())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse FedRAMP OSCAL profile to generate baseline reference YAML"
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        help="Path to FedRAMP OSCAL profile JSON",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=None,
        help="Path to NIST SP 800-53 Rev 5 OSCAL catalog JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("context/fedramp/moderate-rev5-baseline.yaml"),
        help="Output YAML path",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download OSCAL files from GitHub instead of using local files",
    )
    args = parser.parse_args()

    # Load or download profile
    if args.download:
        print("Downloading OSCAL sources from GitHub...")
        profile_data = download_json(FEDRAMP_PROFILE_URL)
        catalog_data = download_json(NIST_CATALOG_URL)
    elif args.profile and args.catalog:
        print(f"Loading profile from {args.profile}...")
        profile_data = json.loads(args.profile.read_text())
        print(f"Loading catalog from {args.catalog}...")
        catalog_data = json.loads(args.catalog.read_text())
    else:
        print("Error: provide --download or both --profile and --catalog", file=sys.stderr)
        return 1

    # Extract control IDs from profile
    print("Extracting control IDs from FedRAMP profile...")
    control_ids = extract_control_ids_from_profile(profile_data)
    print(f"  Found {len(control_ids)} controls")

    # Extract titles from catalog
    print("Extracting control titles from NIST catalog...")
    titles = extract_catalog_titles(catalog_data)
    print(f"  Found {len(titles)} control titles")

    # Build YAML
    print("Building baseline YAML...")
    baseline = build_baseline_yaml(control_ids, titles)
    total = baseline["total_controls"]
    num_families = len(baseline["families"])
    print(f"  {total} controls across {num_families} families")

    # Count applicability types
    tech = semi = proc = 0
    for family_data in baseline["families"].values():
        for ctrl in family_data["controls"]:
            match ctrl["applicability"]:
                case "technical":
                    tech += 1
                case "semi-technical":
                    semi += 1
                case "procedural":
                    proc += 1
    print(f"  Technical: {tech}, Semi-technical: {semi}, Procedural: {proc}")

    # Write output
    header = (
        "# FedRAMP Moderate Rev 5 — Authoritative Control List\n"
        "#\n"
        "# Source: GSA/fedramp-automation OSCAL profile\n"
        f"# URL: {FEDRAMP_PROFILE_URL}\n"
        "# Catalog: NIST SP 800-53 Rev 5 (titles and descriptions)\n"
        f"# Last synced: {date.today().isoformat()}\n"
        "#\n"
        "# Applicability tags (for RHEL host-level SSH enforcement):\n"
        "#   technical      — enforceable via SSH checks on a RHEL host\n"
        "#   semi-technical — partially automatable (e.g., log review, inventory)\n"
        "#   procedural     — organizational/documentation only, not SSH-enforceable\n"
        "\n"
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write(header)
        yaml.dump(baseline, f, default_flow_style=False, sort_keys=False, width=120)

    print(f"\nWritten to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
