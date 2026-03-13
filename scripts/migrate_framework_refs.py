#!/usr/bin/env python3
"""Migrate versioned framework reference keys to unversioned form.

Renames rule YAML reference keys:
  rhel9_v2    → rhel9   (CIS)
  rhel8_v4    → rhel8   (CIS)
  rhel9_v2r7  → rhel9   (STIG)
  rhel8_v2r6  → rhel8   (STIG)

No collision risk: CIS and STIG keys live under separate parent keys.

Usage:
    python3 scripts/migrate_framework_refs.py [--dry-run] [rules_dir]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Mapping of old key → new key
RENAMES = {
    "rhel10_v1": "rhel10",
    "rhel9_v2": "rhel9",
    "rhel8_v4": "rhel8",
    "rhel9_v2r7": "rhel9",
    "rhel8_v2r6": "rhel8",
}

# Build regex: match any old key as a YAML key (indented, followed by colon)
OLD_KEYS_PATTERN = re.compile(
    r"^(\s+)(" + "|".join(re.escape(k) for k in RENAMES) + r")(:)",
    re.MULTILINE,
)


def migrate_file(path: Path, dry_run: bool = False) -> int:
    """Migrate reference keys in a single rule file.

    Returns number of replacements made.
    """
    content = path.read_text()
    count = 0

    def replacer(match: re.Match) -> str:
        nonlocal count
        indent = match.group(1)
        old_key = match.group(2)
        colon = match.group(3)
        count += 1
        return f"{indent}{RENAMES[old_key]}{colon}"

    new_content = OLD_KEYS_PATTERN.sub(replacer, content)

    if count > 0 and not dry_run:
        path.write_text(new_content)

    return count


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    rules_dir = Path(args[0]) if args else Path("rules")

    if not rules_dir.is_dir():
        print(f"Error: {rules_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    total_files = 0
    total_replacements = 0

    for yml in sorted(rules_dir.rglob("*.yml")):
        n = migrate_file(yml, dry_run=dry_run)
        if n > 0:
            total_files += 1
            total_replacements += n
            if dry_run:
                print(f"  would change: {yml} ({n} replacements)")

    action = "Would change" if dry_run else "Changed"
    print(f"\n{action} {total_replacements} keys in {total_files} files.")


if __name__ == "__main__":
    main()
