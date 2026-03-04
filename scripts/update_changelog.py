#!/usr/bin/env python3
"""Update CHANGELOG.md with a new version entry.

Reads merged PR titles from git log since the previous version tag, categorizes
them as Added/Fixed/Changed/Removed, and prepends a formatted section to
CHANGELOG.md.

Usage:
    python3 scripts/update_changelog.py --version 1.2.6
    python3 scripts/update_changelog.py --version 1.2.6 --since-tag v1.2.5
    python3 scripts/update_changelog.py --version 1.2.6 --date 2026-03-03

Spec: specs/internal/changelog.spec.yaml
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

CHANGELOG_PATH = Path(__file__).parent.parent / "CHANGELOG.md"

# First-word → category mapping (AC-7)
_ADDED_WORDS = {"add", "implement", "introduce", "support", "raise", "new"}
_FIXED_WORDS = {"fix", "correct", "resolve", "patch", "handle"}
_REMOVED_WORDS = {"remove", "delete", "drop", "deprecate"}

# Commit lines to exclude from changelog (AC-8)
_EXCLUDE_PATTERNS = [
    re.compile(r"chore\(release\):", re.IGNORECASE),
    re.compile(r"Merge pull request", re.IGNORECASE),
    re.compile(r"Release v\d", re.IGNORECASE),
    re.compile(r"\[skip ci\]", re.IGNORECASE),
    re.compile(r"^[0-9a-f]+ chore\(release\)"),
]

_HEADER = """\
# Changelog

All notable changes to Kensa are documented here. Most recent release first.

---
"""


def categorize(title: str) -> str:
    """Return the changelog category for a commit title (AC-7)."""
    first = title.split()[0].lower().rstrip(":") if title.split() else ""
    if first in _ADDED_WORDS:
        return "Added"
    if first in _FIXED_WORDS:
        return "Fixed"
    if first in _REMOVED_WORDS:
        return "Removed"
    return "Changed"


def filter_log_lines(lines: list[str]) -> list[str]:
    """Remove release/merge commits from git log lines (AC-8)."""
    result = []
    for line in lines:
        if any(p.search(line) for p in _EXCLUDE_PATTERNS):
            continue
        result.append(line)
    return result


def get_git_log(since_tag: str) -> str:
    """Return git log --oneline output since since_tag."""
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", f"{since_tag}..HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        print(f"Error: git log failed: {exc.stderr.strip()}", file=sys.stderr)
        sys.exit(1)


def get_previous_tag() -> str:
    """Return the most recent version tag before HEAD."""
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0", "HEAD^"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        # No previous tag — use the first commit
        result = subprocess.run(
            ["git", "rev-list", "--max-parents=0", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()


def parse_log_entry(line: str) -> tuple[str, str | None]:
    """Extract (title, pr_number) from a git log --oneline line."""
    # Strip the short SHA prefix
    parts = line.split(None, 1)
    title = parts[1] if len(parts) > 1 else parts[0]

    # Extract PR number if present: "(#NNN)"
    pr_match = re.search(r"\(#(\d+)\)", title)
    pr_number = pr_match.group(1) if pr_match else None

    # Strip the PR ref from the title for a cleaner summary
    title = re.sub(r"\s*\(#\d+\)", "", title).strip()

    return title, pr_number


def build_section(version: str, release_date: str, entries: list[tuple[str, str]]) -> str:
    """Build a changelog section string (AC-2, AC-3, AC-4).

    Args:
        version: Version string, e.g. "1.2.6".
        release_date: ISO date string, e.g. "2026-03-03".
        entries: List of (title, pr_number) tuples.

    Returns:
        Formatted Markdown section.

    """
    by_category: dict[str, list[str]] = {
        "Added": [],
        "Fixed": [],
        "Changed": [],
        "Removed": [],
    }

    for title, pr_number in entries:
        cat = categorize(title)
        suffix = f" (#{pr_number})" if pr_number else ""
        by_category[cat].append(f"- {title}{suffix}")

    lines = [f"## v{version} ({release_date})", ""]
    for cat in ("Added", "Fixed", "Changed", "Removed"):
        items = by_category[cat]
        if items:
            lines.append(f"### {cat}")
            lines.extend(items)
            lines.append("")

    return "\n".join(lines)


def update_changelog(version: str, release_date: str, section: str) -> None:
    """Prepend or replace a version section in CHANGELOG.md (AC-1, AC-9).

    Args:
        version: Version string for idempotency check.
        release_date: ISO date string for the section header.
        section: The formatted Markdown section to insert.

    """
    if CHANGELOG_PATH.exists():
        existing = CHANGELOG_PATH.read_text()
    else:
        existing = _HEADER

    # Idempotent: replace existing section if present
    version_pattern = re.compile(
        rf"^## v{re.escape(version)} .*?(?=^## v|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    if version_pattern.search(existing):
        updated = version_pattern.sub(section + "\n---\n\n", existing, count=1)
        CHANGELOG_PATH.write_text(updated)
        return

    # Prepend after the header block (everything before the first ## v)
    first_version = re.search(r"^## v", existing, re.MULTILINE)
    if first_version:
        insert_at = first_version.start()
        updated = existing[:insert_at] + section + "\n---\n\n" + existing[insert_at:]
    else:
        # No existing version sections — append after header
        if not existing.endswith("\n"):
            existing += "\n"
        updated = existing + "\n" + section + "\n---\n"

    CHANGELOG_PATH.write_text(updated)


def main() -> None:
    """Entry point for update_changelog.py."""
    parser = argparse.ArgumentParser(
        description="Prepend a new version section to CHANGELOG.md."
    )
    parser.add_argument("--version", required=True, help="Version to document (e.g. 1.2.6)")
    parser.add_argument("--since-tag", help="Git tag lower bound (default: previous tag)")
    parser.add_argument("--date", help="Release date YYYY-MM-DD (default: today)")
    parser.add_argument(
        "--skip-if-exists",
        action="store_true",
        help="Skip update if a section for this version already exists in CHANGELOG.md",
    )
    args = parser.parse_args()

    if args.skip_if_exists and CHANGELOG_PATH.exists():
        existing = CHANGELOG_PATH.read_text()
        version_pattern = re.compile(
            rf"^## v{re.escape(args.version)} ", re.MULTILINE
        )
        if version_pattern.search(existing):
            print(f"CHANGELOG.md already has v{args.version} section — skipping.")
            return

    release_date = args.date or date.today().isoformat()
    since_tag = args.since_tag or get_previous_tag()

    raw_log = get_git_log(since_tag)
    raw_lines = [l for l in raw_log.splitlines() if l.strip()]
    filtered = filter_log_lines(raw_lines)

    entries = [parse_log_entry(line) for line in filtered]

    if not entries:
        # Still create a section, just note no user-facing changes
        entries = [("No user-facing changes in this release", None)]

    section = build_section(args.version, release_date, entries)
    update_changelog(args.version, release_date, section)

    print(f"Updated CHANGELOG.md for v{args.version} ({len(entries)} entries).")


if __name__ == "__main__":
    main()
