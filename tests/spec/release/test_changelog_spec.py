"""Spec-derived tests for release/changelog.spec.yaml.

Tests validate the CHANGELOG.md format and process conventions defined in
specs/release/changelog.spec.yaml. The script behavior tests are in
tests/spec/internal/test_changelog_spec.py.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parents[3]


class TestReleaseChangelogSpecDerived:
    """Spec-derived tests for changelog format conventions (AC-1 through AC-5)."""

    def test_ac1_changelog_header_format(self):
        """AC-1: CHANGELOG.md starts with # Changelog heading and --- separator."""
        changelog = REPO_ROOT / "CHANGELOG.md"
        assert changelog.exists(), "CHANGELOG.md must exist in repo root"
        content = changelog.read_text()
        lines = content.strip().splitlines()
        assert (
            lines[0] == "# Changelog"
        ), f"First line must be '# Changelog', got: {lines[0]!r}"
        assert "---" in content, "CHANGELOG.md must contain a --- separator"

    def test_ac2_version_headers_format(self):
        """AC-2: Version headers follow ## vX.Y.Z (YYYY-MM-DD) format, no codenames."""
        changelog = REPO_ROOT / "CHANGELOG.md"
        content = changelog.read_text()
        version_pattern = re.compile(r"^## v(\d+\.\d+\.\d+) \((\d{4}-\d{2}-\d{2})\)$")
        version_lines = [
            line for line in content.splitlines() if line.startswith("## v")
        ]
        assert (
            len(version_lines) > 0
        ), "CHANGELOG.md must have at least one version section"
        for line in version_lines:
            assert version_pattern.match(
                line
            ), f"Version header must match '## vX.Y.Z (YYYY-MM-DD)': {line!r}"

    def test_ac3_subsections_use_correct_headings(self):
        """AC-3: Subsections use ### Added, ### Fixed, ### Changed, ### Removed only."""
        changelog = REPO_ROOT / "CHANGELOG.md"
        content = changelog.read_text()
        allowed = {"### Added", "### Fixed", "### Changed", "### Removed"}
        subsections = [
            line.strip()
            for line in content.splitlines()
            if line.strip().startswith("### ")
        ]
        for sub in subsections:
            assert (
                sub in allowed
            ), f"Unexpected subsection heading: {sub!r} (allowed: {allowed})"

    def test_ac4_entries_are_bullets_no_trailing_period(self):
        """AC-4: Entries are bullet points (- ) without trailing periods."""
        changelog = REPO_ROOT / "CHANGELOG.md"
        content = changelog.read_text()
        # Only check entries within version sections (after first ## v)
        in_version = False
        entries = []
        for line in content.splitlines():
            if line.startswith("## v"):
                in_version = True
                continue
            if in_version and line.startswith("- "):
                entries.append(line)
        assert len(entries) > 0, "CHANGELOG.md must have bullet entries"
        for entry in entries:
            assert not entry.rstrip().endswith(
                "."
            ), f"Entry should not end with a period: {entry!r}"

    def test_ac5_no_commit_hashes_or_boilerplate(self):
        """AC-5: No commit hashes or semantic-release boilerplate in CHANGELOG.md."""
        changelog = REPO_ROOT / "CHANGELOG.md"
        content = changelog.read_text()
        # Check for 7+ char hex strings that look like commit hashes
        # Exclude lines that are clearly not commit hashes (URLs, etc.)
        for line in content.splitlines():
            if line.startswith("- "):
                assert not re.search(
                    r"\b[0-9a-f]{7,40}\b", line
                ), f"Entry appears to contain a commit hash: {line!r}"
        assert "Co-Authored-By" not in content
        assert "semantic-release" not in content.lower()
