"""Spec-derived tests for release/changelog.spec.yaml.

Tests validate the CHANGELOG.md format and process conventions defined in
specs/release/changelog.spec.yaml. The script behavior tests are in
tests/spec/internal/test_changelog_spec.py.
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parents[3]


class TestReleaseChangelogSpecDerived:
    """Spec-derived tests for changelog format conventions (AC-1 through AC-10)."""

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

    def test_ac6_update_changelog_script_generates_section(self):
        """AC-6: update_changelog.py extracts merged PR titles and prepends a formatted section."""
        # Verify the script exists and has the build_section function
        script = REPO_ROOT / "scripts" / "update_changelog.py"
        assert script.exists(), "scripts/update_changelog.py must exist"

        # Import the module and test build_section produces correct format
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        try:
            mod = importlib.import_module("update_changelog")
            entries = [("Add new check handler", "42"), ("Fix lint errors", "43")]
            section = mod.build_section("9.9.9", "2026-01-01", entries)
            assert section.startswith("## v9.9.9 (2026-01-01)")
            assert "- Add new check handler (#42)" in section
            assert "- Fix lint errors (#43)" in section
        finally:
            sys.path.pop(0)

    def test_ac7_categorization_rules(self):
        """AC-7: Titles starting with Add/Implement/etc map to Added; Fix/Correct/etc to Fixed; Remove/Delete/etc to Removed; others to Changed."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        try:
            mod = importlib.import_module("update_changelog")
            # Added keywords
            for word in ("Add", "Implement", "Introduce", "Support", "Raise", "New"):
                assert (
                    mod.categorize(f"{word} something") == "Added"
                ), f"{word} should map to Added"
            # Fixed keywords
            for word in ("Fix", "Correct", "Resolve", "Patch", "Handle"):
                assert (
                    mod.categorize(f"{word} something") == "Fixed"
                ), f"{word} should map to Fixed"
            # Removed keywords
            for word in ("Remove", "Delete", "Drop", "Deprecate"):
                assert (
                    mod.categorize(f"{word} something") == "Removed"
                ), f"{word} should map to Removed"
            # Default → Changed
            assert mod.categorize("Update something") == "Changed"
            assert mod.categorize("Refactor something") == "Changed"
        finally:
            sys.path.pop(0)

    def test_ac8_release_commits_excluded(self):
        """AC-8: Release commits matching chore(release), Merge pull request, Release v, [skip ci] are excluded."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        try:
            mod = importlib.import_module("update_changelog")
            lines = [
                "abc1234 chore(release): v1.2.3",
                "def5678 Merge pull request #99 from main",
                "ghi9012 Release v1.2.3",
                "jkl3456 [skip ci] bump version",
                "mno7890 Add new feature (#50)",
            ]
            filtered = mod.filter_log_lines(lines)
            assert len(filtered) == 1, f"Expected 1 remaining line, got {len(filtered)}"
            assert "Add new feature" in filtered[0]
        finally:
            sys.path.pop(0)

    def test_ac9_release_workflow_calls_update_changelog(self):
        """AC-9: The release workflow calls update_changelog.py after bumping pyproject.toml."""
        release_yml = REPO_ROOT / ".github" / "workflows" / "release.yml"
        assert release_yml.exists(), "release.yml must exist"
        content = release_yml.read_text()
        assert (
            "update_changelog.py" in content
        ), "release.yml must call update_changelog.py"

    def test_ac10_skip_if_exists_flag(self):
        """AC-10: The --skip-if-exists flag preserves hand-crafted CHANGELOG sections."""
        # Verify the script accepts --skip-if-exists
        script = REPO_ROOT / "scripts" / "update_changelog.py"
        content = script.read_text()
        assert (
            "--skip-if-exists" in content
        ), "update_changelog.py must support --skip-if-exists flag"
        # Verify release workflow passes the flag
        release_yml = REPO_ROOT / ".github" / "workflows" / "release.yml"
        release_content = release_yml.read_text()
        assert (
            "--skip-if-exists" in release_content
        ), "release.yml must pass --skip-if-exists to update_changelog.py"
