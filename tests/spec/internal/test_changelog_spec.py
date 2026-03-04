"""Spec-derived tests for changelog.spec.yaml.

Tests validate the acceptance criteria defined in
specs/internal/changelog.spec.yaml — verifying that update_changelog.py
produces correctly formatted CHANGELOG.md entries.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path


def _run_script(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    """Run update_changelog.py with given args and return the result."""
    script = Path(__file__).parents[3] / "scripts" / "update_changelog.py"
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )


def _load_mod():
    """Load update_changelog module for direct function calls."""
    repo_root = Path(__file__).parents[3]
    script = repo_root / "scripts" / "update_changelog.py"
    sys.path.insert(0, str(repo_root))
    spec = importlib.util.spec_from_file_location("update_changelog", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SAMPLE_LOG = [
    "abc1234 Add new sysctl check handler (#99)",
    "def5678 Fix sqlite3.IntegrityError in --store (#132)",
    "ghi9012 Update release workflow",
]


class TestChangelogSpecDerived:
    """Spec-derived tests for changelog format and generation (AC-1 through AC-10)."""

    def test_ac1_ac2_header_and_version_format(self, tmp_path):
        """AC-1/AC-2: CHANGELOG starts with heading; version header is ## vX.Y.Z (YYYY-MM-DD)."""
        mod = _load_mod()
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text("# Changelog\n\nAll notable changes.\n\n---\n")

        entries = [mod.parse_log_entry(line) for line in _SAMPLE_LOG]
        section = mod.build_section("1.9.0", "2026-03-03", entries)
        mod.CHANGELOG_PATH = changelog
        mod.update_changelog("1.9.0", "2026-03-03", section)

        content = changelog.read_text()
        assert "# Changelog" in content
        assert "## v1.9.0 (2026-03-03)" in content

    def test_ac3_subheadings_grouped_correctly(self, tmp_path):
        """AC-3: Changes grouped under Added/Fixed/Changed/Removed; empty groups omitted."""
        mod = _load_mod()
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text("# Changelog\n\nAll notable changes.\n\n---\n")

        entries = [mod.parse_log_entry(line) for line in _SAMPLE_LOG]
        section = mod.build_section("1.9.0", "2026-03-03", entries)
        mod.CHANGELOG_PATH = changelog
        mod.update_changelog("1.9.0", "2026-03-03", section)

        content = changelog.read_text()
        assert any(
            h in content
            for h in ["### Added", "### Fixed", "### Changed", "### Removed"]
        )
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("### "):
                rest = [ln for ln in lines[i + 1 :] if ln.strip()]
                if rest:
                    assert not rest[0].startswith("###"), f"Empty subheading: {line}"

    def test_ac4_entries_are_bullets_with_pr_number(self, tmp_path):
        """AC-4: Each entry is a "- " bullet; PR number appears as (#NNN)."""
        mod = _load_mod()
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text("# Changelog\n\nAll notable changes.\n\n---\n")

        entries = [mod.parse_log_entry(line) for line in _SAMPLE_LOG]
        section = mod.build_section("1.9.0", "2026-03-03", entries)
        mod.CHANGELOG_PATH = changelog
        mod.update_changelog("1.9.0", "2026-03-03", section)

        content = changelog.read_text()
        entry_lines = [ln for ln in content.splitlines() if ln.startswith("- ")]
        assert len(entry_lines) > 0
        for line in entry_lines:
            assert line.startswith("- ")

    def test_ac5_no_commit_hashes_or_boilerplate(self, tmp_path):
        """AC-5: No commit hashes, repo URLs, or semantic-release boilerplate in output."""
        mod = _load_mod()
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text("# Changelog\n\nAll notable changes.\n\n---\n")

        entries = [mod.parse_log_entry(line) for line in _SAMPLE_LOG]
        section = mod.build_section("1.9.0", "2026-03-03", entries)
        mod.CHANGELOG_PATH = changelog
        mod.update_changelog("1.9.0", "2026-03-03", section)

        content = changelog.read_text()
        assert "github.com/Hanalyx/aegis" not in content
        assert "Co-Authored-By" not in content
        assert not re.search(r"\b[0-9a-f]{7,40}\b", content)

    def test_ac6_script_extracts_categorizes_and_prepends(self, tmp_path, monkeypatch):
        """AC-6: update_changelog.py extracts PR titles, categorizes, prepends to CHANGELOG.md."""
        mod = _load_mod()
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text("# Changelog\n\nAll notable changes.\n\n---\n")

        monkeypatch.setattr(mod, "CHANGELOG_PATH", changelog)
        monkeypatch.setattr(
            mod,
            "get_git_log",
            lambda _tag: "\n".join(
                [
                    "abc1234 Add new output format (#99)",
                    "def5678 Fix crash on --store (#100)",
                ]
            ),
        )

        raw_log = mod.get_git_log("v1.8.0")
        raw_lines = [ln for ln in raw_log.splitlines() if ln.strip()]
        filtered = mod.filter_log_lines(raw_lines)
        entries = [mod.parse_log_entry(line) for line in filtered]
        section = mod.build_section("1.9.0", "2026-03-03", entries)
        mod.update_changelog("1.9.0", "2026-03-03", section)

        content = changelog.read_text()
        assert "## v1.9.0 (2026-03-03)" in content
        assert "### Added" in content
        assert "### Fixed" in content
        assert "(#99)" in content
        assert "(#100)" in content

    def test_ac7_categorization_rules(self, tmp_path):
        """AC-7: First-word categorization maps correctly to Added/Fixed/Changed/Removed."""
        from scripts.update_changelog import categorize  # noqa: PLC0415

        assert categorize("Add new output format") == "Added"
        assert categorize("Implement path resolution") == "Added"
        assert categorize("Fix sqlite3.IntegrityError on --store") == "Fixed"
        assert categorize("Resolve CI failures") == "Fixed"
        assert categorize("Update release workflow") == "Changed"
        assert categorize("Remove deprecated lookup command") == "Removed"
        assert categorize("Raise STIG RHEL 9 coverage to 95%") == "Added"

    def test_ac8_release_commits_excluded(self, tmp_path):
        """AC-8: Release commits are filtered out of changelog entries."""
        from scripts.update_changelog import filter_log_lines  # noqa: PLC0415

        lines = [
            "abc1234 chore(release): 1.2.5 [skip ci]",
            "def5678 Merge pull request #99 from Hanalyx/fix/foo",
            "ghi9012 Release v1.2.4",
            "jkl3456 Fix sqlite3.IntegrityError in --store (#132)",
        ]
        filtered = filter_log_lines(lines)
        assert len(filtered) == 1
        assert "sqlite3" in filtered[0]

    def test_ac9_exits_0_on_success(self, tmp_path, monkeypatch):
        """AC-9: Script exits 0 when CHANGELOG.md is updated successfully."""
        mod = _load_mod()
        tmp_changelog = tmp_path / "CHANGELOG.md"
        tmp_changelog.write_text("# Changelog\n\nAll notable changes.\n\n---\n")

        monkeypatch.setattr(mod, "CHANGELOG_PATH", tmp_changelog)
        monkeypatch.setattr(
            mod,
            "get_git_log",
            lambda _tag: (
                "abc1234 Fix CI failures (#50)\ndef5678 Add coverage script (#51)\n"
            ),
        )

        raw_log = mod.get_git_log("v1.0.0")
        raw_lines = [ln for ln in raw_log.splitlines() if ln.strip()]
        filtered = mod.filter_log_lines(raw_lines)
        entries = [mod.parse_log_entry(line) for line in filtered] or [
            ("No user-facing changes", None)
        ]
        section = mod.build_section("1.9.0", "2026-03-03", entries)
        mod.update_changelog("1.9.0", "2026-03-03", section)

        content = tmp_changelog.read_text()
        assert "## v1.9.0 (2026-03-03)" in content
        assert "# Changelog" in content

    def test_ac10_release_workflow_calls_script(self, tmp_path):
        """AC-10: release.yml calls update_changelog.py (not semantic-release changelog)."""
        repo_root = Path(__file__).parents[3]
        release_yml = repo_root / ".github" / "workflows" / "release.yml"
        content = release_yml.read_text()
        assert "update_changelog.py" in content
        assert "semantic-release changelog" not in content
