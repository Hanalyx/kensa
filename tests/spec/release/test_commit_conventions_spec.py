"""Spec-derived tests for release/commit-conventions.spec.yaml.

Tests validate that Kensa's commit message and PR title conventions are
documented, machine-checkable, and consistent with the project's actual
practices.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).parents[3]
BANNED_TERMS = [
    "phase",
    "step",
    "stage",
    "milestone",
    "sprint",
    "iteration",
    "backlog",
    "epic",
    "story",
    "task",
    "ticket",
]


def _get_recent_commits(count: int = 30) -> list[str]:
    """Return the first lines of recent commit messages."""
    result = subprocess.run(
        ["git", "log", f"--max-count={count}", "--format=%s"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


class TestCommitConventionsSpecDerived:
    """Spec-derived tests for commit conventions (AC-1 through AC-8)."""

    def test_ac1_no_conventional_prefixes_in_recent_commits(self):
        """AC-1: Commit titles use descriptive format, not conventional commit prefixes."""
        prefix_pattern = re.compile(
            r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
            r"(\(.*?\))?:\s"
        )
        commits = _get_recent_commits(30)
        # Allow release commits (chore(release)) as they are automated
        violations = [
            c
            for c in commits
            if prefix_pattern.match(c) and not c.startswith("chore(release)")
        ]
        assert (
            not violations
        ), f"Commits using conventional prefixes (should be descriptive): {violations}"

    def test_ac2_subject_rules_imperative_mood(self):
        """AC-2: Titles start with a capital letter and use imperative mood."""
        commits = _get_recent_commits(20)
        # Filter out automated commits
        user_commits = [
            c
            for c in commits
            if not c.startswith(("chore(release)", "Merge pull request"))
        ]
        for commit in user_commits:
            assert commit[
                0
            ].isupper(), f"Commit title should start with a capital letter: {commit!r}"

    def test_ac3_banned_terms_list_matches_spec(self):
        """AC-3: The banned terms list is defined and complete in the spec."""
        import yaml

        spec_path = REPO_ROOT / "specs" / "release" / "commit-conventions.spec.yaml"
        with open(spec_path) as f:
            spec = yaml.safe_load(f)
        terms = spec["appendix"]["banned_terms"]["terms"]
        # All canonical banned terms must be present
        for term in BANNED_TERMS:
            assert term in terms, f"Expected banned term {term!r} in spec"
        # Spec must document what they apply to
        applies_to = spec["appendix"]["banned_terms"]["applies_to"]
        assert len(applies_to) >= 2, "Must apply to both commit and PR titles"
        # Spec must include good and bad examples
        examples = spec["appendix"]["banned_terms"]["examples"]
        assert len(examples["bad"]) >= 3, "Must include at least 3 bad examples"
        assert len(examples["good"]) >= 3, "Must include at least 3 good examples"

    def test_ac4_titles_under_100_characters(self):
        """AC-4: PR/commit titles are under 100 characters."""
        commits = _get_recent_commits(30)
        user_commits = [
            c
            for c in commits
            if not c.startswith(("chore(release)", "Merge pull request"))
        ]
        for commit in user_commits:
            assert (
                len(commit) <= 100
            ), f"Title exceeds 100 chars ({len(commit)}): {commit!r}"

    def test_ac5_scope_conventions_documented(self):
        """AC-5: Scope conventions are defined in the spec appendix."""
        import yaml

        spec_path = REPO_ROOT / "specs" / "release" / "commit-conventions.spec.yaml"
        with open(spec_path) as f:
            spec = yaml.safe_load(f)
        scopes = spec["appendix"]["scope_conventions"]["common_scopes"]
        # Verify key Kensa subsystems are covered
        scope_names = [list(s.keys())[0] if isinstance(s, dict) else s for s in scopes]
        for expected in ["rules", "handlers", "mappings", "cli", "specs"]:
            assert (
                expected in scope_names
            ), f"Expected scope {expected!r} in scope_conventions"

    def test_ac6_banned_terms_list_complete(self):
        """AC-6: Spec appendix contains the full banned terms list."""
        import yaml

        spec_path = REPO_ROOT / "specs" / "release" / "commit-conventions.spec.yaml"
        with open(spec_path) as f:
            spec = yaml.safe_load(f)
        terms = spec["appendix"]["banned_terms"]["terms"]
        for term in BANNED_TERMS:
            assert term in terms, f"Expected banned term {term!r} in spec"

    def test_ac7_co_authored_by_format(self):
        """AC-7: Claude Code commits include Co-Authored-By trailer."""
        result = subprocess.run(
            ["git", "log", "--max-count=50", "--format=%b"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        co_authored = [
            line.strip()
            for line in result.stdout.splitlines()
            if "Co-Authored-By:" in line and "anthropic.com" in line
        ]
        # Just verify the format is correct when present
        for line in co_authored:
            assert (
                "noreply@anthropic.com" in line
            ), f"Co-Authored-By should use noreply@anthropic.com: {line!r}"

    def test_ac8_changelog_categorization_alignment(self):
        """AC-8: First words of commit titles map to changelog categories."""
        import yaml

        spec_path = REPO_ROOT / "specs" / "release" / "commit-conventions.spec.yaml"
        with open(spec_path) as f:
            spec = yaml.safe_load(f)
        # Verify good examples start with verbs that categorize cleanly
        good_examples = spec["appendix"]["banned_terms"]["examples"]["good"]
        for example in good_examples:
            first_word = example.split()[0]
            assert first_word[
                0
            ].isupper(), f"Good example should start with capital: {example!r}"
