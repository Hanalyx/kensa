"""Spec-derived tests for man page generation.

See specs/cli/man_pages.spec.yaml for specification.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Expected non-hidden, non-deprecated commands
EXPECTED_COMMANDS = {
    "detect",
    "check",
    "remediate",
    "history",
    "diff",
    "coverage",
    "info",
    "rollback",
    "list",
}

HIDDEN_COMMANDS = {"lookup", "list-frameworks"}


def _generate_man_pages(output_dir: str) -> list[str]:
    """Run the man page generator and return list of created files."""
    result = subprocess.run(
        [sys.executable, "scripts/generate_man_pages.py", "-o", output_dir],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Generator failed: {result.stderr}"
    return os.listdir(output_dir)


class TestManPagesSpecDerived:
    """Spec-derived tests for man page generation.

    Source spec: specs/cli/man_pages.spec.yaml (7 ACs)
    """

    def test_ac1_main_page_lists_subcommands(self):
        """AC-1: Main man page lists all non-hidden subcommands."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = _generate_man_pages(tmpdir)
            assert "kensa.1" in files

            content = Path(os.path.join(tmpdir, "kensa.1")).read_text()
            for cmd in EXPECTED_COMMANDS:
                assert cmd in content, f"Subcommand '{cmd}' not found in kensa.1"

    def test_ac2_per_subcommand_pages_generated(self):
        """AC-2: Per-subcommand man page generated for each non-hidden command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = _generate_man_pages(tmpdir)

            for cmd in EXPECTED_COMMANDS:
                expected = f"kensa-{cmd}.1"
                assert expected in files, f"Missing man page: {expected}"

    def test_ac3_subcommand_pages_have_synopsis_and_options(self):
        """AC-3: Each subcommand man page includes SYNOPSIS and OPTIONS sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _generate_man_pages(tmpdir)

            for cmd in EXPECTED_COMMANDS:
                path = os.path.join(tmpdir, f"kensa-{cmd}.1")
                content = Path(path).read_text()
                assert (
                    ".SH SYNOPSIS" in content
                ), f"kensa-{cmd}.1 missing SYNOPSIS section"
                # 'list' group may not have options of its own
                if cmd != "list":
                    assert (
                        ".SH OPTIONS" in content or "OPTIONS" in content.upper()
                    ), f"kensa-{cmd}.1 missing OPTIONS section"

    def test_ac4_hidden_deprecated_commands_excluded(self):
        """AC-4: Hidden/deprecated commands do not produce man pages."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = _generate_man_pages(tmpdir)

            for cmd in HIDDEN_COMMANDS:
                unexpected = f"kensa-{cmd}.1"
                assert (
                    unexpected not in files
                ), f"Hidden/deprecated command '{cmd}' should not have a man page"

    def test_ac5_configurable_output_directory(self):
        """AC-5: Generator writes files to the specified output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = os.path.join(tmpdir, "custom", "output")
            os.makedirs(custom_dir)
            files = _generate_man_pages(custom_dir)
            assert len(files) > 0
            assert all(f.endswith(".1") for f in files)

    def test_ac6_valid_groff_output(self):
        """AC-6: Generated man pages are valid groff renderable by man -l."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _generate_man_pages(tmpdir)

            main_page = os.path.join(tmpdir, "kensa.1")
            content = Path(main_page).read_text()

            # Verify groff structure markers
            assert (
                content.startswith(".TH ") or ".TH " in content
            ), "Man page missing .TH title header"
            assert ".SH NAME" in content, "Man page missing .SH NAME section"

    def test_ac7_main_page_see_also_references(self):
        """AC-7: Main man page includes SEE ALSO referencing subcommand pages."""
        with tempfile.TemporaryDirectory() as tmpdir:
            _generate_man_pages(tmpdir)

            content = Path(os.path.join(tmpdir, "kensa.1")).read_text()
            assert "SEE ALSO" in content.upper(), "Missing SEE ALSO section"

            for cmd in EXPECTED_COMMANDS:
                assert (
                    f"kensa-{cmd}" in content
                ), f"SEE ALSO missing reference to kensa-{cmd}"
