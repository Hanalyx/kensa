"""Tests for the unified ``kensa info`` command."""

from __future__ import annotations

import json
import re

from click.testing import CliRunner

from runner.cli import main
from runner.rule_info import classify_query


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_escape.sub("", text)


# ── classify_query unit tests ────────────────────────────────────────────────


class TestClassifyQuery:
    def test_exact_rule_id(self):
        known = {"sudo-use-pty", "ssh-disable-root-login"}
        assert classify_query("sudo-use-pty", known) == ("rule", "sudo-use-pty")

    def test_stig_id(self):
        assert classify_query("V-258036") == ("stig", "V-258036")
        assert classify_query("v-258036") == ("stig", "V-258036")

    def test_nist_control(self):
        assert classify_query("AC-3") == ("nist", "AC-3")
        assert classify_query("cm-6") == ("nist", "CM-6")

    def test_cis_section(self):
        assert classify_query("5.2.2") == ("cis", "5.2.2")
        assert classify_query("1.1") == ("cis", "1.1")

    def test_unknown_defaults_to_rule(self):
        assert classify_query("some-unknown-thing") == ("rule", "some-unknown-thing")

    def test_rule_id_takes_priority_over_pattern(self):
        """A known rule ID wins even if it matches a NIST pattern."""
        known = {"AC-999"}
        assert classify_query("AC-999", known) == ("rule", "AC-999")

    def test_empty_known_set(self):
        assert classify_query("sudo-use-pty", set()) == ("rule", "sudo-use-pty")
        assert classify_query("sudo-use-pty", None) == ("rule", "sudo-use-pty")


# ── info command integration tests ───────────────────────────────────────────


class TestInfoRuleDetail:
    """Test ``kensa info <rule-id>`` — full rule detail display."""

    def test_info_rule_by_positional(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "sudo-use-pty"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "sudo-use-pty" in output
        assert "Ensure sudo commands use a pseudo terminal" in output
        assert "Severity:" in output
        assert "medium" in output

    def test_info_rule_by_flag(self):
        """--rule with a known rule ID shows full detail."""
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--rule", "sudo-use-pty"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "sudo-use-pty" in output
        assert "Severity:" in output

    def test_info_rule_shows_description(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "sudo-use-pty"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Description:" in output

    def test_info_rule_shows_implementations(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "sudo-use-pty"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Implementations" in output
        assert "Check:" in output

    def test_info_rule_shows_references(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "sudo-use-pty"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "References" in output

    def test_info_rule_shows_framework_crossrefs(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "sudo-use-pty"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert (
            "Framework cross-references:" in output or "framework references" in output
        )

    def test_info_rule_not_found(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "nonexistent-rule-xyz"])
        assert result.exit_code != 0
        output = strip_ansi(result.output)
        assert "not found" in output.lower()

    def test_info_rule_json(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "sudo-use-pty", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["rule"]["id"] == "sudo-use-pty"
        assert data["rule"]["severity"] == "medium"
        assert "frameworks" in data


class TestInfoAutoDetect:
    """Test positional QUERY auto-detection."""

    def test_auto_detect_cis(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "5.2.2"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "CIS" in output

    def test_auto_detect_stig(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "V-258036"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "STIG" in output

    def test_auto_detect_nist(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "CM-6"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "NIST" in output


class TestInfoExplicitFlags:
    """Test explicit --cis, --stig, --nist flags."""

    def test_explicit_cis(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--cis", "5.2.2"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "CIS" in output

    def test_explicit_cis_with_rhel(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--cis", "5.2.2", "--rhel", "9"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "CIS" in output

    def test_explicit_stig(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--stig", "V-258036"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "STIG" in output

    def test_explicit_nist(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--nist", "CM-6"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "NIST" in output

    def test_explicit_cis_json(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--cis", "5.2.2", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["query"]["type"] == "cis"
        assert data["query"]["value"] == "5.2.2"
        assert "matches" in data

    def test_explicit_stig_json(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--stig", "V-258036", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["query"]["type"] == "stig"

    def test_explicit_nist_json(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--nist", "CM-6", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["query"]["type"] == "nist"


class TestInfoExistingBehavior:
    """Ensure existing --control, --list-controls, --framework still work."""

    def test_control_lookup(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info", "--control", "cis-rhel9:5.2.2"])
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "sudo-use-pty" in output or "Rules implementing" in output

    def test_list_controls(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["info", "--list-controls", "--framework", "cis-rhel9"]
        )
        assert result.exit_code == 0
        output = strip_ansi(result.output)
        assert "Controls in" in output or "controls" in output.lower()

    def test_list_controls_json(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "info",
                "--list-controls",
                "--framework",
                "cis-rhel9",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "controls" in data


class TestInfoNoArgs:
    """Test error handling when no arguments provided."""

    def test_no_args_shows_error(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info"])
        assert result.exit_code != 0
        output = strip_ansi(result.output)
        assert "Error" in output or "error" in output.lower()

    def test_no_args_shows_examples(self):
        runner = CliRunner()
        result = runner.invoke(main, ["info"])
        output = strip_ansi(result.output)
        assert "kensa info" in output


# ── deprecated lookup tests ──────────────────────────────────────────────────


class TestDeprecatedLookup:
    """Test that ``kensa lookup`` still works with deprecation warning."""

    @staticmethod
    def _all_output(result):
        """Combine stdout and stderr from CliRunner result.

        click 8.1 raises ValueError on result.stderr unless
        mix_stderr=False; click 8.2+ removed mix_stderr entirely
        and always separates streams.
        """
        try:
            return result.output + (result.stderr or "")
        except (ValueError, AttributeError):
            return result.output

    def test_lookup_shows_deprecation_warning(self):
        runner = CliRunner()
        result = runner.invoke(main, ["lookup", "5.2.2"])
        assert result.exit_code == 0
        assert "deprecated" in self._all_output(result).lower()

    def test_lookup_still_returns_results(self):
        runner = CliRunner()
        result = runner.invoke(main, ["lookup", "5.2.2"])
        assert result.exit_code == 0
        output = strip_ansi(self._all_output(result))
        assert "CIS" in output

    def test_lookup_hidden_from_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "lookup" not in result.output
