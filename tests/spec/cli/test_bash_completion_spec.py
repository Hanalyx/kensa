"""Spec-derived tests for bash shell completion.

See specs/cli/bash_completion.spec.yaml for specification.
"""

from __future__ import annotations

import os

import click
from click.testing import CliRunner

from runner.cli import main


def _get_option(command, option_name):
    """Find an option by name in a Click command's params."""
    for param in command.params:
        if isinstance(param, click.Option) and option_name in param.opts:
            return param
    return None


class TestBashCompletionSpecDerived:
    """Spec-derived tests for bash completion.

    Source spec: specs/cli/bash_completion.spec.yaml (5 ACs)
    """

    def test_ac1_output_option_completes_formats(self):
        """AC-1: --output has shell_complete offering csv, json, pdf, evidence."""
        # Find the --output option on the check command
        check_cmd = main.commands.get("check")
        assert check_cmd is not None

        opt = _get_option(check_cmd, "--output")
        assert opt is not None

        # The option should have a shell_complete callback or type with completions
        has_completion = opt.shell_complete is not None or isinstance(
            opt.type, click.Choice
        )
        assert has_completion, "--output option has no completion mechanism"

        # Verify the completion values include all formats
        if isinstance(opt.type, click.Choice):
            choices = set(opt.type.choices)
        else:
            # shell_complete callback — invoke via Parameter.shell_complete(ctx, incomplete)
            ctx = click.Context(check_cmd)
            items = opt.shell_complete(ctx, "")
            choices = {item.value for item in items}

        expected = {"csv", "json", "pdf", "evidence"}
        assert expected.issubset(
            choices
        ), f"Missing format completions: {expected - choices}"

    def test_ac2_severity_option_uses_choice(self):
        """AC-2: --severity uses click.Choice with critical, high, medium, low."""
        check_cmd = main.commands.get("check")
        assert check_cmd is not None

        opt = _get_option(check_cmd, "--severity")
        assert opt is not None
        assert isinstance(opt.type, click.Choice), "--severity should use click.Choice"

        expected = {"critical", "high", "medium", "low"}
        actual = set(opt.type.choices)
        assert expected == actual, f"Expected {expected}, got {actual}"

    def test_ac3_framework_option_completes_from_mappings(self):
        """AC-3: --framework has shell_complete returning framework IDs."""
        check_cmd = main.commands.get("check")
        assert check_cmd is not None

        opt = _get_option(check_cmd, "--framework")
        assert opt is not None

        # Should have a shell_complete callback
        has_completion = opt.shell_complete is not None or isinstance(
            opt.type, click.Choice
        )
        assert has_completion, "--framework option has no completion mechanism"

        # Get the completions
        if isinstance(opt.type, click.Choice):
            values = set(opt.type.choices)
        else:
            ctx = click.Context(check_cmd)
            items = opt.shell_complete(ctx, "")
            values = {item.value for item in items}

        # Should include at least cis-rhel9 and stig-rhel9
        assert "cis-rhel9" in values, f"cis-rhel9 not in completions: {values}"
        assert "stig-rhel9" in values, f"stig-rhel9 not in completions: {values}"

    def test_ac4_bash_completion_script_generated(self):
        """AC-4: _KENSA_COMPLETE=bash_source generates valid bash completion."""
        import subprocess
        import sys

        # Click uses the prog_name to derive the env var name: _KENSA_COMPLETE
        # We must call main(prog_name="kensa") so Click recognizes the var.
        env = {**os.environ, "_KENSA_COMPLETE": "bash_source"}
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                ("from runner.cli import main; main(prog_name='kensa')"),
            ],
            capture_output=True,
            text=True,
            env=env,
        )

        output = result.stdout
        assert len(output) > 0, "Completion script is empty"
        # Click bash completion scripts contain _kensa_completion or COMPREPLY
        assert (
            "_kensa" in output.lower()
            or "compreply" in output.lower()
            or "complete" in output.lower()
        ), f"Output doesn't look like a bash completion script: {output[:200]}"

    def test_ac5_output_option_accepts_format_path_syntax(self):
        """AC-5: --output still accepts format:path syntax at runtime."""
        runner = CliRunner()

        # This should not fail with "invalid choice" — the option must
        # accept format:path syntax even with completion configured
        result = runner.invoke(
            main,
            [
                "check",
                "--output",
                "json:/tmp/test.json",
                "--host",
                "dummy",
            ],
        )

        # We expect a connection error (no host), NOT a usage/option error
        assert (
            result.exit_code != 2
        ), f"Click rejected the command (exit code 2): {result.output}"
        try:
            stderr = result.stderr or ""
        except ValueError:
            stderr = ""
        output = result.output + stderr
        assert "Invalid value" not in output, f"format:path syntax rejected: {output}"
        assert (
            "invalid choice" not in output.lower()
        ), f"format:path syntax rejected as invalid choice: {output}"
