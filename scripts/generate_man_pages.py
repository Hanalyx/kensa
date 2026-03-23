"""Generate groff-formatted man pages from Click CLI introspection.

Produces kensa.1 (main) and kensa-<command>.1 for each non-hidden,
non-deprecated subcommand. Output directory is configurable via -o.

Usage:
    python3 scripts/generate_man_pages.py -o man/
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import date
from pathlib import Path

# Ensure the project root is on sys.path when run as a script
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import click  # noqa: E402

from runner.cli import main as cli_main  # noqa: E402
from runner.paths import get_version  # noqa: E402


def _format_option_flags(param: click.Parameter) -> str:
    """Build the flag string for an option (e.g. '\\-h, \\-\\-host HOST')."""
    if not isinstance(param, click.Option):
        return ""
    parts = []
    for decl in param.opts + param.secondary_opts:
        parts.append(decl.replace("-", "\\-"))
    flag_str = ", ".join(parts)
    if param.type is not None and not isinstance(param.type, click.types.BoolParamType):
        metavar = param.metavar or param.type.name.upper()
        if not isinstance(param.is_flag, bool) or not param.is_flag:
            flag_str += f" {metavar}"
    return flag_str


def _get_visible_commands(group: click.Group) -> list[tuple[str, click.Command]]:
    """Return non-hidden, non-deprecated commands from a Click group."""
    commands = []
    ctx = click.Context(group)
    for name in group.list_commands(ctx):
        cmd = group.get_command(ctx, name)
        if cmd is None:
            continue
        if getattr(cmd, "hidden", False):
            continue
        if getattr(cmd, "deprecated", False):
            continue
        commands.append((name, cmd))
    return commands


def _get_command_help(cmd: click.Command) -> str:
    """Extract one-line help string from a command."""
    return cmd.get_short_help_str(limit=300) or ""


def _generate_main_page(commands: list[tuple[str, click.Command]], version: str) -> str:
    """Generate the kensa.1 main man page."""
    today = date.today().strftime("%Y\\-%m\\-%d")
    lines = [
        f'.TH KENSA 1 "{today}" "kensa {version}" "Kensa Manual"',
        ".SH NAME",
        "kensa \\- SSH\\-based compliance test runner",
        ".SH SYNOPSIS",
        ".B kensa",
        "[\\-\\-version] [\\-\\-help]",
        ".I command",
        "[options]",
        ".SH DESCRIPTION",
        " ".join((cli_main.help or "Kensa CLI").strip().split()),
        ".SH COMMANDS",
    ]

    for name, cmd in sorted(commands, key=lambda x: x[0]):
        help_text = _get_command_help(cmd)
        lines.append(".TP")
        lines.append(f".B {name}")
        lines.append(help_text)

    lines.append(".SH SEE ALSO")
    refs = []
    for name, _ in sorted(commands, key=lambda x: x[0]):
        refs.append(f".BR kensa-{name} (1)")
    lines.append(",\n".join(refs))

    return "\n".join(lines) + "\n"


def _generate_subcommand_page(name: str, cmd: click.Command, version: str) -> str:
    """Generate a kensa-<cmd>.1 man page."""
    today = date.today().strftime("%Y\\-%m\\-%d")
    upper_name = f"KENSA\\-{name.upper()}"
    lines = [
        f'.TH {upper_name} 1 "{today}" "kensa {version}" "Kensa Manual"',
        ".SH NAME",
        f"kensa\\-{name} \\- {_get_command_help(cmd)}",
        ".SH SYNOPSIS",
        f".B kensa {name}",
    ]

    # Build usage pattern from params
    ctx = click.Context(cmd, info_name=f"kensa {name}")
    params = cmd.get_params(ctx)
    options = [p for p in params if isinstance(p, click.Option)]
    arguments = [p for p in params if isinstance(p, click.Argument)]

    if options:
        lines.append("[OPTIONS]")
    for arg in arguments:
        arg_name = (arg.metavar or arg.name or "ARG").upper()
        if not arg.required:
            lines.append(f"[{arg_name}]")
        else:
            lines.append(arg_name)

    # Description
    lines.append(".SH DESCRIPTION")
    help_text = cmd.help or _get_command_help(cmd)
    if help_text:
        # Split into paragraphs
        for para in help_text.strip().split("\n\n"):
            cleaned = " ".join(para.split())
            lines.append(cleaned)
            lines.append(".PP")
        # Remove trailing .PP
        if lines[-1] == ".PP":
            lines.pop()

    # Options section
    if options:
        lines.append(".SH OPTIONS")
        for opt in options:
            flag_str = _format_option_flags(opt)
            lines.append(".TP")
            lines.append(f".B {flag_str}")
            lines.append(opt.help or "")

    # If this is a group, list subcommands
    if isinstance(cmd, click.Group):
        sub_commands = _get_visible_commands(cmd)
        if sub_commands:
            lines.append(".SH COMMANDS")
            for sub_name, sub_cmd in sorted(sub_commands, key=lambda x: x[0]):
                lines.append(".TP")
                lines.append(f".B {sub_name}")
                lines.append(_get_command_help(sub_cmd))

    lines.append(".SH SEE ALSO")
    lines.append(".BR kensa (1)")

    return "\n".join(lines) + "\n"


def generate_man_pages(output_dir: str) -> None:
    """Generate all man pages to the given output directory."""
    os.makedirs(output_dir, exist_ok=True)

    version = get_version()
    commands = _get_visible_commands(cli_main)

    # Main page
    main_content = _generate_main_page(commands, version)
    with open(os.path.join(output_dir, "kensa.1"), "w") as f:
        f.write(main_content)

    # Per-subcommand pages
    for name, cmd in commands:
        content = _generate_subcommand_page(name, cmd, version)
        with open(os.path.join(output_dir, f"kensa-{name}.1"), "w") as f:
            f.write(content)

    print(f"Generated {1 + len(commands)} man pages in {output_dir}/")


def main() -> None:
    """Entry point for man page generation script."""
    parser = argparse.ArgumentParser(
        description="Generate groff man pages from Kensa CLI definitions."
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="man/",
        help="Directory to write .1 files to (default: man/)",
    )
    args = parser.parse_args()
    generate_man_pages(args.output_dir)


if __name__ == "__main__":
    main()
