"""Output formatters for check and remediate results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from runner._types import RuleResult

from runner.output.csv_fmt import format_csv
from runner.output.json_fmt import format_json
from runner.output.pdf_fmt import format_pdf

__all__ = [
    "HostResult",
    "RunResult",
    "format_json",
    "format_csv",
    "format_pdf",
    "write_output",
    "parse_output_spec",
]


@dataclass
class HostResult:
    """Results from a single host."""

    hostname: str
    platform_family: str | None = None
    platform_version: int | None = None
    capabilities: dict[str, bool] = field(default_factory=dict)
    results: list[RuleResult] = field(default_factory=list)
    error: str | None = None

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.passed and not r.skipped)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if not r.passed and not r.skipped)

    @property
    def skip_count(self) -> int:
        return sum(1 for r in self.results if r.skipped)

    @property
    def fixed_count(self) -> int:
        return sum(1 for r in self.results if r.remediated and r.passed)


@dataclass
class RunResult:
    """Aggregated results from a full run."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    command: str = "check"  # "check" or "remediate"
    hosts: list[HostResult] = field(default_factory=list)

    @property
    def total_pass(self) -> int:
        return sum(h.pass_count for h in self.hosts)

    @property
    def total_fail(self) -> int:
        return sum(h.fail_count for h in self.hosts)

    @property
    def total_skip(self) -> int:
        return sum(h.skip_count for h in self.hosts)

    @property
    def total_fixed(self) -> int:
        return sum(h.fixed_count for h in self.hosts)

    @property
    def host_count(self) -> int:
        return len([h for h in self.hosts if h.error is None])


def parse_output_spec(spec: str) -> tuple[str, str | None]:
    """Parse output spec like 'json' or 'json:results.json'.

    Returns (format, filepath) where filepath is None for stdout.
    """
    if ":" in spec:
        fmt, path = spec.split(":", 1)
        return fmt.lower(), path
    return spec.lower(), None


def write_output(run_result: RunResult, fmt: str, filepath: str | None = None) -> str:
    """Format and optionally write results.

    Args:
        run_result: The aggregated run results.
        fmt: Output format ('json', 'csv', 'pdf').
        filepath: Optional file path to write to. Required for PDF.

    Returns:
        The formatted output string (empty string for PDF).

    Raises:
        ValueError: If format is unknown or PDF without filepath.
    """
    # PDF requires a filepath (binary format)
    if fmt == "pdf":
        if not filepath:
            raise ValueError("PDF format requires a filepath (e.g., -o pdf:report.pdf)")
        format_pdf(run_result, filepath)
        return ""

    formatters = {
        "json": format_json,
        "csv": format_csv,
    }

    if fmt not in formatters:
        valid_formats = list(formatters.keys()) + ["pdf"]
        raise ValueError(
            f"Unknown output format: {fmt} (valid: {', '.join(valid_formats)})"
        )

    output = formatters[fmt](run_result)

    if filepath:
        with open(filepath, "w") as f:
            f.write(output)

    return output
