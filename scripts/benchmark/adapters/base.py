"""Base types and adapter interface for benchmarking."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ToolControlResult:
    """Result of a single tool evaluating a single framework control.

    Attributes:
        tool_name: Name of the tool (e.g., "kensa", "openscap").
        control_id: Framework control identifier (e.g., CIS "5.1.20").
        passed: Whether the control passed. None means not covered.
        rule_ids: Tool-specific rule IDs contributing to this result.
        has_evidence: Whether machine-verifiable evidence was captured.
        has_remediation: Whether remediation is available for this control.
        evidence_fields: Names of populated evidence fields.
        detail: Human-readable result detail.

    """

    tool_name: str
    control_id: str
    passed: bool | None
    rule_ids: list[str] = field(default_factory=list)
    has_evidence: bool = False
    has_remediation: bool = False
    evidence_fields: list[str] = field(default_factory=list)
    detail: str = ""


class ToolAdapter(ABC):
    """Abstract base for tool result adapters.

    Each adapter parses a tool's output format and produces
    ToolControlResult objects keyed by framework control ID.
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Short name for the tool (e.g., 'kensa', 'openscap')."""

    @abstractmethod
    def parse(self, path: str) -> dict[str, ToolControlResult]:
        """Parse tool output into control-level results.

        Args:
            path: Path to the tool's output file.

        Returns:
            Dict mapping control_id -> ToolControlResult.

        """
