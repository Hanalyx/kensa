"""Adapter for parsing Aegis JSON results into control-level results."""

from __future__ import annotations

import json
from collections import defaultdict

from scripts.benchmark.adapters.base import ToolAdapter, ToolControlResult

# Evidence fields defined by the Evidence dataclass in runner/_types.py
EVIDENCE_FIELDS = [
    "method",
    "command",
    "stdout",
    "stderr",
    "exit_code",
    "expected",
    "actual",
    "timestamp",
]


class AegisAdapter(ToolAdapter):
    """Parse Aegis JSON output into control-level results.

    Handles both legacy flat format (``{"results": [...]}``) and the
    multi-host format (``{"hosts": [{"results": [...]}]}``)
    produced by ``runner/output/json_fmt.py``.
    """

    @property
    def tool_name(self) -> str:
        return "aegis"

    def parse(self, path: str) -> dict[str, ToolControlResult]:
        """Parse Aegis JSON and group results by framework section.

        Args:
            path: Path to Aegis JSON results file.

        Returns:
            Dict mapping control_id -> ToolControlResult.

        """
        with open(path) as f:
            data = json.load(f)

        return self._parse_data(data)

    def parse_host(self, path: str, hostname: str) -> dict[str, ToolControlResult]:
        """Parse results for a specific host from multi-host JSON.

        Args:
            path: Path to Aegis JSON results file.
            hostname: Target hostname to extract.

        Returns:
            Dict mapping control_id -> ToolControlResult.

        """
        with open(path) as f:
            data = json.load(f)

        if "hosts" in data:
            for host in data["hosts"]:
                if host.get("hostname") == hostname:
                    return self._parse_host_results(host.get("results", []))
        return {}

    def list_hosts(self, path: str) -> list[str]:
        """List hostnames in a multi-host JSON file.

        Args:
            path: Path to Aegis JSON results file.

        Returns:
            List of hostnames, or ["default"] for flat format.

        """
        with open(path) as f:
            data = json.load(f)

        if "hosts" in data:
            return [h.get("hostname", "unknown") for h in data["hosts"]]
        return ["default"]

    def _parse_data(self, data: dict) -> dict[str, ToolControlResult]:
        """Parse either flat or multi-host format."""
        if "hosts" in data:
            # Multi-host: merge first host's results (Phase 1 = single host)
            all_results: list[dict] = []
            for host in data["hosts"]:
                all_results.extend(host.get("results", []))
            return self._parse_host_results(all_results)

        # Flat format: results at top level
        return self._parse_host_results(data.get("results", []))

    def _parse_host_results(
        self, results: list[dict]
    ) -> dict[str, ToolControlResult]:
        """Group rule results by framework_section into control results."""
        # Group rules by control (framework_section)
        by_section: dict[str, list[dict]] = defaultdict(list)
        for rule in results:
            if rule.get("skipped"):
                continue
            section = rule.get("framework_section", "")
            if section:
                by_section[section].append(rule)

        controls: dict[str, ToolControlResult] = {}
        for section, rules in by_section.items():
            # Control passes only if ALL rules for that section pass
            all_pass = all(r.get("passed", False) for r in rules)
            rule_ids = [r.get("rule_id", "") for r in rules]
            details = [r.get("detail", "") for r in rules]

            # Check for evidence
            has_evidence = any(
                isinstance(r.get("evidence"), dict) for r in rules
            )
            evidence_fields: list[str] = []
            if has_evidence:
                for r in rules:
                    ev = r.get("evidence", {})
                    if isinstance(ev, dict):
                        evidence_fields = [
                            f for f in EVIDENCE_FIELDS if ev.get(f) is not None
                        ]
                        break

            # Check for remediation
            has_remediation = any(r.get("remediated") is not None for r in rules)

            controls[section] = ToolControlResult(
                tool_name="aegis",
                control_id=section,
                passed=all_pass,
                rule_ids=rule_ids,
                has_evidence=has_evidence,
                has_remediation=has_remediation,
                evidence_fields=evidence_fields,
                detail="; ".join(d for d in details if d),
            )

        return controls
