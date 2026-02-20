"""Tests for evidence output with groups and effective_variables fields."""

from __future__ import annotations

import json

from runner.output import HostResult, RunResult
from runner.output.evidence_fmt import format_evidence


class TestEvidenceGroupsAndVariables:
    """Verify groups and effective_variables appear in evidence JSON."""

    def test_groups_in_evidence(self):
        """Host groups appear in evidence output."""
        run = RunResult(command="check")
        host = HostResult(
            hostname="web-01",
            groups=["web", "pci-scope"],
        )
        run.hosts.append(host)

        output = json.loads(format_evidence(run, host))
        assert output["host"]["groups"] == ["web", "pci-scope"]

    def test_effective_variables_in_evidence(self):
        """Effective variables appear in evidence output."""
        run = RunResult(command="check")
        host = HostResult(
            hostname="web-01",
            effective_variables={
                "ssh_max_auth_tries": 3,
                "login_defs_pass_max_days": 30,
            },
        )
        run.hosts.append(host)

        output = json.loads(format_evidence(run, host))
        assert output["host"]["effective_variables"]["ssh_max_auth_tries"] == 3
        assert output["host"]["effective_variables"]["login_defs_pass_max_days"] == 30

    def test_empty_groups_and_variables(self):
        """Empty groups and variables produce empty collections."""
        run = RunResult(command="check")
        host = HostResult(hostname="plain-host")
        run.hosts.append(host)

        output = json.loads(format_evidence(run, host))
        assert output["host"]["groups"] == []
        assert output["host"]["effective_variables"] == {}

    def test_multi_host_evidence(self):
        """Groups are per-host in multi-host evidence."""
        from runner.output.evidence_fmt import format_evidence_all

        run = RunResult(command="check")
        host1 = HostResult(hostname="web-01", groups=["web"])
        host2 = HostResult(hostname="db-01", groups=["db", "pci-scope"])
        run.hosts.extend([host1, host2])

        output = json.loads(format_evidence_all(run))
        assert isinstance(output, list)
        assert output[0]["host"]["groups"] == ["web"]
        assert output[1]["host"]["groups"] == ["db", "pci-scope"]
