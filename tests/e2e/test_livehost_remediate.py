"""E2E tests for kensa remediate dry-run against live inventory hosts.

Live host remediation tests use --dry-run by default to avoid
modifying production-like systems. Only safe, reversible operations
are tested with actual remediation.
"""

from __future__ import annotations

import pytest

from tests.e2e.conftest import run_kensa


@pytest.mark.livehost
@pytest.mark.e2e
class TestLivehostRemediateDryRun:
    """Test kensa remediate --dry-run against live hosts.

    Dry-run validates the full remediation pipeline (rule loading,
    handler selection, plan generation) without applying changes.
    """

    def test_remediate_dry_run_single_rule(self, livehost):
        """Dry-run remediation for a single rule on a live host."""
        result = run_kensa(
            livehost,
            [
                "remediate",
                "--rule",
                "rules/system/gpgcheck-enabled.yml",
                "--dry-run",
            ],
        )
        assert result.returncode in (0, 1), (
            f"remediate dry-run errored on {livehost.host}: "
            f"{result.stderr}\n{result.stdout}"
        )

    def test_remediate_dry_run_filesystem(self, livehost):
        """Dry-run remediation for filesystem rules on a live host."""
        result = run_kensa(
            livehost,
            [
                "remediate",
                "--rules",
                "rules/filesystem/",
                "--dry-run",
                "--severity",
                "low",
            ],
        )
        assert result.returncode in (0, 1), (
            f"remediate dry-run errored on {livehost.host}: "
            f"{result.stderr}\n{result.stdout}"
        )

    def test_remediate_dry_run_access_control(self, livehost):
        """Dry-run remediation for access-control rules on a live host."""
        result = run_kensa(
            livehost,
            [
                "remediate",
                "--rules",
                "rules/access-control/",
                "--dry-run",
                "--severity",
                "low",
            ],
        )
        assert result.returncode in (0, 1), (
            f"remediate dry-run errored on {livehost.host}: "
            f"{result.stderr}\n{result.stdout}"
        )

    def test_remediate_dry_run_all_hosts(self, livehost_targets):
        """Dry-run a single remediation across all inventory hosts."""
        failures = []
        for host in livehost_targets:
            result = run_kensa(
                host,
                [
                    "remediate",
                    "--rule",
                    "rules/system/gpgcheck-enabled.yml",
                    "--dry-run",
                ],
            )
            if result.returncode not in (0, 1):
                failures.append(
                    f"{host.host}: exit {result.returncode} — {result.stderr.strip()}"
                )
        assert not failures, (
            f"Remediate dry-run failed on {len(failures)}/{len(livehost_targets)} "
            f"hosts:\n" + "\n".join(failures)
        )
