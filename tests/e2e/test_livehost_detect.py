"""E2E tests for kensa detect against live inventory hosts.

Validates that capability detection works end-to-end over SSH
against real RHEL-compatible production-like systems from inventory.ini.
"""

from __future__ import annotations

import pytest

from tests.e2e.conftest import run_kensa


@pytest.mark.livehost
@pytest.mark.e2e
class TestLivehostDetect:
    """Test kensa detect against live hosts from inventory."""

    def test_detect_succeeds(self, livehost):
        """Detect command completes successfully against a live host."""
        result = run_kensa(livehost, ["detect"])
        assert (
            result.returncode == 0
        ), f"detect failed on {livehost.host}: {result.stderr}\n{result.stdout}"

    def test_detect_finds_platform(self, livehost):
        """Detect identifies a RHEL-family platform on a live host."""
        result = run_kensa(livehost, ["detect"])
        output = result.stdout.lower()
        assert any(
            distro in output for distro in ("rhel", "rocky", "alma", "oracle", "centos")
        ), f"No RHEL-family platform detected on {livehost.host}: {result.stdout}"

    def test_detect_finds_capabilities(self, livehost):
        """Detect reports capability probes on a live host."""
        result = run_kensa(livehost, ["detect", "--verbose"])
        output = result.stdout
        assert (
            "base" in output.lower() or "capability" in output.lower()
        ), f"No capabilities reported on {livehost.host}: {output}"

    def test_detect_all_hosts(self, livehost_targets):
        """Detect succeeds on every host in the inventory."""
        failures = []
        for host in livehost_targets:
            result = run_kensa(host, ["detect"])
            if result.returncode != 0:
                failures.append(
                    f"{host.host}: exit {result.returncode} — {result.stderr.strip()}"
                )
        assert not failures, (
            f"Detect failed on {len(failures)}/{len(livehost_targets)} hosts:\n"
            + "\n".join(failures)
        )
