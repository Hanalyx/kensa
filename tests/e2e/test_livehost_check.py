"""E2E tests for kensa check against live inventory hosts.

Validates that compliance checks run correctly against real
RHEL-compatible systems from inventory.ini. Live hosts have full
kernel, audit, SELinux, and systemd capabilities that containers lack.
"""

from __future__ import annotations

import pytest

from tests.e2e.conftest import run_kensa


@pytest.mark.livehost
@pytest.mark.e2e
class TestLivehostCheck:
    """Test kensa check against live hosts from inventory."""

    def test_check_single_rule(self, livehost):
        """Check a single rule completes without error on a live host."""
        result = run_kensa(
            livehost,
            ["check", "--rule", "rules/system/gpgcheck-enabled.yml"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored on {livehost.host}: {result.stderr}\n{result.stdout}"
        assert "gpgcheck-enabled" in result.stdout

    def test_check_filesystem_rules(self, livehost):
        """Check filesystem rules directory on a live host."""
        result = run_kensa(
            livehost,
            ["check", "--rules", "rules/filesystem/", "--severity", "low"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored on {livehost.host}: {result.stderr}\n{result.stdout}"

    def test_check_audit_rules(self, livehost):
        """Check audit rules on a live host (requires audit subsystem).

        This exercises audit_rule_exists and service_state handlers
        which are not available in containers.
        """
        result = run_kensa(
            livehost,
            ["check", "--rules", "rules/audit/", "--severity", "low"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored on {livehost.host}: {result.stderr}\n{result.stdout}"

    def test_check_services_rules(self, livehost):
        """Check services rules on a live host (requires full systemd).

        Exercises service_state handler with real systemd.
        """
        result = run_kensa(
            livehost,
            ["check", "--rules", "rules/services/", "--severity", "low"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored on {livehost.host}: {result.stderr}\n{result.stdout}"

    def test_check_kernel_rules(self, livehost):
        """Check kernel rules on a live host (requires kernel modules).

        Exercises kernel_module_state and sysctl_value handlers
        which are not available in containers.
        """
        result = run_kensa(
            livehost,
            ["check", "--rules", "rules/kernel/", "--severity", "low"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored on {livehost.host}: {result.stderr}\n{result.stdout}"

    def test_check_access_control_rules(self, livehost):
        """Check access-control rules on a live host."""
        result = run_kensa(
            livehost,
            ["check", "--rules", "rules/access-control/", "--severity", "low"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored on {livehost.host}: {result.stderr}\n{result.stdout}"

    def test_check_network_rules(self, livehost):
        """Check network rules on a live host."""
        result = run_kensa(
            livehost,
            ["check", "--rules", "rules/network/", "--severity", "low"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored on {livehost.host}: {result.stderr}\n{result.stdout}"

    def test_check_all_hosts(self, livehost_targets):
        """Run a single check rule across all inventory hosts."""
        failures = []
        for host in livehost_targets:
            result = run_kensa(
                host,
                ["check", "--rule", "rules/system/gpgcheck-enabled.yml"],
            )
            if result.returncode not in (0, 1):
                failures.append(
                    f"{host.host}: exit {result.returncode} — {result.stderr.strip()}"
                )
        assert not failures, (
            f"Check failed on {len(failures)}/{len(livehost_targets)} hosts:\n"
            + "\n".join(failures)
        )

    def test_check_by_control_reference(self, livehost):
        """Check a rule by CIS control reference on a live host."""
        result = run_kensa(
            livehost,
            ["check", "--control", "1.1.1"],
        )
        # May pass, fail, or have no matching rule — just shouldn't error
        assert result.returncode in (0, 1, 2), (
            f"check --control errored on {livehost.host}: "
            f"{result.stderr}\n{result.stdout}"
        )
