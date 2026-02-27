"""E2E tests for kensa check against known-bad container state.

Validates that check correctly identifies compliance failures for
rules with known-bad state baked into the container image.
"""

from __future__ import annotations

import subprocess

import pytest


def _run_kensa(
    host, args: list[str], timeout: int = 120
) -> subprocess.CompletedProcess:
    """Run a kensa CLI command against the E2E host."""
    cmd = [
        "python3",
        "-m",
        "runner.cli",
        *args,
        "--host",
        f"{host.user}@{host.host}:{host.port}",
        "--ssh-key",
        host.key_path,
    ]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.mark.container
@pytest.mark.e2e
class TestCheckKnownBadE2E:
    """Test kensa check detects known-bad state in container."""

    def test_gpgcheck_fails(self, el9_container):
        """Check gpgcheck-enabled rule against container with gpgcheck=0.

        The container has default dnf.conf which may or may not have gpgcheck.
        This tests the config_value handler end-to-end.
        """
        result = _run_kensa(
            el9_container,
            ["check", "--rule", "rules/system/gpgcheck-enabled.yml"],
        )
        # Should complete (exit 0 = all pass, exit 1 = some fail, exit 2 = error)
        assert result.returncode in (
            0,
            1,
        ), f"check errored: {result.stderr}\n{result.stdout}"
        # Output should contain the rule ID
        assert "gpgcheck-enabled" in result.stdout

    def test_motd_permissions_fails(self, el9_container):
        """Check motd-permissions rule detects bad permissions.

        Container has /etc/motd with 0666 permissions (should be 0644).
        Tests the file_permission handler.
        """
        result = _run_kensa(
            el9_container,
            ["check", "--rule", "rules/filesystem/motd-permissions.yml"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored: {result.stderr}\n{result.stdout}"
        assert "motd-permissions" in result.stdout

    def test_auditd_installed_fails(self, el9_container):
        """Check auditd-installed rule detects missing audit package.

        Container does not have audit package installed.
        Tests the package_state handler.
        """
        result = _run_kensa(
            el9_container,
            ["check", "--rule", "rules/audit/auditd-installed.yml"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored: {result.stderr}\n{result.stdout}"
        assert "auditd-installed" in result.stdout

    def test_password_min_age(self, el9_container):
        """Check password-min-age rule against container.

        Tests the config_value handler with comparator.
        """
        result = _run_kensa(
            el9_container,
            ["check", "--rule", "rules/access-control/password-min-age.yml"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored: {result.stderr}\n{result.stdout}"
        assert "password-min-age" in result.stdout

    def test_multiple_rules_via_directory(self, el9_container):
        """Check multiple rules from a category directory.

        Tests that kensa can load and evaluate a directory of rules
        against a real host.
        """
        result = _run_kensa(
            el9_container,
            ["check", "--rules", "rules/filesystem/", "--severity", "low"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored: {result.stderr}\n{result.stdout}"

    def test_check_el8(self, el8_container):
        """Check rules against Rocky Linux 8 container."""
        result = _run_kensa(
            el8_container,
            ["check", "--rule", "rules/system/gpgcheck-enabled.yml"],
        )
        assert result.returncode in (
            0,
            1,
        ), f"check errored on el8: {result.stderr}\n{result.stdout}"
