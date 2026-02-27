"""E2E tests for kensa detect against container hosts.

Validates that capability detection works end-to-end over SSH
against a real RHEL-compatible system.
"""

from __future__ import annotations

import subprocess

import pytest


@pytest.mark.container
@pytest.mark.e2e
class TestDetectE2E:
    """Test kensa detect against a live container."""

    def _run_kensa(self, host, args: list[str]) -> subprocess.CompletedProcess:
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
            timeout=60,
        )

    def test_detect_succeeds(self, el9_container):
        """Detect command completes successfully against container."""
        result = self._run_kensa(el9_container, ["detect"])
        assert (
            result.returncode == 0
        ), f"detect failed: {result.stderr}\n{result.stdout}"

    def test_detect_finds_platform(self, el9_container):
        """Detect identifies Rocky Linux 9 platform."""
        result = self._run_kensa(el9_container, ["detect"])
        output = result.stdout.lower()
        assert (
            "rocky" in output or "rhel" in output
        ), f"Platform not detected: {result.stdout}"

    def test_detect_finds_capabilities(self, el9_container):
        """Detect reports capability probes."""
        result = self._run_kensa(el9_container, ["detect", "--verbose"])
        output = result.stdout
        # Should report some capabilities
        assert (
            "base" in output.lower() or "capability" in output.lower()
        ), f"No capabilities reported: {output}"

    def test_detect_el8(self, el8_container):
        """Detect works against Rocky Linux 8."""
        result = self._run_kensa(el8_container, ["detect"])
        assert (
            result.returncode == 0
        ), f"detect failed on el8: {result.stderr}\n{result.stdout}"
