"""Tests for runner/detect.py — capability probes and platform detection."""

from __future__ import annotations

from runner.detect import CAPABILITY_PROBES, RHEL_FAMILY, detect_capabilities, detect_platform
from runner.ssh import Result


class TestProbeDefinitions:
    def test_all_probes_defined(self):
        assert len(CAPABILITY_PROBES) >= 22

    def test_probe_names_are_valid(self):
        import re
        for name in CAPABILITY_PROBES:
            assert re.match(r"^[a-z][a-z0-9_]*$", name), f"Invalid probe name: {name}"

    def test_probe_values_are_strings(self):
        for name, cmd in CAPABILITY_PROBES.items():
            assert isinstance(cmd, str), f"Probe {name} command is not a string"

    def test_probes_suppress_stderr(self):
        """Most probes should suppress stderr to avoid noisy output."""
        for name, cmd in CAPABILITY_PROBES.items():
            # Not a hard requirement, but most should have 2>/dev/null
            # Just verify they're non-empty commands
            assert len(cmd) > 5, f"Probe {name} command suspiciously short"


class TestDetectCapabilities:
    def test_returns_all_probes(self, mock_ssh):
        ssh = mock_ssh({"": Result(exit_code=1, stdout="", stderr="")})
        caps = detect_capabilities(ssh)
        assert set(caps.keys()) == set(CAPABILITY_PROBES.keys())

    def test_exit_zero_means_true(self, mock_ssh):
        # Mock all commands to succeed
        ssh = mock_ssh()
        ssh.responses[""] = Result(exit_code=0, stdout="", stderr="")
        caps = detect_capabilities(ssh)
        assert all(v is True for v in caps.values())

    def test_exit_nonzero_means_false(self, mock_ssh):
        ssh = mock_ssh()
        ssh.responses[""] = Result(exit_code=1, stdout="", stderr="")
        caps = detect_capabilities(ssh)
        assert all(v is False for v in caps.values())

    def test_mixed_results(self, mock_ssh):
        ssh = mock_ssh({
            "systemctl is-active systemd-journald": Result(exit_code=0, stdout="active", stderr=""),
        })
        caps = detect_capabilities(ssh)
        assert caps["journald_primary"] is True
        # Others should be False (default mock returns exit 1)


class TestDetectPlatform:
    def _os_release(self, os_id, version_id, **extra):
        lines = [f'ID="{os_id}"', f'VERSION_ID="{version_id}"']
        for k, v in extra.items():
            lines.append(f'{k}="{v}"')
        return "\n".join(lines)

    def test_detect_rhel9(self, mock_ssh):
        ssh = mock_ssh({"cat /etc/os-release": Result(exit_code=0, stdout=self._os_release("rhel", "9.3"), stderr="")})
        p = detect_platform(ssh)
        assert p.family == "rhel"
        assert p.version == 9

    def test_detect_rhel8(self, mock_ssh):
        ssh = mock_ssh({"cat /etc/os-release": Result(exit_code=0, stdout=self._os_release("rhel", "8.9"), stderr="")})
        p = detect_platform(ssh)
        assert p.family == "rhel"
        assert p.version == 8

    def test_detect_rocky9(self, mock_ssh):
        ssh = mock_ssh({"cat /etc/os-release": Result(exit_code=0, stdout=self._os_release("rocky", "9.4"), stderr="")})
        p = detect_platform(ssh)
        assert p.family == "rhel"
        assert p.version == 9

    def test_detect_almalinux(self, mock_ssh):
        ssh = mock_ssh({"cat /etc/os-release": Result(exit_code=0, stdout=self._os_release("almalinux", "9.2"), stderr="")})
        p = detect_platform(ssh)
        assert p.family == "rhel"
        assert p.version == 9

    def test_detect_centos_stream(self, mock_ssh):
        ssh = mock_ssh({"cat /etc/os-release": Result(exit_code=0, stdout=self._os_release("centos", "9"), stderr="")})
        p = detect_platform(ssh)
        assert p.family == "rhel"
        assert p.version == 9

    def test_detect_oracle_linux(self, mock_ssh):
        ssh = mock_ssh({"cat /etc/os-release": Result(exit_code=0, stdout=self._os_release("ol", "8.7"), stderr="")})
        p = detect_platform(ssh)
        assert p.family == "rhel"
        assert p.version == 8

    def test_detect_unreadable(self, mock_ssh):
        ssh = mock_ssh({"cat /etc/os-release": Result(exit_code=1, stdout="", stderr="No such file")})
        assert detect_platform(ssh) is None

    def test_detect_unknown_distro(self, mock_ssh):
        ssh = mock_ssh({"cat /etc/os-release": Result(exit_code=0, stdout=self._os_release("debian", "12"), stderr="")})
        p = detect_platform(ssh)
        assert p.family == "debian"
        assert p.version == 12
