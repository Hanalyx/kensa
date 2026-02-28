"""SpecDerived tests for detect_capability module."""

from __future__ import annotations

from runner.detect import (
    CAPABILITY_PROBES,
    RHEL_FAMILY,
    PlatformInfo,
    detect_capabilities,
    detect_platform,
)
from runner.ssh import Result


class TestDetectCapabilitySpecDerived:
    """Spec-derived tests for detect_capability.

    See specs/internal/detect_capability.spec.yaml for specification.
    """

    def test_ac1_detect_platform_reads_os_release(self, mock_ssh):
        """AC-1: detect_platform reads /etc/os-release and returns PlatformInfo(family, version, version_id)."""
        ssh = mock_ssh(
            {
                "cat /etc/os-release": Result(
                    exit_code=0,
                    stdout='ID=rhel\nVERSION_ID="9.3"\nNAME="Red Hat Enterprise Linux"',
                    stderr="",
                ),
            }
        )
        platform = detect_platform(ssh)
        assert platform is not None
        assert isinstance(platform, PlatformInfo)
        assert platform.family == "rhel"
        assert platform.version == 9
        assert platform.version_id == "9.3"

    def test_ac2_rhel_derivatives_normalized(self, mock_ssh):
        """AC-2: RHEL derivatives (centos, rocky, almalinux, ol) normalized to 'rhel'."""
        for os_id in ("centos", "rocky", "almalinux", "ol"):
            ssh = mock_ssh(
                {
                    "cat /etc/os-release": Result(
                        exit_code=0,
                        stdout=f'ID={os_id}\nVERSION_ID="9.2"',
                        stderr="",
                    ),
                }
            )
            platform = detect_platform(ssh)
            assert platform is not None, f"Failed for {os_id}"
            assert platform.family == "rhel", f"{os_id} not normalized to 'rhel'"

        # Verify the RHEL_FAMILY set contains all expected IDs
        assert {"rhel", "centos", "rocky", "almalinux", "ol"} == RHEL_FAMILY

    def test_ac3_fallback_to_redhat_release_then_debian_version(self, mock_ssh):
        """AC-3: Fallback to /etc/redhat-release then /etc/debian_version."""
        # Fallback to /etc/redhat-release
        ssh = mock_ssh(
            {
                "cat /etc/os-release": Result(exit_code=1, stdout="", stderr=""),
                "cat /etc/redhat-release": Result(
                    exit_code=0,
                    stdout="CentOS Linux release 7.9.2009 (Core)",
                    stderr="",
                ),
            }
        )
        platform = detect_platform(ssh)
        assert platform is not None
        assert platform.family == "rhel"
        assert platform.version == 7
        assert platform.version_id == "7.9.2009"

        # Fallback to /etc/debian_version
        ssh2 = mock_ssh(
            {
                "cat /etc/os-release": Result(exit_code=1, stdout="", stderr=""),
                "cat /etc/redhat-release": Result(exit_code=1, stdout="", stderr=""),
                "cat /etc/debian_version": Result(
                    exit_code=0,
                    stdout="12.1",
                    stderr="",
                ),
            }
        )
        platform2 = detect_platform(ssh2)
        assert platform2 is not None
        assert platform2.family == "debian"
        assert platform2.version == 12
        assert platform2.version_id == "12.1"

    def test_ac4_all_detection_methods_fail_returns_none(self, mock_ssh):
        """AC-4: When all detection methods fail, returns None."""
        ssh = mock_ssh(
            {
                "cat /etc/os-release": Result(exit_code=1, stdout="", stderr=""),
                "cat /etc/redhat-release": Result(exit_code=1, stdout="", stderr=""),
                "cat /etc/debian_version": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        platform = detect_platform(ssh)
        assert platform is None

    def test_ac5_detect_capabilities_runs_all_probes(self, mock_ssh):
        """AC-5: detect_capabilities runs all 22 CAPABILITY_PROBES and returns dict[str, bool]."""
        # Create responses for all probes: half succeed, half fail
        responses = {}
        probe_names = list(CAPABILITY_PROBES.keys())
        for i, name in enumerate(probe_names):
            cmd = CAPABILITY_PROBES[name]
            responses[cmd] = Result(
                exit_code=0 if i % 2 == 0 else 1,
                stdout="",
                stderr="" if i % 2 == 0 else "not found",
            )

        ssh = mock_ssh(responses)
        caps = detect_capabilities(ssh)

        assert isinstance(caps, dict)
        assert len(caps) == 22
        assert all(isinstance(v, bool) for v in caps.values())
        # All probe names present
        for name in CAPABILITY_PROBES:
            assert name in caps

    def test_ac6_exit_code_zero_is_true_nonzero_is_false(self, mock_ssh):
        """AC-6: Exit code 0 = True, non-zero = False."""
        responses = {}
        for probe_name, cmd in CAPABILITY_PROBES.items():
            # Make "tmux" succeed and everything else fail
            if probe_name == "tmux":
                responses[cmd] = Result(exit_code=0, stdout="", stderr="")
            else:
                responses[cmd] = Result(exit_code=127, stdout="", stderr="not found")

        ssh = mock_ssh(responses)
        caps = detect_capabilities(ssh)

        assert caps["tmux"] is True
        assert caps["authselect"] is False

    def test_ac7_verbose_prints_failed_probes(self, mock_ssh, capsys):
        """AC-7: When verbose=True, failed probes print debug info."""
        responses = {}
        for _name, cmd in CAPABILITY_PROBES.items():
            responses[cmd] = Result(exit_code=1, stdout="", stderr="error msg")

        ssh = mock_ssh(responses)
        detect_capabilities(ssh, verbose=True)

        captured = capsys.readouterr()
        # Debug info goes to stderr
        assert "[probe]" in captured.err
        # Should mention at least one probe name
        assert "tmux" in captured.err or "authselect" in captured.err

    def test_ac8_probes_are_independent(self, mock_ssh):
        """AC-8: Probes are independent; failure in one doesn't affect others."""
        responses = {}
        probe_names = list(CAPABILITY_PROBES.keys())
        # First probe fails, second succeeds, rest fail
        for i, name in enumerate(probe_names):
            cmd = CAPABILITY_PROBES[name]
            if i == 1:
                responses[cmd] = Result(exit_code=0, stdout="ok", stderr="")
            else:
                responses[cmd] = Result(exit_code=1, stdout="", stderr="fail")

        ssh = mock_ssh(responses)
        caps = detect_capabilities(ssh)

        # The second probe should still succeed despite others failing
        assert caps[probe_names[1]] is True
        assert caps[probe_names[0]] is False
        # All 22 probes still executed
        assert len(caps) == 22

    def test_ac9_twenty_two_probes_cover_documented_set(self):
        """AC-9: 22 probes cover the documented set."""
        expected_probes = {
            "sshd_config_d",
            "authselect",
            "authselect_sssd",
            "crypto_policies",
            "crypto_policy_modules",
            "fips_mode",
            "firewalld_nftables",
            "firewalld_iptables",
            "systemd_resolved",
            "pam_faillock",
            "grub_bls",
            "grub_legacy",
            "journald_primary",
            "rsyslog_active",
            "fapolicyd",
            "selinux",
            "aide",
            "tpm2",
            "usbguard",
            "dnf_automatic",
            "gdm",
            "tmux",
        }
        assert len(CAPABILITY_PROBES) == 22
        assert set(CAPABILITY_PROBES.keys()) == expected_probes

    def test_ac10_version_id_dotted_parsing(self, mock_ssh):
        """AC-10: VERSION_ID parsing preserves full string as version_id, extracts major as int."""
        ssh = mock_ssh(
            {
                "cat /etc/os-release": Result(
                    exit_code=0,
                    stdout='ID=rhel\nVERSION_ID="9.3"',
                    stderr="",
                ),
            }
        )
        platform = detect_platform(ssh)
        assert platform is not None
        assert platform.version == 9
        assert isinstance(platform.version, int)
        assert platform.version_id == "9.3"

        # Also test without quotes around VERSION_ID
        ssh2 = mock_ssh(
            {
                "cat /etc/os-release": Result(
                    exit_code=0,
                    stdout="ID=ubuntu\nVERSION_ID=22.04",
                    stderr="",
                ),
            }
        )
        platform2 = detect_platform(ssh2)
        assert platform2 is not None
        assert platform2.family == "ubuntu"
        assert platform2.version == 22
        assert platform2.version_id == "22.04"
