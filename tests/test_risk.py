"""Tests for Phase 7: Risk classification for snapshot policy."""

from __future__ import annotations

import pytest

from runner.risk import (
    HIGH_RISK_PATHS,
    MECHANISM_RISK,
    MEDIUM_RISK_PATHS,
    classify_step_risk,
    should_capture,
)


class TestMechanismRisk:
    """Test base risk classification by mechanism type."""

    @pytest.mark.parametrize(
        "mechanism",
        [
            "grub_parameter_set",
            "grub_parameter_remove",
            "mount_option_set",
            "pam_module_configure",
            "kernel_module_disable",
        ],
    )
    def test_high_risk_mechanisms(self, mechanism):
        assert MECHANISM_RISK[mechanism] == "high"

    @pytest.mark.parametrize(
        "mechanism",
        [
            "config_set",
            "config_set_dropin",
            "config_block",
            "config_remove",
            "sysctl_set",
            "service_masked",
            "service_disabled",
            "audit_rule_set",
            "selinux_boolean_set",
            "file_content",
        ],
    )
    def test_medium_risk_mechanisms(self, mechanism):
        assert MECHANISM_RISK[mechanism] == "medium"

    @pytest.mark.parametrize(
        "mechanism",
        [
            "file_permissions",
            "package_present",
            "package_absent",
            "service_enabled",
            "cron_job",
            "file_absent",
        ],
    )
    def test_low_risk_mechanisms(self, mechanism):
        assert MECHANISM_RISK[mechanism] == "low"

    @pytest.mark.parametrize("mechanism", ["command_exec", "manual"])
    def test_na_mechanisms(self, mechanism):
        assert MECHANISM_RISK[mechanism] == "na"

    def test_all_25_mechanisms_classified(self):
        """All 25 known mechanisms have a risk classification."""
        assert len(MECHANISM_RISK) == 25


class TestClassifyStepRisk:
    """Test classify_step_risk with mechanism + path escalation."""

    def test_basic_mechanism_risk(self):
        assert classify_step_risk("config_set", {}) == "medium"
        assert classify_step_risk("file_permissions", {}) == "low"
        assert classify_step_risk("grub_parameter_set", {}) == "high"

    def test_path_escalation_to_high(self):
        """PAM path escalates config_set from medium to high."""
        assert (
            classify_step_risk("config_set", {"path": "/etc/pam.d/system-auth"})
            == "high"
        )

    def test_fstab_escalation(self):
        assert classify_step_risk("config_set", {"path": "/etc/fstab"}) == "high"

    def test_crypttab_escalation(self):
        assert classify_step_risk("config_set", {"path": "/etc/crypttab"}) == "high"

    def test_grub_config_escalation(self):
        assert classify_step_risk("config_set", {"path": "/etc/default/grub"}) == "high"

    def test_selinux_config_escalation(self):
        assert (
            classify_step_risk("config_set", {"path": "/etc/selinux/config"}) == "high"
        )

    def test_sshd_config_medium_min(self):
        """SSH config path ensures at least medium risk."""
        # file_permissions is low, but sshd_config escalates to medium
        assert (
            classify_step_risk("file_permissions", {"path": "/etc/ssh/sshd_config"})
            == "medium"
        )

    def test_security_dir_medium_min(self):
        """Security dir path ensures at least medium risk."""
        assert (
            classify_step_risk(
                "file_permissions", {"path": "/etc/security/limits.conf"}
            )
            == "medium"
        )

    def test_no_path_uses_mechanism_risk(self):
        assert classify_step_risk("config_set", {}) == "medium"

    def test_file_key_used_as_path(self):
        """Remediation dict may use 'file' instead of 'path'."""
        assert (
            classify_step_risk("file_permissions", {"file": "/etc/pam.d/password-auth"})
            == "high"
        )

    def test_high_mechanism_stays_high_regardless_of_path(self):
        """High-risk mechanism stays high even with a benign path."""
        assert (
            classify_step_risk("grub_parameter_set", {"path": "/some/random/file"})
            == "high"
        )

    def test_medium_not_downgraded_by_path(self):
        """Path can escalate but not downgrade risk."""
        assert classify_step_risk("config_set", {"path": "/etc/some.conf"}) == "medium"

    def test_unknown_mechanism_defaults_medium(self):
        assert classify_step_risk("unknown_mechanism", {}) == "medium"

    def test_extra_high_risk_paths(self):
        """Custom high_risk_paths are respected."""
        assert (
            classify_step_risk(
                "config_set",
                {"path": "/etc/custom/important.conf"},
                extra_high_risk=["/etc/custom/"],
            )
            == "high"
        )


class TestShouldCapture:
    """Test should_capture decision logic."""

    def test_mode_all_always_captures(self):
        assert should_capture("file_permissions", {}, snapshot_mode="all") is True
        assert should_capture("command_exec", {}, snapshot_mode="all") is True

    def test_mode_none_never_captures(self):
        assert should_capture("grub_parameter_set", {}, snapshot_mode="none") is False

    def test_risk_based_threshold_medium(self):
        """With threshold=medium, captures medium and high, skips low and na."""
        assert (
            should_capture(
                "grub_parameter_set",
                {},
                snapshot_mode="risk_based",
                risk_threshold="medium",
            )
            is True
        )
        assert (
            should_capture(
                "config_set",
                {},
                snapshot_mode="risk_based",
                risk_threshold="medium",
            )
            is True
        )
        assert (
            should_capture(
                "file_permissions",
                {},
                snapshot_mode="risk_based",
                risk_threshold="medium",
            )
            is False
        )
        assert (
            should_capture(
                "command_exec",
                {},
                snapshot_mode="risk_based",
                risk_threshold="medium",
            )
            is False
        )

    def test_risk_based_threshold_high(self):
        """With threshold=high, captures only high risk."""
        assert (
            should_capture(
                "grub_parameter_set",
                {},
                snapshot_mode="risk_based",
                risk_threshold="high",
            )
            is True
        )
        assert (
            should_capture(
                "config_set",
                {},
                snapshot_mode="risk_based",
                risk_threshold="high",
            )
            is False
        )

    def test_risk_based_threshold_low(self):
        """With threshold=low, captures low, medium, and high."""
        assert (
            should_capture(
                "file_permissions",
                {},
                snapshot_mode="risk_based",
                risk_threshold="low",
            )
            is True
        )
        assert (
            should_capture(
                "command_exec",
                {},
                snapshot_mode="risk_based",
                risk_threshold="low",
            )
            is False
        )

    def test_risk_based_with_path_escalation(self):
        """Path escalation can promote a low-risk step above threshold."""
        # file_permissions is low, but /etc/pam.d/ escalates to high
        assert (
            should_capture(
                "file_permissions",
                {"path": "/etc/pam.d/system-auth"},
                snapshot_mode="risk_based",
                risk_threshold="medium",
            )
            is True
        )


class TestBuiltInPaths:
    """Verify the built-in path lists are correct."""

    def test_high_risk_paths(self):
        assert "/etc/pam.d/" in HIGH_RISK_PATHS
        assert "/etc/fstab" in HIGH_RISK_PATHS
        assert "/etc/crypttab" in HIGH_RISK_PATHS
        assert "/etc/default/grub" in HIGH_RISK_PATHS
        assert "/etc/selinux/config" in HIGH_RISK_PATHS

    def test_medium_risk_paths(self):
        assert "/etc/ssh/sshd_config" in MEDIUM_RISK_PATHS
        assert "/etc/security/" in MEDIUM_RISK_PATHS
