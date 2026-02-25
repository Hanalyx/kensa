"""SpecDerived tests for risk classification module."""

from __future__ import annotations

from runner.risk import (
    classify_step_risk,
    should_capture,
)


class TestRiskClassificationSpecDerived:
    """Spec-derived tests for risk classification.

    See specs/internal/risk_classification.spec.yaml for specification.
    """

    def test_ac1_base_risk_from_mechanism_risk(self):
        """AC-1: classify_step_risk returns base risk from MECHANISM_RISK for known mechanism."""
        # grub_parameter_set is mapped to "high"
        assert classify_step_risk("grub_parameter_set", {}) == "high"
        # config_set is mapped to "medium"
        assert classify_step_risk("config_set", {}) == "medium"
        # file_permissions is mapped to "low"
        assert classify_step_risk("file_permissions", {}) == "low"
        # command_exec is mapped to "na"
        assert classify_step_risk("command_exec", {}) == "na"

    def test_ac2_unknown_mechanism_defaults_to_medium(self):
        """AC-2: Unknown mechanisms default to 'medium' risk."""
        assert classify_step_risk("totally_unknown_mechanism", {}) == "medium"
        assert classify_step_risk("", {}) == "medium"

    def test_ac3_high_risk_paths_escalate_to_high(self):
        """AC-3: Paths matching HIGH_RISK_PATHS escalate to 'high'."""
        # file_permissions is base "low", but /etc/pam.d/ prefix escalates to "high"
        assert (
            classify_step_risk("file_permissions", {"path": "/etc/pam.d/su"}) == "high"
        )
        # Exact match: /etc/fstab
        assert classify_step_risk("file_permissions", {"path": "/etc/fstab"}) == "high"
        # /etc/default/grub exact match
        assert (
            classify_step_risk("service_enabled", {"path": "/etc/default/grub"})
            == "high"
        )

    def test_ac4_medium_risk_paths_escalate_to_medium(self):
        """AC-4: Paths matching MEDIUM_RISK_PATHS escalate to 'medium' if base is lower."""
        # file_permissions is base "low"; /etc/ssh/sshd_config escalates to "medium"
        assert (
            classify_step_risk("file_permissions", {"path": "/etc/ssh/sshd_config"})
            == "medium"
        )
        # /etc/security/ directory prefix
        assert (
            classify_step_risk(
                "file_permissions", {"path": "/etc/security/limits.conf"}
            )
            == "medium"
        )

    def test_ac5_effective_risk_is_max(self):
        """AC-5: Effective risk is max(mechanism_risk, path_risk) using RISK_LEVELS ordering."""
        # config_set is "medium", /etc/pam.d/ escalates to "high" -> max is "high"
        assert (
            classify_step_risk("config_set", {"path": "/etc/pam.d/system-auth"})
            == "high"
        )
        # grub_parameter_set is "high", /etc/ssh/sshd_config path is "medium" -> max stays "high"
        assert (
            classify_step_risk("grub_parameter_set", {"path": "/etc/ssh/sshd_config"})
            == "high"
        )
        # file_permissions is "low", no path -> stays "low"
        assert (
            classify_step_risk("file_permissions", {"path": "/tmp/harmless"}) == "low"
        )

    def test_ac6_path_extraction_fallback(self):
        """AC-6: Path extracted from 'path' key, falling back to 'file' key, default empty."""
        # "path" key is used first
        assert classify_step_risk("file_permissions", {"path": "/etc/fstab"}) == "high"
        # Falls back to "file" key when "path" is absent
        assert classify_step_risk("file_permissions", {"file": "/etc/fstab"}) == "high"
        # Default empty when neither key present — no path escalation
        assert classify_step_risk("file_permissions", {}) == "low"
        # "path" takes priority over "file"
        assert (
            classify_step_risk(
                "file_permissions", {"path": "/etc/fstab", "file": "/tmp/safe"}
            )
            == "high"
        )

    def test_ac7_should_capture_none_mode(self):
        """AC-7: should_capture returns False when snapshot_mode is 'none'."""
        assert should_capture("grub_parameter_set", {}, snapshot_mode="none") is False
        assert (
            should_capture("config_set", {"path": "/etc/fstab"}, snapshot_mode="none")
            is False
        )

    def test_ac8_should_capture_all_mode(self):
        """AC-8: should_capture returns True when snapshot_mode is 'all'."""
        assert should_capture("grub_parameter_set", {}, snapshot_mode="all") is True
        assert should_capture("file_permissions", {}, snapshot_mode="all") is True
        assert should_capture("command_exec", {}, snapshot_mode="all") is True

    def test_ac9_risk_based_mode_threshold(self):
        """AC-9: In 'risk_based' mode, returns True only when risk >= threshold."""
        # "high" >= "medium" threshold -> True
        assert (
            should_capture(
                "grub_parameter_set",
                {},
                snapshot_mode="risk_based",
                risk_threshold="medium",
            )
            is True
        )
        # "medium" >= "medium" threshold -> True
        assert (
            should_capture(
                "config_set", {}, snapshot_mode="risk_based", risk_threshold="medium"
            )
            is True
        )
        # "low" < "medium" threshold -> False
        assert (
            should_capture(
                "file_permissions",
                {},
                snapshot_mode="risk_based",
                risk_threshold="medium",
            )
            is False
        )
        # "low" >= "low" threshold -> True
        assert (
            should_capture(
                "file_permissions", {}, snapshot_mode="risk_based", risk_threshold="low"
            )
            is True
        )
        # "high" threshold: only "high" passes
        assert (
            should_capture(
                "config_set", {}, snapshot_mode="risk_based", risk_threshold="high"
            )
            is False
        )
        assert (
            should_capture(
                "grub_parameter_set",
                {},
                snapshot_mode="risk_based",
                risk_threshold="high",
            )
            is True
        )

    def test_ac10_na_risk_always_false_in_risk_based(self):
        """AC-10: Returns False for 'na' risk in risk_based mode regardless of threshold."""
        assert (
            should_capture(
                "command_exec", {}, snapshot_mode="risk_based", risk_threshold="low"
            )
            is False
        )
        assert (
            should_capture(
                "manual", {}, snapshot_mode="risk_based", risk_threshold="low"
            )
            is False
        )
        assert (
            should_capture(
                "command_exec", {}, snapshot_mode="risk_based", risk_threshold="medium"
            )
            is False
        )
