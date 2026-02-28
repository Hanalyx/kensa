"""SpecDerived tests for host_runner orchestration."""

from __future__ import annotations

from collections import namedtuple
from io import StringIO
from unittest.mock import MagicMock, patch

from rich.console import Console

from runner._host_runner import (
    ControlContext,
    HostCheckResult,
    HostRemediateResult,
    HostRunConfig,
    execute_on_host,
)
from runner._types import RuleResult
from runner.inventory import HostInfo

PlatformInfo = namedtuple("PlatformInfo", ["family", "version", "version_id"])


def _quiet_console() -> Console:
    """Return a Console that captures output to a StringIO."""
    return Console(file=StringIO(), highlight=False)


def _make_rule(
    rule_id: str,
    *,
    title: str = "",
    platforms: list | None = None,
    depends_on: list | None = None,
) -> dict:
    """Build a minimal rule dict."""
    rule: dict = {
        "id": rule_id,
        "title": title or rule_id,
        "severity": "medium",
        "category": "test",
        "implementations": [
            {
                "default": True,
                "check": {"method": "command", "run": "true", "expected_exit": 0},
            }
        ],
    }
    if platforms is not None:
        rule["platforms"] = platforms
    if depends_on is not None:
        rule["depends_on"] = depends_on
    return rule


def _pass_result(rule_id: str) -> RuleResult:
    return RuleResult(rule_id=rule_id, title=rule_id, severity="medium", passed=True)


def _fail_result(rule_id: str) -> RuleResult:
    return RuleResult(
        rule_id=rule_id, title=rule_id, severity="medium", passed=False, detail="failed"
    )


def _skip_result(rule_id: str, reason: str = "no implementation") -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        title=rule_id,
        severity="medium",
        passed=False,
        skipped=True,
        skip_reason=reason,
    )


def _remediate_pass_result(rule_id: str) -> RuleResult:
    return RuleResult(
        rule_id=rule_id, title=rule_id, severity="medium", passed=True, remediated=False
    )


def _remediate_fixed_result(rule_id: str) -> RuleResult:
    return RuleResult(
        rule_id=rule_id, title=rule_id, severity="medium", passed=True, remediated=True
    )


def _remediate_fail_result(rule_id: str, *, rolled_back: bool = False) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        title=rule_id,
        severity="medium",
        passed=False,
        remediated=True,
        rolled_back=rolled_back,
    )


# Shared patches for the module under test
_PATCH_BASE = "runner._host_runner"


class TestHostRunnerSpecDerived:
    """Spec-derived tests for host_runner orchestration.

    See specs/orchestration/host_runner.spec.yaml for specification.
    """

    def _make_hi(self, hostname: str = "test-host") -> HostInfo:
        return HostInfo(
            hostname=hostname, port=22, user="root", key_path=None, groups=[]
        )

    def _make_config(self, mode: str = "check", **kwargs) -> HostRunConfig:
        return HostRunConfig(mode=mode, **kwargs)

    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac1_ssh_connection_context_manager(
        self, mock_connect, mock_platform, mock_caps
    ):
        """AC-1: execute_on_host establishes SSH connection using HostInfo credentials and closes it on completion (context manager)."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {"sshd_config_d": True}

        hi = self._make_hi()
        config = self._make_config("check")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=True,
            strict_host_keys=False,
            rule_list=[],
            config=config,
            out=out,
        )

        # Verify connect was called with correct HostInfo parameters
        mock_connect.assert_called_once_with(
            hi, None, sudo=True, strict_host_keys=False
        )
        # Verify context manager protocol was used (enter and exit called)
        mock_ssh.__enter__.assert_called_once()
        mock_ssh.__exit__.assert_called_once()
        assert result.success is True

    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac2_platform_detection_before_evaluation(
        self, mock_connect, mock_platform, mock_caps
    ):
        """AC-2: Platform detection via detect_platform(ssh) runs before rule evaluation; result is stored on the returned result."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        platform = PlatformInfo("rhel", 9, "9.3")
        mock_platform.return_value = platform
        mock_caps.return_value = {}

        hi = self._make_hi()
        config = self._make_config("check")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=[],
            config=config,
            out=out,
        )

        mock_platform.assert_called_once_with(mock_ssh)
        assert result.platform is platform

    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac3_capability_detection_with_overrides(
        self, mock_connect, mock_platform, mock_caps
    ):
        """AC-3: Capability detection via detect_capabilities(ssh) runs before rule evaluation; manual overrides from config.capability_overrides are applied on top."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {"sshd_config_d": True, "authselect": False}

        hi = self._make_hi()
        config = self._make_config("check", capability_overrides={"authselect": True})
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=[],
            config=config,
            out=out,
        )

        mock_caps.assert_called_once_with(mock_ssh, verbose=False)
        # authselect should be overridden to True
        assert result.capabilities["authselect"] is True
        # sshd_config_d should remain as detected
        assert result.capabilities["sshd_config_d"] is True

    @patch(f"{_PATCH_BASE}.platform_filter_control_rules")
    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac4_control_ctx_platform_filtering(
        self, mock_connect, mock_platform, mock_caps, mock_filter
    ):
        """AC-4: When config.control_ctx is set and platform is detected, rules are narrowed to platform-applicable mappings via platform_filter_control_rules()."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        platform = PlatformInfo("rhel", 9, "9.3")
        mock_platform.return_value = platform
        mock_caps.return_value = {}

        rule_a = _make_rule("rule-a")
        rule_b = _make_rule("rule-b")
        control_ctx = ControlContext(
            control="cis:1.1.1", mappings={}, index=MagicMock()
        )

        # platform_filter_control_rules returns only rule_a
        mock_filter.return_value = [rule_a]

        hi = self._make_hi()
        config = self._make_config("check", control_ctx=control_ctx)
        out = _quiet_console()

        with patch(f"{_PATCH_BASE}.run_checks") as mock_run_checks:
            mock_run_checks.return_value = (0, 0, 0, [])
            execute_on_host(
                hi,
                None,
                sudo=False,
                strict_host_keys=False,
                rule_list=[rule_a, rule_b],
                config=config,
                out=out,
            )

        mock_filter.assert_called_once_with([rule_a, rule_b], control_ctx, platform)
        # run_checks should receive the filtered list
        call_args = mock_run_checks.call_args
        assert call_args[0][1] == [rule_a]

    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac5_variable_resolution(self, mock_connect, mock_platform, mock_caps):
        """AC-5: When config.rule_config is set, per-host variable resolution is applied using resolve_variables with hostname and groups from HostInfo."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {}

        rule = _make_rule("rule-a")
        mock_rule_config = MagicMock()

        hi = HostInfo(
            hostname="web01",
            port=22,
            user="root",
            key_path=None,
            groups=["web", "prod"],
        )
        config = self._make_config(
            "check",
            rule_config=mock_rule_config,
            framework="cis",
            cli_overrides={"key": "val"},
        )
        out = _quiet_console()

        with (
            patch("runner._config.resolve_variables") as mock_resolve,
            patch(f"{_PATCH_BASE}.run_checks") as mock_run_checks,
        ):
            mock_resolve.return_value = rule
            mock_run_checks.return_value = (0, 0, 0, [])
            execute_on_host(
                hi,
                None,
                sudo=False,
                strict_host_keys=False,
                rule_list=[rule],
                config=config,
                out=out,
            )

        mock_resolve.assert_called_once_with(
            rule,
            mock_rule_config,
            framework="cis",
            cli_overrides={"key": "val"},
            hostname="web01",
            groups=["web", "prod"],
            strict=True,
        )

    @patch(f"{_PATCH_BASE}.evaluate_rule")
    @patch(f"{_PATCH_BASE}.should_skip_rule")
    @patch(f"{_PATCH_BASE}.rule_applies_to_platform")
    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac6_check_mode_evaluates_rules(
        self,
        mock_connect,
        mock_platform,
        mock_caps,
        mock_platform_check,
        mock_skip,
        mock_eval,
    ):
        """AC-6: In check mode, run_checks iterates rules: skips if should_skip_rule, skips if platform doesn't match, otherwise calls evaluate_rule."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {"sshd_config_d": True}

        rule_a = _make_rule("rule-a")
        rule_b = _make_rule("rule-b")
        rule_c = _make_rule("rule-c")

        # rule-a: should_skip_rule returns True (dependency failure)
        # rule-b: should_skip_rule False, platform doesn't match
        # rule-c: should_skip_rule False, platform matches, evaluate_rule called
        mock_skip.side_effect = [
            (True, "depends on rule-x which failed"),
            (False, ""),
            (False, ""),
        ]
        mock_platform_check.side_effect = [False, True]
        mock_eval.return_value = _pass_result("rule-c")

        hi = self._make_hi()
        config = self._make_config("check")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=[rule_a, rule_b, rule_c],
            config=config,
            out=out,
        )

        assert isinstance(result, HostCheckResult)
        # evaluate_rule called only for rule-c
        mock_eval.assert_called_once()
        assert mock_eval.call_args[0][1] == rule_c

    @patch(f"{_PATCH_BASE}.remediate_rule")
    @patch(f"{_PATCH_BASE}.should_skip_rule")
    @patch(f"{_PATCH_BASE}.rule_applies_to_platform")
    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac7_remediate_mode_calls_remediate_rule(
        self,
        mock_connect,
        mock_platform,
        mock_caps,
        mock_platform_check,
        mock_skip,
        mock_remediate,
    ):
        """AC-7: In remediate mode, similarly but calls remediate_rule."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {}

        rule = _make_rule("rule-a")
        mock_skip.return_value = (False, "")
        mock_platform_check.return_value = True
        mock_remediate.return_value = _remediate_fixed_result("rule-a")

        hi = self._make_hi()
        config = self._make_config(
            "remediate", dry_run=True, rollback_on_failure=True, snapshot=False
        )
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=[rule],
            config=config,
            out=out,
        )

        assert isinstance(result, HostRemediateResult)
        mock_remediate.assert_called_once()
        call_kwargs = mock_remediate.call_args
        assert call_kwargs[1]["dry_run"] is True
        assert call_kwargs[1]["rollback_on_failure"] is True
        assert call_kwargs[1]["snapshot"] is False

    @patch(f"{_PATCH_BASE}.should_skip_rule")
    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac8_skipped_rules_have_skip_reason(
        self, mock_connect, mock_platform, mock_caps, mock_skip
    ):
        """AC-8: Skipped rules produce RuleResult with skipped=True and appropriate skip_reason."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {}

        rule = _make_rule("rule-a", depends_on=["rule-x"])
        mock_skip.return_value = (True, "depends on rule-x which failed")

        hi = self._make_hi()
        config = self._make_config("check")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=[rule],
            config=config,
            out=out,
        )

        assert len(result.rule_results) == 1
        rr = result.rule_results[0]
        assert rr.skipped is True
        assert "rule-x" in rr.skip_reason

    @patch(f"{_PATCH_BASE}.connect")
    def test_ac9_connection_failure_returns_error(self, mock_connect):
        """AC-9: Connection failure returns a result with success=False and error message; no rules are evaluated."""
        mock_connect.side_effect = ConnectionError("SSH timeout")

        hi = self._make_hi()
        config = self._make_config("check")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=[_make_rule("rule-a")],
            config=config,
            out=out,
        )

        assert isinstance(result, HostCheckResult)
        assert result.success is False
        assert "SSH timeout" in result.error
        assert result.rule_results == []

    @patch(f"{_PATCH_BASE}.connect")
    def test_ac9_connection_failure_remediate_mode(self, mock_connect):
        """AC-9: Connection failure in remediate mode returns HostRemediateResult with success=False."""
        mock_connect.side_effect = OSError("Connection refused")

        hi = self._make_hi()
        config = self._make_config("remediate")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=[],
            config=config,
            out=out,
        )

        assert isinstance(result, HostRemediateResult)
        assert result.success is False
        assert "Connection refused" in result.error

    @patch(f"{_PATCH_BASE}.evaluate_rule")
    @patch(f"{_PATCH_BASE}.should_skip_rule")
    @patch(f"{_PATCH_BASE}.rule_applies_to_platform")
    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac10_check_mode_returns_counts(
        self,
        mock_connect,
        mock_platform,
        mock_caps,
        mock_platform_check,
        mock_skip,
        mock_eval,
    ):
        """AC-10: Check mode returns HostCheckResult with pass_count, fail_count, skip_count."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {}

        rules = [_make_rule(f"rule-{i}") for i in range(4)]

        # rule-0: skip (dependency), rule-1: pass, rule-2: fail, rule-3: pass
        mock_skip.side_effect = [
            (True, "dep failed"),
            (False, ""),
            (False, ""),
            (False, ""),
        ]
        mock_platform_check.side_effect = [True, True, True]
        mock_eval.side_effect = [
            _pass_result("rule-1"),
            _fail_result("rule-2"),
            _pass_result("rule-3"),
        ]

        hi = self._make_hi()
        config = self._make_config("check")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=rules,
            config=config,
            out=out,
        )

        assert isinstance(result, HostCheckResult)
        assert result.pass_count == 2
        assert result.fail_count == 1
        assert result.skip_count == 1
        assert result.success is True

    @patch(f"{_PATCH_BASE}.remediate_rule")
    @patch(f"{_PATCH_BASE}.should_skip_rule")
    @patch(f"{_PATCH_BASE}.rule_applies_to_platform")
    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac11_remediate_mode_returns_counts(
        self,
        mock_connect,
        mock_platform,
        mock_caps,
        mock_platform_check,
        mock_skip,
        mock_remediate,
    ):
        """AC-11: Remediate mode returns HostRemediateResult with pass_count, fail_count, fixed_count, skip_count, rolled_back_count."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {}

        rules = [_make_rule(f"rule-{i}") for i in range(5)]

        # rule-0: skip, rule-1: already pass, rule-2: fixed, rule-3: fail, rule-4: fail+rollback
        mock_skip.side_effect = [
            (True, "dep failed"),
            (False, ""),
            (False, ""),
            (False, ""),
            (False, ""),
        ]
        mock_platform_check.side_effect = [True, True, True, True]
        mock_remediate.side_effect = [
            _remediate_pass_result("rule-1"),
            _remediate_fixed_result("rule-2"),
            _remediate_fail_result("rule-3"),
            _remediate_fail_result("rule-4", rolled_back=True),
        ]

        hi = self._make_hi()
        config = self._make_config("remediate")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=rules,
            config=config,
            out=out,
        )

        assert isinstance(result, HostRemediateResult)
        assert result.pass_count == 1
        assert result.fail_count == 2
        assert result.fixed_count == 1
        assert result.skip_count == 1
        assert result.rolled_back_count == 1
        assert result.success is True

    @patch(f"{_PATCH_BASE}.evaluate_rule")
    @patch(f"{_PATCH_BASE}.should_skip_rule")
    @patch(f"{_PATCH_BASE}.rule_applies_to_platform")
    @patch(f"{_PATCH_BASE}.detect_capabilities")
    @patch(f"{_PATCH_BASE}.detect_platform")
    @patch(f"{_PATCH_BASE}.connect")
    def test_ac12_failed_rules_tracked_for_dependency_skip(
        self,
        mock_connect,
        mock_platform,
        mock_caps,
        mock_platform_check,
        mock_skip,
        mock_eval,
    ):
        """AC-12: Failed rules are tracked so that dependent rules are skipped via should_skip_rule in subsequent iterations."""
        mock_ssh = MagicMock()
        mock_ssh.__enter__ = MagicMock(return_value=mock_ssh)
        mock_ssh.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_ssh

        mock_platform.return_value = PlatformInfo("rhel", 9, "9.3")
        mock_caps.return_value = {}

        rule_a = _make_rule("rule-a")
        rule_b = _make_rule("rule-b", depends_on=["rule-a"])

        # rule-a: not skipped, platform matches, but fails evaluation
        # rule-b: should_skip_rule sees rule-a in failed set
        mock_skip.side_effect = [
            (False, ""),
            (True, "depends on rule-a which failed"),
        ]
        mock_platform_check.return_value = True
        mock_eval.return_value = _fail_result("rule-a")

        hi = self._make_hi()
        config = self._make_config("check")
        out = _quiet_console()

        result = execute_on_host(
            hi,
            None,
            sudo=False,
            strict_host_keys=False,
            rule_list=[rule_a, rule_b],
            config=config,
            out=out,
        )

        # should_skip_rule was called for both rules
        assert mock_skip.call_count == 2
        # evaluate_rule called only for rule-a (rule-b was skipped)
        assert mock_eval.call_count == 1
        assert result.fail_count == 1
        assert result.skip_count == 1

        # Verify failed_rules set was passed to should_skip_rule for rule-b
        # The second call should have rule-a in the failed_rules set
        second_call = mock_skip.call_args_list[1]
        failed_set = second_call[0][2]  # third positional arg is failed_rules
        assert "rule-a" in failed_set
