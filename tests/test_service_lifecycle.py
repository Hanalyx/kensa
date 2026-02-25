"""Spec-derived tests for service_enabled / service_disabled remediation handlers.

Tests are derived from specs/handlers/remediation/service_lifecycle.spec.md.
Each test method docstring references the acceptance criterion it validates.

Existing test coverage note:
    There are NO pre-existing direct tests for _remediate_service_enabled or
    _remediate_service_disabled.  The only related tests are for rollback
    (TestRollbackServiceEnabled, TestRollbackServiceDisabled) and capture
    (TestCaptureServiceEnabled, TestCaptureServiceDisabled) in
    test_engine_remediation.py -- those test adjacent subsystems, not the
    remediation handlers themselves.
"""

from __future__ import annotations

from runner.engine import run_remediation
from runner.ssh import Result

# ---------------------------------------------------------------------------
# service_enabled
# ---------------------------------------------------------------------------


class TestServiceEnabledSpecDerived:
    """Spec-derived tests for _remediate_service_enabled (AC-1 through AC-7)."""

    # -- Dry-run --------------------------------------------------------

    def test_dry_run_with_start_default(self, mock_ssh):
        """AC-1: Dry-run with start=True (default) returns success and preview message."""
        ssh = mock_ssh({})
        rem = {"mechanism": "service_enabled", "name": "sshd"}
        ok, detail, steps = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would enable and start sshd"
        assert ssh.commands_run == [], "Dry-run must not execute any SSH commands"

    def test_dry_run_with_start_true_explicit(self, mock_ssh):
        """AC-1: Dry-run with explicit start=True returns same as default."""
        ssh = mock_ssh({})
        rem = {"mechanism": "service_enabled", "name": "crond", "start": True}
        ok, detail, steps = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would enable and start crond"
        assert ssh.commands_run == []

    def test_dry_run_with_start_false(self, mock_ssh):
        """AC-2: Dry-run with start=False returns enable-only preview."""
        ssh = mock_ssh({})
        rem = {"mechanism": "service_enabled", "name": "sshd", "start": False}
        ok, detail, steps = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would enable sshd"
        assert ssh.commands_run == []

    # -- Enable + start succeeds ----------------------------------------

    def test_enable_and_start_success(self, mock_ssh):
        """AC-3: Enable and start both succeed -> (True, 'Enabled and started {name}')."""
        ssh = mock_ssh(
            {
                "systemctl enable": Result(exit_code=0, stdout="", stderr=""),
                "systemctl start": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_enabled", "name": "sshd"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert detail == "Enabled and started sshd"
        assert any("systemctl enable" in cmd for cmd in ssh.commands_run)
        assert any("systemctl start" in cmd for cmd in ssh.commands_run)

    # -- Enable succeeds, start fails -----------------------------------

    def test_enable_ok_start_fails(self, mock_ssh):
        """AC-4: Enable succeeds but start fails -> (False, 'Enabled but failed to start')."""
        ssh = mock_ssh(
            {
                "systemctl enable": Result(exit_code=0, stdout="", stderr=""),
                "systemctl start": Result(
                    exit_code=1, stdout="", stderr="Job for sshd.service failed"
                ),
            }
        )
        rem = {"mechanism": "service_enabled", "name": "sshd"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is False
        assert "Enabled sshd but failed to start" in detail
        assert "Job for sshd.service failed" in detail

    # -- Enable fails ---------------------------------------------------

    def test_enable_fails(self, mock_ssh):
        """AC-5: Enable fails -> (False, 'Failed to enable') and no start attempted."""
        ssh = mock_ssh(
            {
                "systemctl enable": Result(
                    exit_code=1, stdout="", stderr="Unit sshd.service not found"
                ),
            }
        )
        rem = {"mechanism": "service_enabled", "name": "sshd"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to enable sshd" in detail
        assert "Unit sshd.service not found" in detail
        # Must NOT have attempted start
        assert not any("systemctl start" in cmd for cmd in ssh.commands_run)

    # -- Enable-only (start=False) --------------------------------------

    def test_enable_only_no_start(self, mock_ssh):
        """AC-6: start=False and enable succeeds -> (True, 'Enabled {name}'), no start."""
        ssh = mock_ssh(
            {
                "systemctl enable": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_enabled", "name": "crond", "start": False}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert detail == "Enabled crond"
        assert not any("systemctl start" in cmd for cmd in ssh.commands_run)

    # -- Shell quoting --------------------------------------------------

    def test_service_name_is_shell_quoted(self, mock_ssh):
        """AC-7: Service name with special chars is shell-quoted in systemctl commands."""
        ssh = mock_ssh(
            {
                "systemctl enable": Result(exit_code=0, stdout="", stderr=""),
                "systemctl start": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_enabled", "name": "my service"}
        ok, detail, steps = run_remediation(ssh, rem)
        # shlex.quote("my service") -> "'my service'"
        assert any(
            "'my service'" in cmd for cmd in ssh.commands_run
        ), f"Expected shell-quoted service name in commands: {ssh.commands_run}"

    # -- StepResult structure -------------------------------------------

    def test_step_result_structure(self, mock_ssh):
        """Verify run_remediation returns proper StepResult metadata."""
        ssh = mock_ssh(
            {
                "systemctl enable": Result(exit_code=0, stdout="", stderr=""),
                "systemctl start": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_enabled", "name": "sshd"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert len(steps) == 1
        step = steps[0]
        assert step.step_index == 0
        assert step.mechanism == "service_enabled"
        assert step.success is True

    def test_enable_fails_step_result_reflects_failure(self, mock_ssh):
        """StepResult.success is False when enable fails."""
        ssh = mock_ssh(
            {
                "systemctl enable": Result(
                    exit_code=1, stdout="", stderr="access denied"
                ),
            }
        )
        rem = {"mechanism": "service_enabled", "name": "sshd"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert len(steps) == 1
        assert steps[0].success is False


# ---------------------------------------------------------------------------
# service_disabled
# ---------------------------------------------------------------------------


class TestServiceDisabledSpecDerived:
    """Spec-derived tests for _remediate_service_disabled (AC-8 through AC-14)."""

    # -- Dry-run --------------------------------------------------------

    def test_dry_run_with_stop_default(self, mock_ssh):
        """AC-8: Dry-run with stop=True (default) returns success and preview message."""
        ssh = mock_ssh({})
        rem = {"mechanism": "service_disabled", "name": "cups"}
        ok, detail, steps = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would disable and stop cups"
        assert ssh.commands_run == [], "Dry-run must not execute any SSH commands"

    def test_dry_run_with_stop_true_explicit(self, mock_ssh):
        """AC-8: Dry-run with explicit stop=True returns same as default."""
        ssh = mock_ssh({})
        rem = {"mechanism": "service_disabled", "name": "avahi-daemon", "stop": True}
        ok, detail, steps = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would disable and stop avahi-daemon"
        assert ssh.commands_run == []

    def test_dry_run_with_stop_false(self, mock_ssh):
        """AC-9: Dry-run with stop=False returns disable-only preview."""
        ssh = mock_ssh({})
        rem = {"mechanism": "service_disabled", "name": "cups", "stop": False}
        ok, detail, steps = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would disable cups"
        assert ssh.commands_run == []

    # -- Stop + disable succeed -----------------------------------------

    def test_stop_and_disable_success(self, mock_ssh):
        """AC-10: Stop and disable both succeed -> (True, 'Stopped and disabled {name}')."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl disable": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "cups"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert detail == "Stopped and disabled cups"
        assert any("systemctl stop" in cmd for cmd in ssh.commands_run)
        assert any("systemctl disable" in cmd for cmd in ssh.commands_run)

    # -- Stop fails, disable succeeds -----------------------------------

    def test_stop_fails_disable_succeeds(self, mock_ssh):
        """AC-11: Stop failure is ignored; disable succeeds -> (True, 'Stopped and disabled')."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(
                    exit_code=5,
                    stdout="",
                    stderr="Unit cups.service not loaded",
                ),
                "systemctl disable": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "cups"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert detail == "Stopped and disabled cups"

    # -- Disable fails --------------------------------------------------

    def test_disable_fails(self, mock_ssh):
        """AC-12: Disable fails -> (False, 'Failed to disable') regardless of stop result."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl disable": Result(
                    exit_code=1, stdout="", stderr="access denied"
                ),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "cups"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to disable cups" in detail
        assert "access denied" in detail

    def test_disable_fails_when_stop_also_fails(self, mock_ssh):
        """AC-12: Both stop and disable fail -> still reports disable failure."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=1, stdout="", stderr="not loaded"),
                "systemctl disable": Result(
                    exit_code=1, stdout="", stderr="unit not found"
                ),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "cups"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to disable cups" in detail

    # -- Disable-only (stop=False) --------------------------------------

    def test_disable_only_no_stop(self, mock_ssh):
        """AC-13: stop=False and disable succeeds -> (True, 'Disabled {name}'), no stop."""
        ssh = mock_ssh(
            {
                "systemctl disable": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "avahi-daemon", "stop": False}
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert detail == "Disabled avahi-daemon"
        assert not any("systemctl stop" in cmd for cmd in ssh.commands_run)

    # -- Shell quoting --------------------------------------------------

    def test_service_name_is_shell_quoted(self, mock_ssh):
        """AC-14: Service name with special chars is shell-quoted in systemctl commands."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl disable": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "my service"}
        ok, detail, steps = run_remediation(ssh, rem)
        # shlex.quote("my service") -> "'my service'"
        assert any(
            "'my service'" in cmd for cmd in ssh.commands_run
        ), f"Expected shell-quoted service name in commands: {ssh.commands_run}"

    # -- StepResult structure -------------------------------------------

    def test_step_result_structure(self, mock_ssh):
        """Verify run_remediation returns proper StepResult metadata."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl disable": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "cups"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert len(steps) == 1
        step = steps[0]
        assert step.step_index == 0
        assert step.mechanism == "service_disabled"
        assert step.success is True

    def test_disable_fails_step_result_reflects_failure(self, mock_ssh):
        """StepResult.success is False when disable fails."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl disable": Result(
                    exit_code=1, stdout="", stderr="access denied"
                ),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "cups"}
        ok, detail, steps = run_remediation(ssh, rem)
        assert len(steps) == 1
        assert steps[0].success is False

    # -- Operation order -----------------------------------------------

    def test_stop_runs_before_disable(self, mock_ssh):
        """Verify stop is executed before disable (operation ordering)."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl disable": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "cups"}
        run_remediation(ssh, rem)
        stop_idx = next(
            i for i, cmd in enumerate(ssh.commands_run) if "systemctl stop" in cmd
        )
        disable_idx = next(
            i for i, cmd in enumerate(ssh.commands_run) if "systemctl disable" in cmd
        )
        assert stop_idx < disable_idx, "stop must run before disable"
