"""Spec-derived tests for audit_rule_set remediation handler.

Spec: specs/handlers/remediation/audit_rule_set.spec.md

Existing test coverage note:
    - TestRollbackAuditRuleSet (test_engine_remediation.py) — rollback handler tests
    - TestCaptureAuditRuleSet (test_engine_remediation.py) — capture handler tests
    Neither class tests the _remediate_audit_rule_set handler directly.
    This file provides full coverage for the remediation handler itself.
"""

from __future__ import annotations

from runner.handlers.remediation import run_remediation
from runner.ssh import Result


class TestAuditRuleSetSpecDerived:
    """Spec-derived tests for _remediate_audit_rule_set."""

    # ── AC-1: Dry-run returns preview ────────────────────────────────────

    def test_dry_run_returns_success_with_preview(self, mock_ssh):
        """AC-1: dry_run=True returns (True, ...) mentioning persist file."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would add audit rule" in detail
        assert "/etc/audit/rules.d/99-kensa.rules" in detail

    def test_dry_run_executes_no_commands(self, mock_ssh):
        """AC-1: dry_run=True does not execute any SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        run_remediation(ssh, rem, dry_run=True)
        assert ssh.commands_run == []

    def test_dry_run_with_custom_persist_file(self, mock_ssh):
        """AC-1 + AC-7: dry_run mentions the custom persist_file path."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-w /etc/shadow -p wa",
            "persist_file": "/etc/audit/rules.d/50-shadow.rules",
        }
        ok, detail, steps = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "/etc/audit/rules.d/50-shadow.rules" in detail

    # ── AC-2: auditctl success + rule not persisted -> append ────────────

    def test_auditctl_ok_rule_not_persisted_appends(self, mock_ssh):
        """AC-2: auditctl succeeds, grep fails -> append_line is called."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert "Added audit rule" in detail
        assert "99-kensa.rules" in detail
        # Verify append was called (echo >> file)
        assert any("echo" in cmd and ">>" in cmd for cmd in ssh.commands_run)

    # ── AC-3: auditctl success + rule already persisted -> skip append ───

    def test_auditctl_ok_rule_already_persisted_skips_append(self, mock_ssh):
        """AC-3: auditctl succeeds, grep succeeds -> no append."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert "Added audit rule" in detail
        # No echo/append command should have been issued
        assert not any("echo" in cmd and ">>" in cmd for cmd in ssh.commands_run)

    # ── AC-4: auditctl "already exists" -> treated as success ────────────

    def test_auditctl_already_exists_is_success(self, mock_ssh):
        """AC-4: auditctl fails with 'already exists' in stderr -> success."""
        ssh = mock_ssh(
            {
                "auditctl": Result(
                    exit_code=1,
                    stdout="",
                    stderr="Rule already exists",
                ),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert "Added audit rule" in detail

    def test_auditctl_already_exists_case_insensitive(self, mock_ssh):
        """AC-4: 'ALREADY EXISTS' in stderr (uppercase) is also treated as success."""
        ssh = mock_ssh(
            {
                "auditctl": Result(
                    exit_code=1,
                    stdout="",
                    stderr="RULE ALREADY EXISTS",
                ),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-w /etc/shadow -p wa",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True

    def test_auditctl_already_exists_still_checks_persistence(self, mock_ssh):
        """AC-4 + AC-2: 'already exists' still triggers persistence check and append."""
        ssh = mock_ssh(
            {
                "auditctl": Result(
                    exit_code=1,
                    stdout="",
                    stderr="Rule already exists",
                ),
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert any("echo" in cmd and ">>" in cmd for cmd in ssh.commands_run)

    # ── AC-5: auditctl fails with other error -> failure ─────────────────

    def test_auditctl_fails_other_error(self, mock_ssh):
        """AC-5: auditctl fails with non-'already exists' error -> failure."""
        ssh = mock_ssh(
            {
                "auditctl": Result(
                    exit_code=1,
                    stdout="",
                    stderr="Permission denied",
                ),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is False
        assert "auditctl failed" in detail
        assert "Permission denied" in detail

    def test_auditctl_fails_empty_stderr(self, mock_ssh):
        """AC-5: auditctl fails with empty stderr -> failure."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is False
        assert "auditctl failed" in detail

    # ── AC-6: Persistence write fails -> failure ─────────────────────────

    def test_persist_write_fails(self, mock_ssh):
        """AC-6: auditctl ok, grep fails, append_line fails -> failure."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=1, stdout="", stderr="write error"),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to persist rule" in detail

    # ── AC-7: Custom persist_file path ───────────────────────────────────

    def test_custom_persist_file_used_in_grep(self, mock_ssh):
        """AC-7: custom persist_file is used in the grep idempotency check."""
        custom_path = "/etc/audit/rules.d/50-custom.rules"
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-w /etc/shadow -p wa",
            "persist_file": custom_path,
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert custom_path in detail
        # Verify grep command references the custom path
        grep_cmds = [cmd for cmd in ssh.commands_run if "grep" in cmd]
        assert any(custom_path in cmd for cmd in grep_cmds)

    def test_custom_persist_file_used_in_append(self, mock_ssh):
        """AC-7: custom persist_file is used in the append_line call."""
        custom_path = "/etc/audit/rules.d/50-custom.rules"
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-w /etc/shadow -p wa",
            "persist_file": custom_path,
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        # Verify echo/append references the custom path
        echo_cmds = [cmd for cmd in ssh.commands_run if "echo" in cmd]
        assert any(custom_path in cmd for cmd in echo_cmds)

    # ── AC-8: Default persist_file path ──────────────────────────────────

    def test_default_persist_file(self, mock_ssh):
        """AC-8: omitting persist_file uses /etc/audit/rules.d/99-kensa.rules."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem)
        assert ok is True
        assert "/etc/audit/rules.d/99-kensa.rules" in detail
        # Verify grep uses the default path
        grep_cmds = [cmd for cmd in ssh.commands_run if "grep" in cmd]
        assert any("99-kensa.rules" in cmd for cmd in grep_cmds)

    # ── AC-9: Shell quoting ──────────────────────────────────────────────

    def test_rule_is_quoted_in_auditctl(self, mock_ssh):
        """AC-9: rule value is shell-quoted in the auditctl command."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        # Filter to the remediation auditctl command (not capture's auditctl -l)
        auditctl_cmds = [
            cmd
            for cmd in ssh.commands_run
            if cmd.startswith("auditctl") and "-l" not in cmd
        ]
        assert len(auditctl_cmds) == 1
        # shlex.quote wraps in single quotes
        assert "'" in auditctl_cmds[0]

    # ── StepResult structure ─────────────────────────────────────────────

    def test_returns_step_result(self, mock_ssh):
        """run_remediation wraps the handler result in a StepResult list."""
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ok, detail, steps = run_remediation(ssh, rem, snapshot=False)
        assert len(steps) == 1
        assert steps[0].mechanism == "audit_rule_set"
        assert steps[0].success is True
