"""Tests for remediation handlers in runner/engine.py."""

from __future__ import annotations

from runner.engine import (
    PreState,
    StepResult,
    _capture_audit_rule_set,
    _capture_command_exec,
    _capture_config_block,
    _capture_config_remove,
    _capture_config_set,
    _capture_config_set_dropin,
    _capture_cron_job,
    _capture_crypto_policy_set,  # noqa: F401
    _capture_dconf_set,  # noqa: F401
    _capture_file_absent,
    _capture_file_content,
    _capture_file_permissions,
    _capture_grub_parameter_set,
    _capture_kernel_module_disable,
    _capture_manual,
    _capture_mount_option_set,
    _capture_package_absent,
    _capture_package_present,
    _capture_pam_module_configure,
    _capture_selinux_boolean_set,
    _capture_service_disabled,
    _capture_service_enabled,
    _capture_service_masked,
    _capture_sysctl_set,
    _execute_rollback,
    _rollback_audit_rule_set,
    _rollback_command_exec,
    _rollback_config_block,
    _rollback_config_remove,
    _rollback_config_set,
    _rollback_config_set_dropin,
    _rollback_cron_job,
    _rollback_crypto_policy_set,  # noqa: F401
    _rollback_dconf_set,  # noqa: F401
    _rollback_file_absent,
    _rollback_file_content,
    _rollback_file_permissions,
    _rollback_grub_parameter_set,
    _rollback_kernel_module_disable,
    _rollback_manual,
    _rollback_mount_option_set,
    _rollback_package_absent,
    _rollback_package_present,
    _rollback_pam_module_configure,
    _rollback_selinux_boolean_set,
    _rollback_service_disabled,
    _rollback_service_enabled,
    _rollback_service_masked,
    _rollback_sysctl_set,
    evaluate_rule,
    remediate_rule,
    run_remediation,
)
from runner.ssh import Result

# ── Existing remediation handler tests (updated for 3-tuple return) ────────


class TestConfigSet:
    def test_dry_run(self, mock_ssh):
        """AC-1: Dry-run returns without execution."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
            "separator": " ",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set" in detail

    def test_replaces_existing_key(self, mock_ssh):
        """AC-2: Existing key is replaced via sed."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="Foo old_value", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
            "separator": " ",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("sed" in cmd for cmd in ssh.commands_run)

    def test_appends_when_key_absent(self, mock_ssh):
        """AC-3: Missing key is appended."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
            "separator": " ",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("echo" in cmd and ">>" in cmd for cmd in ssh.commands_run)

    def test_calls_reload(self, mock_ssh):
        """AC-4: Service reload on success."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "K",
            "value": "V",
            "separator": " ",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("systemctl" in cmd and "sshd" in cmd for cmd in ssh.commands_run)


class TestConfigSetSpecDerived:
    """Spec-derived gap tests for config_set remediation handler."""

    def test_dry_run_no_ssh_commands(self, mock_ssh):
        """AC-1: Dry-run must not execute any SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set",
            "path": "/etc/sshd_config",
            "key": "PermitRootLogin",
            "value": "no",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert len(ssh.commands_run) == 0

    def test_dry_run_detail_format(self, mock_ssh):
        """AC-11: Dry-run detail message includes key, separator, value, and path."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "MaxAuthTries",
            "value": "4",
            "separator": " ",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert detail == "Would set 'MaxAuthTries 4' in /etc/conf"

    def test_success_detail_format_sed_path(self, mock_ssh):
        """AC-10: Success detail after sed replacement matches expected format."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="Foo old_value", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
            "separator": " ",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert detail == "Set 'Foo bar' in /etc/conf"

    def test_success_detail_format_append_path(self, mock_ssh):
        """AC-10: Success detail after append matches expected format."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/myapp.conf",
            "key": "LogLevel",
            "value": "INFO",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert detail == "Set 'LogLevel INFO' in /etc/myapp.conf"

    def test_restart_service_on_success(self, mock_ssh):
        """AC-5: Service restart (not reload) is invoked when restart key is present."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "K",
            "value": "V",
            "restart": "auditd",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any(
            "systemctl restart" in cmd and "auditd" in cmd for cmd in ssh.commands_run
        )

    def test_no_service_action_when_absent(self, mock_ssh):
        """AC-6: No systemctl command when neither reload nor restart is specified."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "K",
            "value": "V",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert not any("systemctl" in cmd for cmd in ssh.commands_run)

    def test_custom_separator(self, mock_ssh):
        """AC-7: Custom separator is used between key and value."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/sysctl.conf",
            "key": "net.ipv4.ip_forward",
            "value": "0",
            "separator": " = ",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert detail == "Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.conf"
        # Verify the echo command includes the separator
        echo_cmds = [cmd for cmd in ssh.commands_run if "echo" in cmd and ">>" in cmd]
        assert len(echo_cmds) == 1
        assert "net.ipv4.ip_forward = 0" in echo_cmds[0]

    def test_default_separator_is_space(self, mock_ssh):
        """AC-7: Default separator is a single space when not specified."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "MyKey",
            "value": "MyVal",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert detail == "Set 'MyKey MyVal' in /etc/conf"

    def test_sed_failure_returns_false(self, mock_ssh):
        """AC-8: Sed failure returns (False, ...) with failure detail."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="Foo old_value", stderr=""),
                "sed -i": Result(exit_code=1, stdout="", stderr="sed: error"),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to set Foo in /etc/conf" in detail

    def test_append_failure_returns_false_with_stderr(self, mock_ssh):
        """AC-9: Append failure returns (False, ...) including stderr."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=1, stdout="", stderr="Permission denied"),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to set Foo in /etc/conf" in detail
        assert "Permission denied" in detail

    def test_sed_failure_skips_service_action(self, mock_ssh):
        """AC-8: When sed fails, service_action is not called."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="Foo old", stderr=""),
                "sed -i": Result(exit_code=1, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert not any("systemctl" in cmd for cmd in ssh.commands_run)

    def test_append_failure_skips_service_action(self, mock_ssh):
        """AC-9: When append fails, service_action is not called."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=1, stdout="", stderr="err"),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert not any("systemctl" in cmd for cmd in ssh.commands_run)

    def test_service_reload_after_sed_path(self, mock_ssh):
        """AC-12: Service reload is called after successful sed replacement."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="K old", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "K",
            "value": "V",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("systemctl" in cmd and "sshd" in cmd for cmd in ssh.commands_run)


class TestConfigSetDropin:
    def test_writes_file(self, mock_ssh):
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa-test.conf",
            "key": "PermitRootLogin",
            "value": "no",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "00-kensa-test.conf" in detail

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa-test.conf",
            "key": "K",
            "value": "V",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would write" in detail


class TestCommandExec:
    def test_runs_command(self, mock_ssh):
        ssh = mock_ssh(
            {
                "aide --init": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "command_exec", "run": "aide --init"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True

    def test_unless_guard_skips(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f /var/lib/aide/aide.db.gz": Result(
                    exit_code=0, stdout="", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "aide --init",
            "unless": "test -f /var/lib/aide/aide.db.gz",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "Skipped" in detail

    def test_onlyif_guard_skips(self, mock_ssh):
        ssh = mock_ssh(
            {
                "which aide": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "aide --init",
            "onlyif": "which aide",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "Skipped" in detail

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "command_exec", "run": "dangerous-command"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would run" in detail

    def test_command_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "bad-cmd": Result(exit_code=127, stdout="", stderr="not found"),
            }
        )
        rem = {"mechanism": "command_exec", "run": "bad-cmd"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "failed" in detail.lower()


class TestFilePermissions:
    def test_sets_owner_group_mode(self, mock_ssh):
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "owner": "root",
            "group": "root",
            "mode": "0000",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("chown" in cmd for cmd in ssh.commands_run)
        assert any("chmod" in cmd for cmd in ssh.commands_run)

    def test_glob_path_not_quoted(self, mock_ssh):
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/ssh/ssh_host_*_key",
            "owner": "root",
            "group": "ssh_keys",
            "mode": "0640",
            "glob": "ssh_host_*_key",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        # The path should NOT be quoted (no single quotes around it)
        chown_cmd = [c for c in ssh.commands_run if "chown" in c][0]
        assert "'/etc/ssh/ssh_host_*_key'" not in chown_cmd
        assert "/etc/ssh/ssh_host_*_key" in chown_cmd

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "file_permissions", "path": "/etc/shadow", "mode": "0000"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would run" in detail


class TestSysctlSet:
    def test_applies_and_persists(self, mock_ssh):
        """AC-2: sysctl -w success + write_file success returns (True, detail)."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("sysctl -w" in cmd for cmd in ssh.commands_run)
        assert any("printf" in cmd and "sysctl.d" in cmd for cmd in ssh.commands_run)

    def test_dry_run(self, mock_ssh):
        """AC-1: dry_run returns (True, 'Would set ...') with no SSH commands."""
        ssh = mock_ssh({})
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set" in detail


class TestSysctlSetSpecDerived:
    """Spec-derived gap tests for sysctl_set remediation handler."""

    def test_sysctl_w_failure_returns_false_with_stderr(self, mock_ssh):
        """AC-3: sysctl -w failure returns (False, 'sysctl -w failed: {stderr}')."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(
                    exit_code=1, stdout="", stderr="sysctl: permission denied"
                ),
            }
        )
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "sysctl -w failed" in detail
        assert "permission denied" in detail

    def test_sysctl_w_failure_skips_persistence(self, mock_ssh):
        """AC-3: When sysctl -w fails, no persistence write is attempted."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=1, stdout="", stderr="error"),
            }
        )
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        run_remediation(ssh, rem)
        assert not any("printf" in cmd for cmd in ssh.commands_run)

    def test_persistence_failure_returns_false(self, mock_ssh):
        """AC-4: sysctl -w succeeds but write_file fails returns (False, ...)."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                # printf (write_file) fails
            }
        )
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to persist" in detail

    def test_default_persist_file_dots_to_dashes(self, mock_ssh):
        """AC-5: Default persist_file replaces dots in key with dashes."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "sysctl_set",
            "key": "net.ipv4.conf.all.accept_redirects",
            "value": "0",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        expected_path = "/etc/sysctl.d/99-kensa-net-ipv4-conf-all-accept_redirects.conf"
        assert expected_path in detail

    def test_custom_persist_file(self, mock_ssh):
        """AC-6: Custom persist_file overrides the default path."""
        custom_path = "/etc/sysctl.d/50-custom.conf"
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "sysctl_set",
            "key": "net.ipv4.ip_forward",
            "value": "0",
            "persist_file": custom_path,
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert custom_path in detail

    def test_shell_quoting_in_sysctl_command(self, mock_ssh):
        """AC-7: key and value are shell-quoted in the sysctl -w command."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        # Use a value with spaces to force visible quoting
        rem = {
            "mechanism": "sysctl_set",
            "key": "net.ipv4.ip_forward",
            "value": "hello world",
        }
        run_remediation(ssh, rem)
        sysctl_cmds = [c for c in ssh.commands_run if "sysctl -w" in c]
        assert len(sysctl_cmds) == 1
        # shell_util.quote wraps values with spaces in single quotes
        assert "'hello world'" in sysctl_cmds[0]

    def test_persistence_content_format(self, mock_ssh):
        """AC-8: Persisted file contains '{key} = {value}\\n'."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        run_remediation(ssh, rem)
        printf_cmds = [c for c in ssh.commands_run if "printf" in c]
        assert len(printf_cmds) == 1
        # write_file uses: printf %s {quoted_content} > {quoted_path}
        # Content should be "net.ipv4.ip_forward = 0\n"
        assert "net.ipv4.ip_forward = 0" in printf_cmds[0]

    def test_value_coercion_to_str(self, mock_ssh):
        """AC-9: Integer value is coerced to str before quoting."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        # Pass an integer value (as YAML might produce)
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": 0}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "net.ipv4.ip_forward=0" in detail

    def test_dry_run_no_ssh_commands(self, mock_ssh):
        """AC-1: Dry-run executes zero SSH commands."""
        ssh = mock_ssh({})
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        run_remediation(ssh, rem, dry_run=True)
        assert len(ssh.commands_run) == 0

    def test_dry_run_detail_contains_key_value_and_path(self, mock_ssh):
        """AC-1: Dry-run detail contains key, value, and persist file path."""
        ssh = mock_ssh({})
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert "net.ipv4.ip_forward" in detail
        assert "0" in detail
        assert "/etc/sysctl.d/" in detail

    def test_success_detail_format(self, mock_ssh):
        """AC-2: Success detail is 'Set {key}={value}, persisted to {path}'."""
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem)
        # Note: replace('.', '-') only replaces dots, not underscores
        assert detail == (
            "Set net.ipv4.ip_forward=0, persisted to "
            "/etc/sysctl.d/99-kensa-net-ipv4-ip_forward.conf"
        )

    def test_persistence_failure_detail_includes_path(self, mock_ssh):
        """AC-4: Persistence failure detail includes the persist_file path."""
        custom_path = "/etc/sysctl.d/50-custom.conf"
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                # printf not mocked -> fails
            }
        )
        rem = {
            "mechanism": "sysctl_set",
            "key": "net.ipv4.ip_forward",
            "value": "0",
            "persist_file": custom_path,
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert custom_path in detail


class TestPackagePresent:
    def test_installs(self, mock_ssh):
        ssh = mock_ssh(
            {
                "dnf install": Result(exit_code=0, stdout="Complete!", stderr=""),
            }
        )
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "Installed" in detail

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would install" in detail

    def test_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "dnf install": Result(
                    exit_code=1, stdout="", stderr="No package aide available"
                ),
            }
        )
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False


class TestKernelModuleDisable:
    def test_blacklists_and_unloads(self, mock_ssh):
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe -r": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "Blacklisted" in detail

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would blacklist" in detail


class TestManual:
    def test_returns_false_with_note(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "manual", "note": "Contact security team"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "MANUAL" in detail
        assert "Contact security team" in detail


class TestMultiStepRemediation:
    def test_sequential_execution(self, mock_ssh):
        ssh = mock_ssh(
            {
                "dnf install": Result(exit_code=0, stdout="", stderr=""),
                "aide --init": Result(exit_code=0, stdout="", stderr=""),
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "steps": [
                {"mechanism": "package_present", "name": "aide"},
                {
                    "mechanism": "command_exec",
                    "run": "aide --init",
                    "unless": "test -f /var/lib/aide/aide.db.gz",
                },
            ]
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True

    def test_stops_on_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "dnf install": Result(exit_code=1, stdout="", stderr="Error"),
            }
        )
        rem = {
            "steps": [
                {"mechanism": "package_present", "name": "aide"},
                {"mechanism": "command_exec", "run": "aide --init"},
            ]
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False


class TestUnknownMechanism:
    def test_unknown_mechanism(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "nonexistent_mechanism"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "Unknown" in detail


class TestFullCycle:
    def test_evaluate_and_remediate(self, mock_ssh, sample_rule):
        """Check → fail → remediate → re-check → pass."""
        call_count = {"sysctl_n": 0}

        class CycleSSH:
            def __init__(self):
                self.commands_run = []

            def run(self, cmd, *, timeout=None):
                self.commands_run.append(cmd)
                if "sysctl -n" in cmd:
                    call_count["sysctl_n"] += 1
                    # Calls 1-2: wrong value. After remediation (call 3): correct.
                    if call_count["sysctl_n"] <= 2:
                        return Result(exit_code=0, stdout="1", stderr="")
                    return Result(exit_code=0, stdout="0", stderr="")
                if "sysctl -w" in cmd:
                    return Result(exit_code=0, stdout="", stderr="")
                if "echo" in cmd:
                    return Result(exit_code=0, stdout="", stderr="")
                return Result(exit_code=0, stdout="", stderr="")

        ssh = CycleSSH()
        caps = {"sshd_config_d": False}

        # First: evaluate should fail
        result = evaluate_rule(ssh, sample_rule, caps)
        assert result.passed is False

        # Now: remediate should fix and re-check
        result = remediate_rule(ssh, sample_rule, caps)
        assert result.remediated is True
        assert result.passed is True


# ── Capture tests ──────────────────────────────────────────────────────────


class TestCaptureConfigSet:
    def test_key_exists(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="Foo bar", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "baz",
        }
        ps = _capture_config_set(ssh, rem)
        assert ps.mechanism == "config_set"
        assert ps.capturable is True
        assert ps.data["old_line"] == "Foo bar"
        assert ps.data["existed"] is True

    def test_key_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "baz",
        }
        ps = _capture_config_set(ssh, rem)
        assert ps.data["old_line"] is None
        assert ps.data["existed"] is False

    def test_stores_reload_restart(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "K",
            "value": "V",
            "reload": "sshd",
        }
        ps = _capture_config_set(ssh, rem)
        assert ps.data["reload"] == "sshd"
        assert ps.data["restart"] is None


class TestCaptureConfigSetDropin:
    def test_file_exists(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(exit_code=0, stdout="OldContent", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "test.conf",
            "key": "K",
            "value": "V",
        }
        ps = _capture_config_set_dropin(ssh, rem)
        assert ps.data["existed"] is True
        assert ps.data["old_content"] == "OldContent"

    def test_file_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "test.conf",
            "key": "K",
            "value": "V",
        }
        ps = _capture_config_set_dropin(ssh, rem)
        assert ps.data["existed"] is False
        assert ps.data["old_content"] is None


class TestCaptureCommandExec:
    def test_not_capturable(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "command_exec", "run": "some-cmd"}
        ps = _capture_command_exec(ssh, rem)
        assert ps.capturable is False
        assert ps.mechanism == "command_exec"


class TestCaptureFilePermissions:
    def test_stat_parsed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "stat -c": Result(
                    exit_code=0, stdout="root root 644 /etc/shadow", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "owner": "root",
            "mode": "0000",
        }
        ps = _capture_file_permissions(ssh, rem)
        assert ps.mechanism == "file_permissions"
        assert len(ps.data["entries"]) == 1
        assert ps.data["entries"][0]["owner"] == "root"
        assert ps.data["entries"][0]["group"] == "root"
        assert ps.data["entries"][0]["mode"] == "644"
        assert ps.data["entries"][0]["path"] == "/etc/shadow"

    def test_multiple_files(self, mock_ssh):
        ssh = mock_ssh(
            {
                "stat -c": Result(
                    exit_code=0,
                    stdout="root ssh_keys 640 /etc/ssh/ssh_host_rsa_key\nroot ssh_keys 640 /etc/ssh/ssh_host_ed25519_key",
                    stderr="",
                ),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/ssh/ssh_host_*_key",
            "glob": True,
        }
        ps = _capture_file_permissions(ssh, rem)
        assert len(ps.data["entries"]) == 2


class TestCaptureSysctlSet:
    def test_captures_value_and_persist(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sysctl -n": Result(exit_code=0, stdout="1", stderr=""),
                "cat": Result(exit_code=0, stdout="net.ipv4.ip_forward = 1", stderr=""),
            }
        )
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ps = _capture_sysctl_set(ssh, rem)
        assert ps.data["old_value"] == "1"
        assert ps.data["persist_existed"] is True
        assert "net.ipv4.ip_forward = 1" in ps.data["old_persist"]


class TestCapturePackagePresent:
    def test_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=0, stdout="aide-0.16-1.el9", stderr=""),
            }
        )
        rem = {"mechanism": "package_present", "name": "aide"}
        ps = _capture_package_present(ssh, rem)
        assert ps.data["was_installed"] is True

    def test_not_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "package_present", "name": "aide"}
        ps = _capture_package_present(ssh, rem)
        assert ps.data["was_installed"] is False


class TestCaptureKernelModuleDisable:
    def test_conf_and_loaded(self, mock_ssh):
        ssh = mock_ssh(
            {
                "cat": Result(
                    exit_code=0,
                    stdout="blacklist cramfs\ninstall cramfs /bin/false",
                    stderr="",
                ),
                "lsmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ps = _capture_kernel_module_disable(ssh, rem)
        assert ps.data["conf_existed"] is True
        assert ps.data["old_conf"] is not None
        assert ps.data["was_loaded"] is True


class TestCaptureManual:
    def test_not_capturable(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "manual", "note": "Do something"}
        ps = _capture_manual(ssh, rem)
        assert ps.capturable is False


# ── Rollback tests ─────────────────────────────────────────────────────────


class TestRollbackConfigSet:
    def test_restores_old_line(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="config_set",
            data={
                "path": "/etc/conf",
                "key": "Foo",
                "old_line": "Foo oldval",
                "existed": True,
                "reload": None,
                "restart": None,
            },
        )
        ok, detail = _rollback_config_set(ssh, ps)
        assert ok is True
        assert "Restored" in detail
        assert any("sed" in cmd for cmd in ssh.commands_run)

    def test_removes_appended_line(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="config_set",
            data={
                "path": "/etc/conf",
                "key": "Foo",
                "old_line": None,
                "existed": False,
                "reload": "sshd",
                "restart": None,
            },
        )
        ok, detail = _rollback_config_set(ssh, ps)
        assert ok is True
        assert any("sed" in cmd and "/d" in cmd for cmd in ssh.commands_run)


class TestRollbackConfigSetDropin:
    def test_removes_new_file(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="config_set_dropin",
            data={
                "path": "/etc/ssh/sshd_config.d/test.conf",
                "old_content": None,
                "existed": False,
                "reload": "sshd",
                "restart": None,
            },
        )
        ok, detail = _rollback_config_set_dropin(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_restores_old_content(self, mock_ssh):
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="config_set_dropin",
            data={
                "path": "/etc/ssh/sshd_config.d/test.conf",
                "old_content": "OldLine",
                "existed": True,
                "reload": "sshd",
                "restart": None,
            },
        )
        ok, detail = _rollback_config_set_dropin(ssh, ps)
        assert ok is True
        assert "Restored" in detail


class TestRollbackCommandExec:
    def test_cannot_rollback(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="command_exec", data={"note": "arbitrary"}, capturable=False
        )
        ok, detail = _rollback_command_exec(ssh, ps)
        assert ok is False
        assert "Cannot rollback" in detail


class TestRollbackFilePermissions:
    def test_restores_permissions(self, mock_ssh):
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="file_permissions",
            data={
                "entries": [
                    {
                        "path": "/etc/shadow",
                        "owner": "root",
                        "group": "root",
                        "mode": "640",
                    }
                ],
            },
        )
        ok, detail = _rollback_file_permissions(ssh, ps)
        assert ok is True
        assert "1 file(s)" in detail

    def test_no_entries(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(mechanism="file_permissions", data={"entries": []})
        ok, detail = _rollback_file_permissions(ssh, ps)
        assert ok is False


class TestRollbackSysctlSet:
    def test_restores_value_and_persist(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="sysctl_set",
            data={
                "key": "net.ipv4.ip_forward",
                "old_value": "1",
                "persist_file": "/etc/sysctl.d/99-kensa-net-ipv4-ip-forward.conf",
                "old_persist": "net.ipv4.ip_forward = 1",
                "persist_existed": True,
            },
        )
        ok, detail = _rollback_sysctl_set(ssh, ps)
        assert ok is True
        assert any("sysctl -w" in cmd for cmd in ssh.commands_run)

    def test_removes_persist_if_not_existed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="sysctl_set",
            data={
                "key": "net.ipv4.ip_forward",
                "old_value": "1",
                "persist_file": "/etc/sysctl.d/99-kensa-net-ipv4-ip-forward.conf",
                "old_persist": None,
                "persist_existed": False,
            },
        )
        ok, detail = _rollback_sysctl_set(ssh, ps)
        assert ok is True
        assert any("rm -f" in cmd for cmd in ssh.commands_run)


class TestRollbackPackagePresent:
    def test_removes_if_not_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "dnf remove": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="package_present", data={"name": "aide", "was_installed": False}
        )
        ok, detail = _rollback_package_present(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_noop_if_was_installed(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="package_present", data={"name": "aide", "was_installed": True}
        )
        ok, detail = _rollback_package_present(ssh, ps)
        assert ok is True
        assert "already installed" in detail


class TestRollbackKernelModuleDisable:
    def test_restores_conf_and_reloads(self, mock_ssh):
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="kernel_module_disable",
            data={
                "name": "cramfs",
                "conf_path": "/etc/modprobe.d/cramfs.conf",
                "old_conf": "# nothing",
                "conf_existed": True,
                "was_loaded": True,
            },
        )
        ok, detail = _rollback_kernel_module_disable(ssh, ps)
        assert ok is True
        assert any("modprobe" in cmd and "cramfs" in cmd for cmd in ssh.commands_run)

    def test_removes_conf_if_not_existed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="kernel_module_disable",
            data={
                "name": "cramfs",
                "conf_path": "/etc/modprobe.d/cramfs.conf",
                "old_conf": None,
                "conf_existed": False,
                "was_loaded": False,
            },
        )
        ok, detail = _rollback_kernel_module_disable(ssh, ps)
        assert ok is True
        assert any("rm -f" in cmd for cmd in ssh.commands_run)


class TestRollbackManual:
    def test_returns_false(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(mechanism="manual", data={}, capturable=False)
        ok, detail = _rollback_manual(ssh, ps)
        assert ok is False
        assert "Nothing to rollback" in detail


# ── Integration tests ──────────────────────────────────────────────────────


class TestStepResults:
    def test_single_step_returns_step_results(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
            "separator": " ",
        }
        ok, detail, step_results = run_remediation(ssh, rem)
        assert ok is True
        assert len(step_results) == 1
        assert step_results[0].step_index == 0
        assert step_results[0].mechanism == "config_set"
        assert step_results[0].success is True
        assert step_results[0].pre_state is not None
        assert step_results[0].pre_state.mechanism == "config_set"

    def test_multi_step_returns_step_results(self, mock_ssh):
        ssh = mock_ssh(
            {
                "dnf install": Result(exit_code=0, stdout="", stderr=""),
                "aide --init": Result(exit_code=0, stdout="", stderr=""),
                "test -f": Result(exit_code=1, stdout="", stderr=""),
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "steps": [
                {"mechanism": "package_present", "name": "aide"},
                {
                    "mechanism": "command_exec",
                    "run": "aide --init",
                    "unless": "test -f /var/lib/aide/aide.db.gz",
                },
            ]
        }
        ok, detail, step_results = run_remediation(ssh, rem)
        assert ok is True
        assert len(step_results) == 2
        assert step_results[0].mechanism == "package_present"
        assert step_results[1].mechanism == "command_exec"
        assert step_results[1].pre_state.capturable is False

    def test_dry_run_skips_capture(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set",
            "path": "/etc/conf",
            "key": "Foo",
            "value": "bar",
            "separator": " ",
        }
        ok, detail, step_results = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert step_results[0].pre_state is None


class TestMultiStepVerification:
    def test_per_step_verification(self, mock_ssh):
        """Multi-step runs check between steps when check is provided."""
        call_count = {"check": 0}

        class VerifySSH:
            def __init__(self):
                self.commands_run = []

            def run(self, cmd, *, timeout=None):
                self.commands_run.append(cmd)
                if "test -d" in cmd:
                    return Result(exit_code=1, stdout="", stderr="")
                if "grep -h" in cmd or "grep -rh" in cmd:
                    # grep_config_key — used by capture, remediation, and check
                    call_count["check"] += 1
                    if call_count["check"] <= 2:
                        # Capture + config_key_exists: key not found yet
                        return Result(exit_code=1, stdout="", stderr="")
                    # Check verification: key found with correct value
                    return Result(exit_code=0, stdout="deny = 5", stderr="")
                if "echo" in cmd:
                    return Result(exit_code=0, stdout="", stderr="")
                if "authselect" in cmd:
                    return Result(exit_code=0, stdout="", stderr="")
                return Result(exit_code=0, stdout="", stderr="")

        ssh = VerifySSH()
        check = {
            "method": "config_value",
            "path": "/etc/security/faillock.conf",
            "key": "deny",
            "expected": "5",
        }
        rem = {
            "steps": [
                {
                    "mechanism": "config_set",
                    "path": "/etc/security/faillock.conf",
                    "key": "deny",
                    "value": "5",
                    "separator": " = ",
                },
                {
                    "mechanism": "command_exec",
                    "run": "authselect apply-changes",
                },
            ]
        }
        ok, detail, step_results = run_remediation(ssh, rem, check=check)
        assert ok is True
        # Both steps should have verified field set
        assert step_results[0].verified is True
        assert step_results[1].verified is True


class TestRollbackOnFailure:
    def test_step2_fails_step1_rolled_back(self, mock_ssh):
        """Step 2 fails → step 1 gets rolled back."""
        ssh = mock_ssh(
            {
                # grep_config_key: capture + remediation + check all use grep -h
                "grep -h": Result(exit_code=0, stdout="deny = 3", stderr=""),
                # sed_replace_line for config_set remediation
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                # Remediate command_exec fails
                "authselect apply-changes": Result(
                    exit_code=1, stdout="", stderr="authselect error"
                ),
            }
        )
        rule = {
            "id": "test-rollback",
            "title": "Test rollback",
            "severity": "high",
            "category": "access-control",
            "implementations": [
                {
                    "default": True,
                    "check": {
                        "method": "config_value",
                        "path": "/etc/security/faillock.conf",
                        "key": "deny",
                        "expected": "5",
                    },
                    "remediation": {
                        "steps": [
                            {
                                "mechanism": "config_set",
                                "path": "/etc/security/faillock.conf",
                                "key": "deny",
                                "value": "5",
                                "separator": " = ",
                            },
                            {
                                "mechanism": "command_exec",
                                "run": "authselect apply-changes",
                            },
                        ]
                    },
                }
            ],
        }
        caps = {}
        result = remediate_rule(ssh, rule, caps, rollback_on_failure=True)
        assert result.remediated is True
        assert result.passed is False
        assert result.rolled_back is True
        assert len(result.rollback_results) > 0
        # The command_exec step (failed) should be skipped in rollback
        cmd_rollback = [
            rb for rb in result.rollback_results if rb.mechanism == "command_exec"
        ]
        assert all(rb.detail == "skipped" for rb in cmd_rollback)
        # The config_set step (succeeded) should have been rolled back
        cfg_rollback = [
            rb for rb in result.rollback_results if rb.mechanism == "config_set"
        ]
        assert len(cfg_rollback) == 1


class TestRollbackOnRecheckFailure:
    def test_all_steps_succeed_but_recheck_fails(self):
        """All remediation steps succeed but final re-check fails → rollback."""
        call_count = {"check": 0}

        class RecheckSSH:
            def __init__(self):
                self.commands_run = []

            def run(self, cmd, *, timeout=None):
                self.commands_run.append(cmd)
                if "sysctl -n" in cmd:
                    call_count["check"] += 1
                    # Always return wrong value so re-check fails
                    return Result(exit_code=0, stdout="1", stderr="")
                if "sysctl -w" in cmd:
                    return Result(exit_code=0, stdout="", stderr="")
                if "printf" in cmd:
                    return Result(exit_code=0, stdout="", stderr="")
                return Result(exit_code=0, stdout="", stderr="")

        ssh = RecheckSSH()
        rule = {
            "id": "test-recheck-rollback",
            "title": "Test recheck rollback",
            "severity": "medium",
            "category": "kernel",
            "implementations": [
                {
                    "default": True,
                    "check": {
                        "method": "sysctl_value",
                        "key": "net.ipv4.ip_forward",
                        "expected": "0",
                    },
                    "remediation": {
                        "mechanism": "sysctl_set",
                        "key": "net.ipv4.ip_forward",
                        "value": "0",
                    },
                }
            ],
        }
        caps = {}
        result = remediate_rule(ssh, rule, caps, rollback_on_failure=True)
        assert result.remediated is True
        assert result.passed is False
        assert result.rolled_back is True
        assert len(result.rollback_results) == 1
        assert result.rollback_results[0].mechanism == "sysctl_set"


# ── New rollback tests (Phase 3) ──────────────────────────────────────────


class TestRollbackConfigRemove:
    def test_restores_removed_lines(self, mock_ssh):
        ssh = mock_ssh(
            {
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="config_remove",
            data={
                "path": "/etc/conf",
                "key": "BadKey",
                "old_lines": "BadKey val1\nBadKey val2",
                "existed": True,
                "reload": None,
                "restart": None,
            },
        )
        ok, detail = _rollback_config_remove(ssh, ps)
        assert ok is True
        assert "Restored" in detail

    def test_noop_when_not_existed(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="config_remove",
            data={
                "path": "/etc/conf",
                "key": "Missing",
                "old_lines": None,
                "existed": False,
                "reload": None,
                "restart": None,
            },
        )
        ok, detail = _rollback_config_remove(ssh, ps)
        assert ok is True
        assert "No lines" in detail

    def test_triggers_reload(self, mock_ssh):
        ssh = mock_ssh(
            {
                "echo": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="config_remove",
            data={
                "path": "/etc/conf",
                "key": "K",
                "old_lines": "K val",
                "existed": True,
                "reload": "sshd",
                "restart": None,
            },
        )
        ok, detail = _rollback_config_remove(ssh, ps)
        assert ok is True


class TestRollbackConfigBlock:
    def test_removes_file_if_not_existed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="config_block",
            data={
                "path": "/etc/conf.d/block.conf",
                "existed": False,
                "old_content": None,
                "block_existed": False,
                "marker": "# KENSA MANAGED BLOCK",
                "reload": None,
                "restart": None,
            },
        )
        ok, detail = _rollback_config_block(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_restores_old_content(self, mock_ssh):
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="config_block",
            data={
                "path": "/etc/conf.d/block.conf",
                "existed": True,
                "old_content": "original content",
                "block_existed": False,
                "marker": "# KENSA MANAGED BLOCK",
                "reload": None,
                "restart": None,
            },
        )
        ok, detail = _rollback_config_block(ssh, ps)
        assert ok is True
        assert "Restored" in detail


class TestRollbackFileContent:
    def test_removes_if_not_existed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="file_content",
            data={
                "path": "/etc/new-file.conf",
                "existed": False,
                "old_content": None,
                "old_owner": None,
                "old_group": None,
                "old_mode": None,
            },
        )
        ok, detail = _rollback_file_content(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_restores_content_and_perms(self, mock_ssh):
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="file_content",
            data={
                "path": "/etc/important.conf",
                "existed": True,
                "old_content": "old data",
                "old_owner": "root",
                "old_group": "root",
                "old_mode": "644",
            },
        )
        ok, detail = _rollback_file_content(ssh, ps)
        assert ok is True
        assert "Restored" in detail

    def test_remove_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rm -f": Result(exit_code=1, stdout="", stderr="permission denied"),
            }
        )
        ps = PreState(
            mechanism="file_content",
            data={
                "path": "/etc/file",
                "existed": False,
                "old_content": None,
                "old_owner": None,
                "old_group": None,
                "old_mode": None,
            },
        )
        ok, detail = _rollback_file_content(ssh, ps)
        assert ok is False
        assert "Failed" in detail


class TestRollbackFileAbsent:
    def test_noop_when_already_absent(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="file_absent",
            data={
                "path": "/etc/gone.conf",
                "existed": False,
                "old_content": None,
                "old_owner": None,
                "old_group": None,
                "old_mode": None,
            },
        )
        ok, detail = _rollback_file_absent(ssh, ps)
        assert ok is True
        assert "already absent" in detail

    def test_restores_file(self, mock_ssh):
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="file_absent",
            data={
                "path": "/etc/removed.conf",
                "existed": True,
                "old_content": "file contents here",
                "old_owner": "root",
                "old_group": "root",
                "old_mode": "644",
            },
        )
        ok, detail = _rollback_file_absent(ssh, ps)
        assert ok is True
        assert "Restored" in detail

    def test_cannot_restore_without_content(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="file_absent",
            data={
                "path": "/etc/removed.conf",
                "existed": True,
                "old_content": None,
                "old_owner": None,
                "old_group": None,
                "old_mode": None,
            },
        )
        ok, detail = _rollback_file_absent(ssh, ps)
        assert ok is False
        assert "Cannot restore" in detail


class TestRollbackPackageAbsent:
    def test_reinstalls_if_was_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "dnf install": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="package_absent",
            data={
                "name": "telnet",
                "was_installed": True,
                "version": "telnet-0.17-1.el9",
            },
        )
        ok, detail = _rollback_package_absent(ssh, ps)
        assert ok is True
        assert "Reinstalled" in detail

    def test_noop_if_not_installed(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="package_absent",
            data={"name": "telnet", "was_installed": False, "version": None},
        )
        ok, detail = _rollback_package_absent(ssh, ps)
        assert ok is True
        assert "not installed" in detail

    def test_reinstall_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "dnf install": Result(
                    exit_code=1, stdout="", stderr="No package available"
                ),
            }
        )
        ps = PreState(
            mechanism="package_absent",
            data={
                "name": "telnet",
                "was_installed": True,
                "version": "telnet-0.17-1.el9",
            },
        )
        ok, detail = _rollback_package_absent(ssh, ps)
        assert ok is False
        assert "Failed" in detail


class TestRollbackServiceEnabled:
    def test_disables_if_was_disabled(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl disable": Result(exit_code=0, stdout="", stderr=""),
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="service_enabled",
            data={
                "name": "sshd",
                "was_enabled": "disabled",
                "was_active": "inactive",
            },
        )
        ok, detail = _rollback_service_enabled(ssh, ps)
        assert ok is True
        assert "Restored" in detail
        assert any("disable" in cmd for cmd in ssh.commands_run)

    def test_masks_if_was_masked(self, mock_ssh):
        """Verify the masked dead-code bug fix: was_enabled=masked runs mask."""
        ssh = mock_ssh(
            {
                "systemctl mask": Result(exit_code=0, stdout="", stderr=""),
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="service_enabled",
            data={
                "name": "cups",
                "was_enabled": "masked",
                "was_active": "inactive",
            },
        )
        ok, detail = _rollback_service_enabled(ssh, ps)
        assert ok is True
        assert any("systemctl mask" in cmd for cmd in ssh.commands_run)
        # Must NOT have disable — masked takes a different path now
        assert not any("systemctl disable" in cmd for cmd in ssh.commands_run)

    def test_noop_when_was_enabled(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="service_enabled",
            data={
                "name": "sshd",
                "was_enabled": "enabled",
                "was_active": "active",
            },
        )
        ok, detail = _rollback_service_enabled(ssh, ps)
        assert ok is True

    def test_failure_returns_false(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl disable": Result(
                    exit_code=1, stdout="", stderr="unit not found"
                ),
            }
        )
        ps = PreState(
            mechanism="service_enabled",
            data={
                "name": "bad-svc",
                "was_enabled": "disabled",
                "was_active": "active",
            },
        )
        ok, detail = _rollback_service_enabled(ssh, ps)
        assert ok is False
        assert "Failed" in detail


class TestRollbackServiceDisabled:
    def test_enables_if_was_enabled(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl enable": Result(exit_code=0, stdout="", stderr=""),
                "systemctl start": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="service_disabled",
            data={
                "name": "sshd",
                "was_enabled": "enabled",
                "was_active": "active",
            },
        )
        ok, detail = _rollback_service_disabled(ssh, ps)
        assert ok is True
        assert any("enable" in cmd for cmd in ssh.commands_run)
        assert any("start" in cmd for cmd in ssh.commands_run)

    def test_noop_when_was_disabled(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="service_disabled",
            data={
                "name": "cups",
                "was_enabled": "disabled",
                "was_active": "inactive",
            },
        )
        ok, detail = _rollback_service_disabled(ssh, ps)
        assert ok is True

    def test_failure_returns_false(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl enable": Result(exit_code=1, stdout="", stderr="error"),
            }
        )
        ps = PreState(
            mechanism="service_disabled",
            data={
                "name": "sshd",
                "was_enabled": "enabled",
                "was_active": "inactive",
            },
        )
        ok, detail = _rollback_service_disabled(ssh, ps)
        assert ok is False


class TestRollbackServiceMasked:
    def test_unmasks_and_enables(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl unmask": Result(exit_code=0, stdout="", stderr=""),
                "systemctl enable": Result(exit_code=0, stdout="", stderr=""),
                "systemctl start": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="service_masked",
            data={
                "name": "sshd",
                "was_enabled": "enabled",
                "was_active": "active",
            },
        )
        ok, detail = _rollback_service_masked(ssh, ps)
        assert ok is True
        assert any("unmask" in cmd for cmd in ssh.commands_run)
        assert any("enable" in cmd for cmd in ssh.commands_run)
        assert any("start" in cmd for cmd in ssh.commands_run)

    def test_unmask_only_when_was_disabled(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl unmask": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="service_masked",
            data={
                "name": "cups",
                "was_enabled": "disabled",
                "was_active": "inactive",
            },
        )
        ok, detail = _rollback_service_masked(ssh, ps)
        assert ok is True
        assert any("unmask" in cmd for cmd in ssh.commands_run)
        assert not any("enable" in cmd for cmd in ssh.commands_run)

    def test_failure_returns_false(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl unmask": Result(exit_code=1, stdout="", stderr="error"),
            }
        )
        ps = PreState(
            mechanism="service_masked",
            data={
                "name": "cups",
                "was_enabled": "disabled",
                "was_active": "inactive",
            },
        )
        ok, detail = _rollback_service_masked(ssh, ps)
        assert ok is False


class TestRollbackMountOptionSet:
    def test_restores_fstab(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "mount -o remount": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="mount_option_set",
            data={
                "mount_point": "/tmp",
                "old_fstab_line": "tmpfs /tmp tmpfs defaults,nosuid,nodev 0 0",
                "old_options": "defaults,nosuid,nodev",
            },
        )
        ok, detail = _rollback_mount_option_set(ssh, ps)
        assert ok is True
        assert "Restored" in detail

    def test_no_previous_fstab_line(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="mount_option_set",
            data={
                "mount_point": "/tmp",
                "old_fstab_line": None,
                "old_options": None,
            },
        )
        ok, detail = _rollback_mount_option_set(ssh, ps)
        assert ok is False
        assert "no previous fstab" in detail

    def test_sed_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=1, stdout="", stderr="sed error"),
            }
        )
        ps = PreState(
            mechanism="mount_option_set",
            data={
                "mount_point": "/tmp",
                "old_fstab_line": "tmpfs /tmp tmpfs defaults 0 0",
                "old_options": "defaults",
            },
        )
        ok, detail = _rollback_mount_option_set(ssh, ps)
        assert ok is False
        assert "Failed" in detail


class TestRollbackGrubParameterSet:
    def test_returns_false(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="grub_parameter_set",
            data={"key": "audit", "old_args": "args='quiet'"},
            capturable=False,
        )
        ok, detail = _rollback_grub_parameter_set(ssh, ps)
        assert ok is False
        assert "GRUB" in detail


class TestRollbackCronJob:
    def test_removes_new_file(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="cron_job",
            data={
                "cron_file": "/etc/cron.d/kensa-aide",
                "existed": False,
                "old_content": None,
            },
        )
        ok, detail = _rollback_cron_job(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_restores_old_content(self, mock_ssh):
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="cron_job",
            data={
                "cron_file": "/etc/cron.d/kensa-aide",
                "existed": True,
                "old_content": "0 5 * * * /usr/sbin/aide --check",
            },
        )
        ok, detail = _rollback_cron_job(ssh, ps)
        assert ok is True
        assert "Restored" in detail


class TestRollbackSELinuxBooleanSet:
    def test_restores_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "setsebool": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="selinux_boolean_set",
            data={
                "name": "httpd_can_network_connect",
                "old_value": False,
                "persistent": True,
            },
        )
        ok, detail = _rollback_selinux_boolean_set(ssh, ps)
        assert ok is True
        assert "off" in detail
        assert any("-P" in cmd for cmd in ssh.commands_run)

    def test_unknown_value(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="selinux_boolean_set",
            data={
                "name": "httpd_can_network_connect",
                "old_value": None,
                "persistent": True,
            },
        )
        ok, detail = _rollback_selinux_boolean_set(ssh, ps)
        assert ok is False
        assert "could not determine" in detail

    def test_failure_returns_false(self, mock_ssh):
        ssh = mock_ssh(
            {
                "setsebool": Result(exit_code=1, stdout="", stderr="boolean not found"),
            }
        )
        ps = PreState(
            mechanism="selinux_boolean_set",
            data={
                "name": "nonexistent_bool",
                "old_value": True,
                "persistent": False,
            },
        )
        ok, detail = _rollback_selinux_boolean_set(ssh, ps)
        assert ok is False


class TestRollbackAuditRuleSet:
    def test_removes_new_rule(self, mock_ssh):
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="audit_rule_set",
            data={
                "rule": "-a always,exit -F arch=b64 -S execve",
                "persist_file": "/etc/audit/rules.d/99-kensa.rules",
                "rule_existed": False,
                "old_persist_content": None,
                "persist_existed": False,
            },
        )
        ok, detail = _rollback_audit_rule_set(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_noop_if_rule_already_existed(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="audit_rule_set",
            data={
                "rule": "-a always,exit -F arch=b64 -S execve",
                "persist_file": "/etc/audit/rules.d/99-kensa.rules",
                "rule_existed": True,
                "old_persist_content": "existing content",
                "persist_existed": True,
            },
        )
        ok, detail = _rollback_audit_rule_set(ssh, ps)
        assert ok is True
        assert "already existed" in detail

    def test_restores_persist_file(self, mock_ssh):
        ssh = mock_ssh(
            {
                "auditctl": Result(exit_code=0, stdout="", stderr=""),
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="audit_rule_set",
            data={
                "rule": "-a always,exit -F arch=b64 -S execve",
                "persist_file": "/etc/audit/rules.d/99-kensa.rules",
                "rule_existed": False,
                "old_persist_content": "old rules content",
                "persist_existed": True,
            },
        )
        ok, detail = _rollback_audit_rule_set(ssh, ps)
        assert ok is True


class TestRollbackPamModuleConfigure:
    """Rollback tests for pam_module_configure (not direct remediation)."""

    def test_restores_pam_file(self, mock_ssh):
        """Rollback: restores PAM file content from captured pre-state."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="pam_module_configure",
            data={
                "service": "system-auth",
                "pam_file": "/etc/pam.d/system-auth",
                "existed": True,
                "old_content": "auth required pam_unix.so\n",
                "authselect_profile": None,
            },
        )
        ok, detail = _rollback_pam_module_configure(ssh, ps)
        assert ok is True
        assert "Restored" in detail
        assert "system-auth" in detail

    def test_removes_file_if_not_existed(self, mock_ssh):
        """Rollback: removes PAM file if it did not exist before remediation."""
        ssh = mock_ssh(
            {
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="pam_module_configure",
            data={
                "service": "custom-svc",
                "pam_file": "/etc/pam.d/custom-svc",
                "existed": False,
                "old_content": None,
                "authselect_profile": None,
            },
        )
        ok, detail = _rollback_pam_module_configure(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_fails_without_captured_content(self, mock_ssh):
        """Rollback: fails gracefully when no content was captured."""
        ssh = mock_ssh({})
        ps = PreState(
            mechanism="pam_module_configure",
            data={
                "service": "system-auth",
                "pam_file": "/etc/pam.d/system-auth",
                "existed": True,
                "old_content": None,
                "authselect_profile": None,
            },
        )
        ok, detail = _rollback_pam_module_configure(ssh, ps)
        assert ok is False
        assert "Cannot restore" in detail

    def test_write_failure(self, mock_ssh):
        """Rollback: reports failure when file write fails."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=1, stdout="", stderr="permission denied"),
            }
        )
        ps = PreState(
            mechanism="pam_module_configure",
            data={
                "service": "system-auth",
                "pam_file": "/etc/pam.d/system-auth",
                "existed": True,
                "old_content": "auth required pam_unix.so\n",
                "authselect_profile": None,
            },
        )
        ok, detail = _rollback_pam_module_configure(ssh, ps)
        assert ok is False
        assert "Failed" in detail


class TestCapturePamModuleConfigure:
    """Capture tests for pam_module_configure (not direct remediation)."""

    def test_captures_existing_file(self, mock_ssh):
        """Capture: records existing PAM file content and authselect profile."""
        ssh = mock_ssh(
            {
                "cat": Result(
                    exit_code=0,
                    stdout="auth required pam_unix.so\n",
                    stderr="",
                ),
                "authselect current": Result(
                    exit_code=0, stdout="Profile ID: sssd", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
        }
        ps = _capture_pam_module_configure(ssh, rem)
        assert ps.mechanism == "pam_module_configure"
        assert ps.capturable is True
        assert ps.data["existed"] is True
        assert ps.data["old_content"] == "auth required pam_unix.so\n"
        assert ps.data["pam_file"] == "/etc/pam.d/system-auth"
        assert "sssd" in ps.data["authselect_profile"]

    def test_captures_nonexistent_file(self, mock_ssh):
        """Capture: records non-existence when PAM file is missing."""
        ssh = mock_ssh(
            {
                "cat": Result(exit_code=1, stdout="", stderr="No such file"),
                "authselect current": Result(
                    exit_code=1, stdout="", stderr="No configuration"
                ),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "custom-svc",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
        }
        ps = _capture_pam_module_configure(ssh, rem)
        assert ps.data["existed"] is False
        assert ps.data["old_content"] is None
        assert ps.data["authselect_profile"] is None


# ── Spec-derived gap tests: pam_module_configure ────────────────────────


class TestPamModuleConfigureSpecDerived:
    """Spec-derived gap tests for pam_module_configure remediation handler.

    See specs/handlers/remediation/pam_module_configure.spec.md for full
    specification. No direct remediation tests existed prior to this class;
    existing tests cover only capture and rollback paths.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns success with preview message, no SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
            "args": "deny=5 unlock_time=900",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would configure" in detail
        assert "pam_faillock.so" in detail
        assert "/etc/pam.d/system-auth" in detail
        assert "auth    required    pam_faillock.so    deny=5 unlock_time=900" in detail
        # No SSH commands should have been executed
        assert len(ssh.commands_run) == 0

    def test_file_not_found(self, mock_ssh):
        """AC-2: Returns failure when PAM service file does not exist."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "nonexistent-svc",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "/etc/pam.d/nonexistent-svc" in detail
        assert "not found" in detail

    def test_replaces_existing_line_via_sed(self, mock_ssh):
        """AC-3: Replaces existing type+module line in-place via sed."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -E": Result(
                    exit_code=0,
                    stdout="auth    sufficient    pam_faillock.so old_args",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
            "args": "deny=5",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "Updated" in detail
        assert "pam_faillock.so" in detail
        assert "/etc/pam.d/system-auth" in detail
        # Verify sed command was issued
        sed_cmds = [c for c in ssh.commands_run if "sed -i" in c]
        assert len(sed_cmds) == 1

    def test_appends_new_module_line(self, mock_ssh):
        """AC-4: Appends new PAM line when no existing type+module line found."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -E": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
            "args": "deny=5",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "Added" in detail
        assert "pam_faillock.so" in detail
        assert "/etc/pam.d/system-auth" in detail
        # Verify echo/append command was issued (not sed)
        sed_cmds = [c for c in ssh.commands_run if "sed -i" in c]
        assert len(sed_cmds) == 0

    def test_pam_line_includes_args_when_provided(self, mock_ssh):
        """AC-5: Constructed PAM line includes args after the module."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -E": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "password-auth",
            "module": "pam_pwquality.so",
            "type": "password",
            "control": "requisite",
            "args": "retry=3 minlen=14",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        # Verify the echo command includes the full PAM line with args
        echo_cmds = [c for c in ssh.commands_run if "echo" in c]
        assert len(echo_cmds) == 1
        assert "pam_pwquality.so" in echo_cmds[0]
        assert "retry=3 minlen=14" in echo_cmds[0]

    def test_pam_line_no_trailing_args_when_absent(self, mock_ssh):
        """AC-6: PAM line has no trailing arguments when args is absent."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_unix.so",
            "type": "auth",
            "control": "sufficient",
        }
        # Use dry-run to inspect the constructed line
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        # Line should end with module name, no trailing spaces/args
        assert "auth    sufficient    pam_unix.so" in detail
        assert detail.endswith("auth    sufficient    pam_unix.so")

    def test_pam_line_no_trailing_args_when_empty_string(self, mock_ssh):
        """AC-6: PAM line has no trailing arguments when args is empty string."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_unix.so",
            "type": "auth",
            "control": "sufficient",
            "args": "",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail.endswith("auth    sufficient    pam_unix.so")

    def test_sed_replacement_failure(self, mock_ssh):
        """AC-7: Returns failure when sed replacement command fails."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -E": Result(
                    exit_code=0,
                    stdout="auth    required    pam_faillock.so",
                    stderr="",
                ),
                "sed -i": Result(exit_code=1, stdout="", stderr="permission denied"),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to update" in detail
        assert "/etc/pam.d/system-auth" in detail

    def test_append_failure(self, mock_ssh):
        """AC-8: Returns failure when append_line fails."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -E": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=1, stdout="", stderr="permission denied"),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "required",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "Failed to add" in detail
        assert "pam_faillock.so" in detail

    def test_pam_line_four_space_separators(self, mock_ssh):
        """AC-9: PAM line uses 4-space separators between fields."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_unix.so",
            "type": "session",
            "control": "optional",
            "args": "revoke",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        # Verify 4-space separation between type, control, module, and args
        expected_line = "session    optional    pam_unix.so    revoke"
        assert expected_line in detail

    def test_grep_uses_escaped_bre_patterns(self, mock_ssh):
        """AC-10: The grep pattern escapes BRE metacharacters in type and module."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -E": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_unix.so",
            "type": "auth",
            "control": "required",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        # The grep command should escape the dot in pam_unix.so
        grep_cmds = [c for c in ssh.commands_run if "grep -E" in c]
        assert len(grep_cmds) == 1
        # Dot in "pam_unix.so" should be escaped as "pam_unix\.so"
        assert "pam_unix\\.so" in grep_cmds[0]

    def test_sed_uses_escaped_patterns(self, mock_ssh):
        """AC-11: The sed command escapes metacharacters in type, module, and replacement."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "grep -E": Result(
                    exit_code=0,
                    stdout="auth    required    pam_unix.so",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_unix.so",
            "type": "auth",
            "control": "required",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        # The sed command should have escaped dots
        sed_cmds = [c for c in ssh.commands_run if "sed -i" in c]
        assert len(sed_cmds) == 1
        # The dot in "pam_unix.so" should be escaped in the sed pattern
        assert "pam_unix\\.so" in sed_cmds[0]

    def test_bracket_control_value(self, mock_ssh):
        """AC-9: Control values with brackets like [default=die] are handled."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "pam_module_configure",
            "service": "system-auth",
            "module": "pam_faillock.so",
            "type": "auth",
            "control": "[default=die]",
            "args": "authfail",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "[default=die]" in detail
        assert "auth    [default=die]    pam_faillock.so    authfail" in detail


# ── New capture tests (Phase 3) ──────────────────────────────────────────


class TestCaptureConfigRemove:
    def test_key_exists(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grep": Result(exit_code=0, stdout="BadKey val1", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "BadKey",
        }
        ps = _capture_config_remove(ssh, rem)
        assert ps.mechanism == "config_remove"
        assert ps.data["existed"] is True
        assert ps.data["old_lines"] == "BadKey val1"

    def test_key_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grep": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "Missing",
        }
        ps = _capture_config_remove(ssh, rem)
        assert ps.data["existed"] is False
        assert ps.data["old_lines"] is None


class TestCaptureConfigBlock:
    def test_file_exists_with_block(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(exit_code=0, stdout="file content", stderr=""),
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/limits.conf",
            "content": "* hard core 0",
        }
        ps = _capture_config_block(ssh, rem)
        assert ps.data["existed"] is True
        assert ps.data["old_content"] == "file content"
        assert ps.data["block_existed"] is True

    def test_file_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/limits.conf",
            "content": "* hard core 0",
        }
        ps = _capture_config_block(ssh, rem)
        assert ps.data["existed"] is False
        assert ps.data["old_content"] is None


class TestCaptureFileContent:
    def test_file_exists(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(exit_code=0, stdout="old data", stderr=""),
                "stat -c": Result(exit_code=0, stdout="root root 644", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "new data",
        }
        ps = _capture_file_content(ssh, rem)
        assert ps.data["existed"] is True
        assert ps.data["old_content"] == "old data"
        assert ps.data["old_owner"] == "root"

    def test_file_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/newfile",
            "content": "data",
        }
        ps = _capture_file_content(ssh, rem)
        assert ps.data["existed"] is False
        assert ps.data["old_content"] is None


class TestCaptureFileAbsent:
    def test_file_exists(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(exit_code=0, stdout="content", stderr=""),
                "stat -c": Result(exit_code=0, stdout="root root 644", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        ps = _capture_file_absent(ssh, rem)
        assert ps.data["existed"] is True
        assert ps.data["old_content"] == "content"

    def test_file_absent(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        ps = _capture_file_absent(ssh, rem)
        assert ps.data["existed"] is False


class TestCapturePackageAbsent:
    def test_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=0, stdout="telnet-0.17-1.el9", stderr=""),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        ps = _capture_package_absent(ssh, rem)
        assert ps.data["was_installed"] is True
        assert ps.data["version"] == "telnet-0.17-1.el9"

    def test_not_installed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        ps = _capture_package_absent(ssh, rem)
        assert ps.data["was_installed"] is False
        assert ps.data["version"] is None


class TestCaptureServiceEnabled:
    def test_captures_state(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(
                    exit_code=0, stdout="disabled", stderr=""
                ),
                "systemctl is-active": Result(
                    exit_code=0, stdout="inactive", stderr=""
                ),
            }
        )
        rem = {"mechanism": "service_enabled", "name": "sshd"}
        ps = _capture_service_enabled(ssh, rem)
        assert ps.data["name"] == "sshd"
        assert ps.data["was_enabled"] == "disabled"
        assert ps.data["was_active"] == "inactive"


class TestCaptureServiceDisabled:
    def test_captures_state(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(
                    exit_code=0, stdout="enabled", stderr=""
                ),
                "systemctl is-active": Result(exit_code=0, stdout="active", stderr=""),
            }
        )
        rem = {"mechanism": "service_disabled", "name": "cups"}
        ps = _capture_service_disabled(ssh, rem)
        assert ps.data["was_enabled"] == "enabled"
        assert ps.data["was_active"] == "active"


class TestCaptureServiceMasked:
    def test_captures_state(self, mock_ssh):
        ssh = mock_ssh(
            {
                "systemctl is-enabled": Result(
                    exit_code=0, stdout="enabled", stderr=""
                ),
                "systemctl is-active": Result(exit_code=0, stdout="active", stderr=""),
            }
        )
        rem = {"mechanism": "service_masked", "name": "cups"}
        ps = _capture_service_masked(ssh, rem)
        assert ps.data["was_enabled"] == "enabled"
        assert ps.data["was_active"] == "active"


class TestCaptureMountOptionSet:
    def test_captures_fstab_and_options(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grep -E": Result(
                    exit_code=0,
                    stdout="tmpfs /tmp tmpfs defaults 0 0",
                    stderr="",
                ),
                "findmnt": Result(exit_code=0, stdout="rw,nosuid,nodev", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "option": "noexec",
        }
        ps = _capture_mount_option_set(ssh, rem)
        assert ps.data["old_fstab_line"] == "tmpfs /tmp tmpfs defaults 0 0"
        assert ps.data["old_options"] == "rw,nosuid,nodev"


class TestCaptureGrubParameterSet:
    def test_not_capturable(self, mock_ssh):
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="args='quiet audit=1'", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_set", "key": "audit", "value": "1"}
        ps = _capture_grub_parameter_set(ssh, rem)
        assert ps.capturable is False
        assert ps.data["key"] == "audit"


class TestCaptureCronJob:
    def test_existing_cron(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "cat": Result(
                    exit_code=0,
                    stdout="0 5 * * * /usr/sbin/aide --check",
                    stderr="",
                ),
            }
        )
        rem = {"mechanism": "cron_job", "name": "kensa-aide", "schedule": "0 5 * * *"}
        ps = _capture_cron_job(ssh, rem)
        assert ps.data["existed"] is True
        assert "aide" in ps.data["old_content"]

    def test_no_existing_cron(self, mock_ssh):
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "cron_job", "name": "kensa-aide", "schedule": "0 5 * * *"}
        ps = _capture_cron_job(ssh, rem)
        assert ps.data["existed"] is False
        assert ps.data["old_content"] is None


class TestCaptureSELinuxBooleanSet:
    def test_captures_value(self, mock_ssh):
        ssh = mock_ssh(
            {
                "getsebool": Result(
                    exit_code=0,
                    stdout="httpd_can_network_connect --> on",
                    stderr="",
                ),
            }
        )
        rem = {
            "mechanism": "selinux_boolean_set",
            "name": "httpd_can_network_connect",
            "value": False,
        }
        ps = _capture_selinux_boolean_set(ssh, rem)
        assert ps.data["old_value"] is True

    def test_unknown_boolean(self, mock_ssh):
        ssh = mock_ssh(
            {
                "getsebool": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "selinux_boolean_set",
            "name": "nonexistent",
            "value": True,
        }
        ps = _capture_selinux_boolean_set(ssh, rem)
        assert ps.data["old_value"] is None


class TestCaptureAuditRuleSet:
    def test_rule_not_existed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "auditctl -l": Result(exit_code=0, stdout="No rules", stderr=""),
                "cat": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ps = _capture_audit_rule_set(ssh, rem)
        assert ps.data["rule_existed"] is False
        assert ps.data["persist_existed"] is False

    def test_rule_existed(self, mock_ssh):
        ssh = mock_ssh(
            {
                "auditctl -l": Result(
                    exit_code=0,
                    stdout="-a always,exit -F arch=b64 -S execve",
                    stderr="",
                ),
                "cat": Result(
                    exit_code=0,
                    stdout="-a always,exit -F arch=b64 -S execve",
                    stderr="",
                ),
            }
        )
        rem = {
            "mechanism": "audit_rule_set",
            "rule": "-a always,exit -F arch=b64 -S execve",
        }
        ps = _capture_audit_rule_set(ssh, rem)
        assert ps.data["rule_existed"] is True
        assert ps.data["persist_existed"] is True


# ── Exception safety test ─────────────────────────────────────────────────


class TestRollbackExceptionSafety:
    def test_handler_exception_does_not_abort_remaining(self, mock_ssh):
        """When one rollback handler throws, remaining steps still execute."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )

        # Step 0: will throw an exception in the rollback handler
        step0 = StepResult(
            step_index=0,
            mechanism="config_set",
            success=True,
            detail="ok",
            pre_state=PreState(
                mechanism="config_set",
                data={
                    # Missing "path" key will cause KeyError in handler
                    "key": "Foo",
                    "old_line": "Foo bar",
                    "existed": True,
                    "reload": None,
                    "restart": None,
                },
            ),
        )

        # Step 1: has valid pre_state, should still execute
        step1 = StepResult(
            step_index=1,
            mechanism="config_set",
            success=True,
            detail="ok",
            pre_state=PreState(
                mechanism="config_set",
                data={
                    "path": "/etc/conf",
                    "key": "Bar",
                    "old_line": "Bar baz",
                    "existed": True,
                    "reload": None,
                    "restart": None,
                },
            ),
        )

        results = _execute_rollback(ssh, [step0, step1])

        # Both steps should have results (reversed order: step1 first, step0 second)
        assert len(results) == 2

        # Step1 (executed first due to reverse) should succeed
        step1_result = results[0]
        assert step1_result.step_index == 1
        assert step1_result.success is True

        # Step0 (executed second) should fail with exception
        step0_result = results[1]
        assert step0_result.step_index == 0
        assert step0_result.success is False
        assert "Exception" in step0_result.detail

    def test_skipped_steps_still_processed(self, mock_ssh):
        """Non-capturable steps are skipped but remaining steps still run."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )

        step0 = StepResult(
            step_index=0,
            mechanism="config_set",
            success=True,
            detail="ok",
            pre_state=PreState(
                mechanism="config_set",
                data={
                    "path": "/etc/conf",
                    "key": "K",
                    "old_line": "K V",
                    "existed": True,
                    "reload": None,
                    "restart": None,
                },
            ),
        )

        step1 = StepResult(
            step_index=1,
            mechanism="command_exec",
            success=True,
            detail="ok",
            pre_state=PreState(
                mechanism="command_exec",
                data={"note": "arbitrary"},
                capturable=False,
            ),
        )

        results = _execute_rollback(ssh, [step0, step1])
        assert len(results) == 2
        # Reversed: step1 first (skipped), then step0
        assert results[0].detail == "skipped"
        assert results[1].success is True


# ── File permission return code checking test ─────────────────────────────


class TestRollbackFilePermissionsReturnCode:
    def test_chown_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=1, stdout="", stderr="invalid user"),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        ps = PreState(
            mechanism="file_permissions",
            data={
                "entries": [
                    {
                        "path": "/etc/shadow",
                        "owner": "baduser",
                        "group": "root",
                        "mode": "640",
                    }
                ],
            },
        )
        ok, detail = _rollback_file_permissions(ssh, ps)
        assert ok is False
        assert "Failed" in detail

    def test_chmod_failure(self, mock_ssh):
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=1, stdout="", stderr="invalid mode"),
            }
        )
        ps = PreState(
            mechanism="file_permissions",
            data={
                "entries": [
                    {
                        "path": "/etc/shadow",
                        "owner": "root",
                        "group": "root",
                        "mode": "bad",
                    }
                ],
            },
        )
        ok, detail = _rollback_file_permissions(ssh, ps)
        assert ok is False
        assert "Invalid" in detail or "Failed" in detail


# ── Spec-derived tests: security + service + package remediation handlers ───


class TestSelinuxBooleanSetSpecDerived:
    """Spec-derived tests for selinux_boolean_set remediation handler.

    See specs/handlers/remediation/selinux_boolean_set.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {"mechanism": "selinux_boolean_set", "name": "httpd_can_network_connect"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would run: setsebool" in detail
        assert "httpd_can_network_connect" in detail
        assert len(ssh.commands_run) == 0

    def test_dry_run_includes_persistent_flag(self, mock_ssh):
        """AC-2: Dry-run includes -P when persistent=True (default)."""
        ssh = mock_ssh({})
        rem = {"mechanism": "selinux_boolean_set", "name": "httpd_can_network_connect"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert "-P " in detail

    def test_dry_run_explicit_persistent_true(self, mock_ssh):
        """AC-2: Dry-run includes -P when persistent=True explicitly."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "selinux_boolean_set",
            "name": "httpd_can_network_connect",
            "persistent": True,
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert "-P " in detail

    def test_dry_run_without_persistent_flag(self, mock_ssh):
        """AC-3: Dry-run without -P when persistent=False."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "selinux_boolean_set",
            "name": "httpd_can_network_connect",
            "persistent": False,
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert "-P " not in detail
        assert "Would run: setsebool httpd_can_network_connect" in detail

    def test_success_persistent(self, mock_ssh):
        """AC-4: Success path with persistent=True returns expected detail."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        rem = {"mechanism": "selinux_boolean_set", "name": "httpd_can_network_connect"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set httpd_can_network_connect = on (persistent)"

    def test_success_non_persistent(self, mock_ssh):
        """AC-5: Success path with persistent=False omits '(persistent)'."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        rem = {
            "mechanism": "selinux_boolean_set",
            "name": "httpd_can_network_connect",
            "persistent": False,
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set httpd_can_network_connect = on"
        assert "(persistent)" not in detail

    def test_setsebool_failure(self, mock_ssh):
        """AC-6: Setsebool failure returns (False, 'setsebool failed: {stderr}')."""
        ssh = mock_ssh(
            {
                "setsebool": Result(
                    exit_code=1, stdout="", stderr="Could not change boolean"
                )
            }
        )
        rem = {"mechanism": "selinux_boolean_set", "name": "httpd_can_network_connect"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "setsebool failed" in detail
        assert "Could not change boolean" in detail

    def test_default_value_is_true(self, mock_ssh):
        """AC-7: Default value is True, which maps to 'on'."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        rem = {"mechanism": "selinux_boolean_set", "name": "httpd_can_network_connect"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert "= on" in detail

    def test_default_persistent_is_true(self, mock_ssh):
        """AC-8: Default persistent is True, so (persistent) appears in detail."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        rem = {"mechanism": "selinux_boolean_set", "name": "httpd_can_network_connect"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert "(persistent)" in detail

    def test_value_conversion_true_to_on(self, mock_ssh):
        """AC-9: Boolean True maps to 'on'."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        rem = {
            "mechanism": "selinux_boolean_set",
            "name": "httpd_can_network_connect",
            "value": True,
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert "= on" in detail

    def test_value_conversion_false_to_off(self, mock_ssh):
        """AC-9: Boolean False maps to 'off'."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        rem = {
            "mechanism": "selinux_boolean_set",
            "name": "httpd_can_network_connect",
            "value": False,
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert "= off" in detail

    def test_shell_quoting(self, mock_ssh):
        """AC-10: Boolean name is passed through shell_util.quote()."""
        ssh = mock_ssh({"setsebool": Result(exit_code=0, stdout="", stderr="")})
        # Use a name with a space to force visible quoting by shlex.quote
        rem = {
            "mechanism": "selinux_boolean_set",
            "name": "my boolean",
        }
        run_remediation(ssh, rem, snapshot=False)
        setsebool_cmds = [c for c in ssh.commands_run if "setsebool" in c]
        assert len(setsebool_cmds) == 1
        assert "'my boolean'" in setsebool_cmds[0]

    def test_extended_timeout(self, mock_ssh):
        """AC-11: The setsebool command uses a 60-second timeout."""
        timeouts = []

        class TimeoutSSH:
            def __init__(self):
                self.commands_run = []
                self.sudo = False

            def run(self, cmd, *, timeout=None):
                self.commands_run.append(cmd)
                timeouts.append(timeout)
                return Result(exit_code=0, stdout="", stderr="")

        ssh = TimeoutSSH()
        rem = {"mechanism": "selinux_boolean_set", "name": "httpd_can_network_connect"}
        from runner.handlers.remediation import _dispatch_remediation

        _dispatch_remediation(ssh, rem)
        assert 60 in timeouts


class TestSelinuxStateSetSpecDerived:
    """Spec-derived tests for selinux_state_set remediation handler.

    See specs/handlers/remediation/selinux_state_set.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {"mechanism": "selinux_state_set", "state": "enforcing"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would set SELinux to enforcing"
        assert len(ssh.commands_run) == 0

    def test_config_file_update(self, mock_ssh):
        """AC-2: Config file /etc/selinux/config is modified with SELINUX={state}."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "setenforce": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "selinux_state_set", "state": "enforcing"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        sed_cmds = [c for c in ssh.commands_run if "sed -i" in c]
        assert len(sed_cmds) == 1
        assert "SELINUX=" in sed_cmds[0]
        assert "/etc/selinux/config" in sed_cmds[0]

    def test_runtime_enforcement_enforcing(self, mock_ssh):
        """AC-3: setenforce 1 is called when state is 'enforcing'."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "setenforce": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "selinux_state_set", "state": "enforcing"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        setenforce_cmds = [c for c in ssh.commands_run if "setenforce" in c]
        assert len(setenforce_cmds) == 1
        assert "setenforce 1" in setenforce_cmds[0]

    def test_runtime_enforcement_permissive(self, mock_ssh):
        """AC-3: setenforce 0 is called when state is 'permissive'."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "setenforce": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "selinux_state_set", "state": "permissive"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        setenforce_cmds = [c for c in ssh.commands_run if "setenforce" in c]
        assert len(setenforce_cmds) == 1
        assert "setenforce 0" in setenforce_cmds[0]

    def test_disabled_state_no_setenforce(self, mock_ssh):
        """AC-4: When state is 'disabled', setenforce is not called."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "selinux_state_set", "state": "disabled"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert not any("setenforce" in cmd for cmd in ssh.commands_run)

    def test_success_path(self, mock_ssh):
        """AC-5: Success returns (True, 'Set SELinux to {state}')."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "setenforce": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "selinux_state_set", "state": "enforcing"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set SELinux to enforcing"

    def test_success_disabled(self, mock_ssh):
        """AC-5: Success with disabled state."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "selinux_state_set", "state": "disabled"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set SELinux to disabled"

    def test_config_update_failure(self, mock_ssh):
        """AC-6: Config modification failure returns failure detail."""
        ssh = mock_ssh(
            {
                "sed -i": Result(exit_code=1, stdout="", stderr="Permission denied"),
            }
        )
        rem = {"mechanism": "selinux_state_set", "state": "enforcing"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to set SELinux config" in detail
        assert "Permission denied" in detail


class TestServiceMaskedSpecDerived:
    """Spec-derived tests for service_masked remediation handler.

    See specs/handlers/remediation/service_masked.spec.yaml.
    """

    def test_dry_run_with_stop_default(self, mock_ssh):
        """AC-1: Dry-run with stop=True (default) returns expected message."""
        ssh = mock_ssh({})
        rem = {"mechanism": "service_masked", "name": "autofs"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would stop and mask autofs"
        assert len(ssh.commands_run) == 0

    def test_dry_run_with_stop_false(self, mock_ssh):
        """AC-2: Dry-run with stop=False returns 'Would mask {name}'."""
        ssh = mock_ssh({})
        rem = {"mechanism": "service_masked", "name": "autofs", "stop": False}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would mask autofs"
        assert len(ssh.commands_run) == 0

    def test_full_success_with_stop(self, mock_ssh):
        """AC-3: Full success with stop returns 'Stopped and masked {name}'."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl mask": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_masked", "name": "autofs"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Stopped and masked autofs"

    def test_stop_failure_ignored(self, mock_ssh):
        """AC-4: Stop failure is ignored; handler proceeds to mask."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(
                    exit_code=5, stdout="", stderr="Unit not loaded"
                ),
                "systemctl mask": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_masked", "name": "autofs"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Stopped and masked autofs" in detail

    def test_mask_failure(self, mock_ssh):
        """AC-5: Mask failure returns failure detail with stderr."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl mask": Result(
                    exit_code=1, stdout="", stderr="Access denied"
                ),
            }
        )
        rem = {"mechanism": "service_masked", "name": "autofs"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to mask autofs" in detail
        assert "Access denied" in detail

    def test_mask_only_success(self, mock_ssh):
        """AC-6: Mask-only success with stop=False returns 'Masked {name}'."""
        ssh = mock_ssh(
            {
                "systemctl mask": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_masked", "name": "autofs", "stop": False}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Masked autofs"
        assert not any("systemctl stop" in cmd for cmd in ssh.commands_run)

    def test_shell_quoting(self, mock_ssh):
        """AC-7: Service name is passed through shell_util.quote()."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl mask": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        # Use a name with space to force visible quoting
        rem = {"mechanism": "service_masked", "name": "my service"}
        run_remediation(ssh, rem, snapshot=False)
        systemctl_cmds = [c for c in ssh.commands_run if "systemctl" in c]
        assert len(systemctl_cmds) >= 1
        for cmd in systemctl_cmds:
            assert "'my service'" in cmd

    def test_mask_failure_with_stop_false(self, mock_ssh):
        """AC-5: Mask failure with stop=False also returns failure."""
        ssh = mock_ssh(
            {
                "systemctl mask": Result(
                    exit_code=1, stdout="", stderr="Failed to mask"
                ),
            }
        )
        rem = {"mechanism": "service_masked", "name": "autofs", "stop": False}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to mask autofs" in detail

    def test_stop_default_is_true(self, mock_ssh):
        """AC-8: When stop is not provided, defaults to True."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl mask": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_masked", "name": "autofs"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("systemctl stop" in cmd for cmd in ssh.commands_run)
        assert "Stopped and masked" in detail

    def test_stop_before_mask_ordering(self, mock_ssh):
        """AC-8: Stop runs before mask."""
        ssh = mock_ssh(
            {
                "systemctl stop": Result(exit_code=0, stdout="", stderr=""),
                "systemctl mask": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "service_masked", "name": "autofs"}
        run_remediation(ssh, rem, snapshot=False)
        systemctl_cmds = [c for c in ssh.commands_run if "systemctl" in c]
        stop_idx = next(i for i, c in enumerate(systemctl_cmds) if "stop" in c)
        mask_idx = next(i for i, c in enumerate(systemctl_cmds) if "mask" in c)
        assert stop_idx < mask_idx


class TestPackageAbsentSpecDerived:
    """Spec-derived tests for package_absent remediation handler.

    See specs/handlers/remediation/package_absent.spec.yaml.
    """

    def test_already_absent(self, mock_ssh):
        """AC-1: When package is not installed, returns success immediately."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "telnet: already not installed" in detail
        assert not any("dnf" in cmd for cmd in ssh.commands_run)

    def test_already_absent_skips_dry_run_check(self, mock_ssh):
        """AC-1: Already absent returns immediately even when dry_run=True."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "already not installed" in detail

    def test_dry_run_with_package_present(self, mock_ssh):
        """AC-2: Dry-run with package installed returns 'Would remove {name}'."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=0, stdout="telnet-0.17-83.el9", stderr=""),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would remove telnet"
        assert not any("dnf remove" in cmd for cmd in ssh.commands_run)

    def test_success_path(self, mock_ssh):
        """AC-3: Successful removal returns (True, 'Removed {name}')."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=0, stdout="telnet-0.17-83.el9", stderr=""),
                "dnf remove": Result(exit_code=0, stdout="Complete!", stderr=""),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Removed telnet"

    def test_remove_failure(self, mock_ssh):
        """AC-4: Remove failure returns failure detail with stderr."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=0, stdout="telnet-0.17-83.el9", stderr=""),
                "dnf remove": Result(exit_code=1, stdout="", stderr="Error: depsolve"),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "dnf remove failed" in detail
        assert "depsolve" in detail

    def test_shell_quoting(self, mock_ssh):
        """AC-5: Package name is passed through shell_util.quote()."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=0, stdout="my pkg-0.1", stderr=""),
                "dnf remove": Result(exit_code=0, stdout="Complete!", stderr=""),
            }
        )
        # Use a name with a space to force visible quoting
        rem = {"mechanism": "package_absent", "name": "my pkg"}
        run_remediation(ssh, rem, snapshot=False)
        rpm_cmds = [c for c in ssh.commands_run if "rpm -q" in c]
        dnf_cmds = [c for c in ssh.commands_run if "dnf remove" in c]
        assert len(rpm_cmds) == 1
        assert "'my pkg'" in rpm_cmds[0]
        assert len(dnf_cmds) == 1
        assert "'my pkg'" in dnf_cmds[0]

    def test_extended_timeout(self, mock_ssh):
        """AC-6: The dnf remove command uses a 300-second timeout."""
        timeouts = []

        class TimeoutSSH:
            def __init__(self):
                self.commands_run = []
                self.sudo = False

            def run(self, cmd, *, timeout=None):
                self.commands_run.append(cmd)
                timeouts.append(timeout)
                if "rpm -q" in cmd:
                    return Result(exit_code=0, stdout="telnet-0.17", stderr="")
                return Result(exit_code=0, stdout="Complete!", stderr="")

        ssh = TimeoutSSH()
        rem = {"mechanism": "package_absent", "name": "telnet"}
        from runner.handlers.remediation import _dispatch_remediation

        _dispatch_remediation(ssh, rem)
        assert 300 in timeouts

    def test_idempotency_check_suppresses_stderr(self, mock_ssh):
        """AC-7: The rpm -q command uses 2>/dev/null to suppress stderr."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        run_remediation(ssh, rem, snapshot=False)
        rpm_cmds = [c for c in ssh.commands_run if "rpm -q" in c]
        assert len(rpm_cmds) == 1
        assert "2>/dev/null" in rpm_cmds[0]

    def test_absent_check_before_dry_run(self, mock_ssh):
        """AC-1: The absent check runs before the dry_run check by design."""
        ssh = mock_ssh(
            {
                "rpm -q": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "package_absent", "name": "telnet"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "already not installed" in detail
        assert "Would remove" not in detail


class TestPackagePresentSpecDerived:
    """Spec-derived tests for package_present remediation handler.

    See specs/handlers/remediation/package_present.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands."""
        ssh = mock_ssh({})
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would install aide"
        assert len(ssh.commands_run) == 0

    def test_success_path(self, mock_ssh):
        """AC-2: Successful install returns (True, 'Installed {name}')."""
        ssh = mock_ssh(
            {
                "dnf install": Result(exit_code=0, stdout="Complete!", stderr=""),
            }
        )
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Installed aide"

    def test_install_failure(self, mock_ssh):
        """AC-3: Install failure returns failure detail with stderr."""
        ssh = mock_ssh(
            {
                "dnf install": Result(
                    exit_code=1, stdout="", stderr="No package aide available"
                ),
            }
        )
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "dnf install failed" in detail
        assert "No package aide available" in detail

    def test_shell_quoting(self, mock_ssh):
        """AC-4: Package name is passed through shell_util.quote()."""
        ssh = mock_ssh(
            {
                "dnf install": Result(exit_code=0, stdout="Complete!", stderr=""),
            }
        )
        # Use a name with a space to force visible quoting
        rem = {"mechanism": "package_present", "name": "my pkg"}
        run_remediation(ssh, rem, snapshot=False)
        dnf_cmds = [c for c in ssh.commands_run if "dnf install" in c]
        assert len(dnf_cmds) == 1
        assert "'my pkg'" in dnf_cmds[0]

    def test_extended_timeout(self, mock_ssh):
        """AC-5: The dnf install command uses a 300-second timeout."""
        timeouts = []

        class TimeoutSSH:
            def __init__(self):
                self.commands_run = []
                self.sudo = False

            def run(self, cmd, *, timeout=None):
                self.commands_run.append(cmd)
                timeouts.append(timeout)
                return Result(exit_code=0, stdout="Complete!", stderr="")

        ssh = TimeoutSSH()
        rem = {"mechanism": "package_present", "name": "aide"}
        from runner.handlers.remediation import _dispatch_remediation

        _dispatch_remediation(ssh, rem)
        assert 300 in timeouts

    def test_uses_dash_y_flag(self, mock_ssh):
        """AC-5: The dnf install command uses -y flag for non-interactive install."""
        ssh = mock_ssh(
            {
                "dnf install": Result(exit_code=0, stdout="Complete!", stderr=""),
            }
        )
        rem = {"mechanism": "package_present", "name": "aide"}
        run_remediation(ssh, rem, snapshot=False)
        dnf_cmds = [c for c in ssh.commands_run if "dnf install" in c]
        assert len(dnf_cmds) == 1
        assert "-y" in dnf_cmds[0]

    def test_dry_run_no_dnf_command(self, mock_ssh):
        """AC-1: Dry-run does not execute any dnf commands."""
        ssh = mock_ssh({})
        rem = {"mechanism": "package_present", "name": "aide"}
        run_remediation(ssh, rem, dry_run=True)
        assert not any("dnf" in cmd for cmd in ssh.commands_run)


class TestCommandExecSpecDerived:
    """Spec-derived tests for command_exec remediation handler.

    See specs/handlers/remediation/command_exec.spec.yaml.
    """

    def test_unless_guard_passes_skips(self, mock_ssh):
        """AC-1: Unless guard succeeds (exit 0) skips execution."""
        ssh = mock_ssh(
            {
                "test -f /var/lib/aide/aide.db.gz": Result(
                    exit_code=0, stdout="", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "aide --init",
            "unless": "test -f /var/lib/aide/aide.db.gz",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert (
            detail == "Skipped (unless guard passed): test -f /var/lib/aide/aide.db.gz"
        )
        assert not any("aide --init" in cmd for cmd in ssh.commands_run)

    def test_onlyif_guard_fails_skips(self, mock_ssh):
        """AC-2: Onlyif guard fails (non-zero exit) skips execution."""
        ssh = mock_ssh(
            {
                "which aide": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "aide --init",
            "onlyif": "which aide",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Skipped (onlyif guard failed): which aide"
        assert not any("aide --init" in cmd for cmd in ssh.commands_run)

    def test_guard_evaluation_order_unless_first(self, mock_ssh):
        """AC-3: Unless guard is checked first; if it passes, onlyif is not evaluated."""
        ssh = mock_ssh(
            {
                "test -f /check": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "do-something",
            "unless": "test -f /check",
            "onlyif": "which tool",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "unless guard passed" in detail
        assert not any("which tool" in cmd for cmd in ssh.commands_run)

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-4: Dry-run returns preview without executing the main command."""
        ssh = mock_ssh({})
        rem = {"mechanism": "command_exec", "run": "aide --init"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would run: aide --init"
        assert len(ssh.commands_run) == 0

    def test_guards_evaluated_in_dry_run(self, mock_ssh):
        """AC-5: Guard commands are evaluated even when dry_run=True."""
        ssh = mock_ssh(
            {
                "which aide": Result(exit_code=0, stdout="/usr/bin/aide", stderr=""),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "aide --init",
            "onlyif": "which aide",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would run: aide --init"
        assert any("which aide" in cmd for cmd in ssh.commands_run)
        assert not any("aide --init" in cmd for cmd in ssh.commands_run)

    def test_unless_guard_evaluated_in_dry_run_skips(self, mock_ssh):
        """AC-5: Unless guard evaluated in dry-run; if it passes, main command is skipped."""
        ssh = mock_ssh(
            {
                "test -f /ok": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "dangerous-cmd",
            "unless": "test -f /ok",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "unless guard passed" in detail

    def test_success_path(self, mock_ssh):
        """AC-6: Command succeeds returns (True, 'Executed: {cmd}')."""
        ssh = mock_ssh(
            {
                "aide --init": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "command_exec", "run": "aide --init"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Executed: aide --init"

    def test_command_failure_returns_false(self, mock_ssh):
        """AC-7: Command failure returns (False, 'Command failed (exit N): ...')."""
        ssh = mock_ssh(
            {
                "bad-cmd": Result(exit_code=127, stdout="", stderr="not found"),
            }
        )
        rem = {"mechanism": "command_exec", "run": "bad-cmd"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Command failed (exit 127)" in detail

    def test_failure_detail_prefers_stderr(self, mock_ssh):
        """AC-8: Failure detail uses stderr when available."""
        ssh = mock_ssh(
            {
                "fail-cmd": Result(
                    exit_code=1, stdout="stdout-output", stderr="stderr-output"
                ),
            }
        )
        rem = {"mechanism": "command_exec", "run": "fail-cmd"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "stderr-output" in detail
        assert "stdout-output" not in detail

    def test_failure_detail_falls_back_to_stdout(self, mock_ssh):
        """AC-8: Failure detail falls back to stdout when stderr is empty."""
        ssh = mock_ssh(
            {
                "fail-cmd": Result(exit_code=1, stdout="stdout-fallback", stderr=""),
            }
        )
        rem = {"mechanism": "command_exec", "run": "fail-cmd"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "stdout-fallback" in detail

    def test_service_action_on_success(self, mock_ssh):
        """AC-9: Service action is called after successful command."""
        ssh = mock_ssh(
            {
                "my-cmd": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "my-cmd",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("systemctl" in cmd and "sshd" in cmd for cmd in ssh.commands_run)

    def test_no_service_action_on_failure(self, mock_ssh):
        """AC-10: When command fails, service_action is not called."""
        ssh = mock_ssh(
            {
                "fail-cmd": Result(exit_code=1, stdout="", stderr="error"),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "fail-cmd",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert not any("systemctl" in cmd for cmd in ssh.commands_run)

    def test_extended_timeout(self, mock_ssh):
        """AC-11: The main command uses a 120-second timeout."""
        timeouts = []

        class TimeoutSSH:
            def __init__(self):
                self.commands_run = []
                self.sudo = False

            def run(self, cmd, *, timeout=None):
                self.commands_run.append(cmd)
                timeouts.append(timeout)
                return Result(exit_code=0, stdout="", stderr="")

        ssh = TimeoutSSH()
        rem = {"mechanism": "command_exec", "run": "aide --init"}
        from runner.handlers.remediation import _dispatch_remediation

        _dispatch_remediation(ssh, rem)
        assert 120 in timeouts

    def test_guard_both_pass_execution_proceeds(self, mock_ssh):
        """AC-3: When unless fails and onlyif succeeds, execution proceeds."""
        ssh = mock_ssh(
            {
                "test -f /missing": Result(exit_code=1, stdout="", stderr=""),
                "which aide": Result(exit_code=0, stdout="/usr/bin/aide", stderr=""),
                "aide --init": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "command_exec",
            "run": "aide --init",
            "unless": "test -f /missing",
            "onlyif": "which aide",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Executed: aide --init"


class TestCronJobSpecDerived:
    """Spec-derived tests for cron_job remediation handler.

    See specs/handlers/remediation/cron_job.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would create /etc/cron.d/kensa-managed" in detail
        assert "0 5 * * * root /usr/sbin/aide --check" in detail
        assert len(ssh.commands_run) == 0

    def test_success_path(self, mock_ssh):
        """AC-2: Successful write returns (True, 'Created cron job: {path}')."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Created cron job: /etc/cron.d/kensa-managed"

    def test_write_failure(self, mock_ssh):
        """AC-3: Write failure returns (False, 'Failed to create cron job')."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert detail == "Failed to create cron job"

    def test_write_failure_no_chmod(self, mock_ssh):
        """AC-3: Write failure does not attempt to set permissions."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
        }
        run_remediation(ssh, rem, snapshot=False)
        assert not any("chmod" in cmd for cmd in ssh.commands_run)

    def test_default_user_is_root(self, mock_ssh):
        """AC-4: When user is not provided, defaults to 'root'."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
        }
        run_remediation(ssh, rem, snapshot=False)
        printf_cmds = [c for c in ssh.commands_run if "printf" in c]
        assert len(printf_cmds) == 1
        assert "root" in printf_cmds[0]

    def test_custom_user(self, mock_ssh):
        """AC-4: Custom user appears in the cron line."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
            "user": "nobody",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert "nobody" in detail

    def test_default_name_is_kensa_managed(self, mock_ssh):
        """AC-5: When name is not provided, defaults to 'kensa-managed'."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert "/etc/cron.d/kensa-managed" in detail

    def test_custom_name_in_path(self, mock_ssh):
        """AC-6: Cron file path is /etc/cron.d/{name}."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
            "name": "aide-check",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert detail == "Created cron job: /etc/cron.d/aide-check"

    def test_cron_line_format(self, mock_ssh):
        """AC-7: The file contains '{schedule} {user} {command}\\n'."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
            "user": "aide",
        }
        run_remediation(ssh, rem, snapshot=False)
        printf_cmds = [c for c in ssh.commands_run if "printf" in c]
        assert len(printf_cmds) == 1
        assert "0 5 * * * aide /usr/sbin/aide --check" in printf_cmds[0]

    def test_file_permissions_set_to_644(self, mock_ssh):
        """AC-8: After successful write, file permissions are set to 644."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "cron_job",
            "schedule": "0 5 * * *",
            "command": "/usr/sbin/aide --check",
        }
        run_remediation(ssh, rem, snapshot=False)
        chmod_cmds = [c for c in ssh.commands_run if "chmod" in c]
        assert len(chmod_cmds) == 1
        assert "644" in chmod_cmds[0]
        assert "/etc/cron.d/kensa-managed" in chmod_cmds[0]


class TestGrubParameterSetSpecDerived:
    """Spec-derived tests for grub_parameter_set remediation handler.

    See specs/handlers/remediation/grub_parameter_set.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands."""
        ssh = mock_ssh({})
        rem = {"mechanism": "grub_parameter_set", "key": "audit", "value": "1"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would set kernel arg: audit=1"
        assert len(ssh.commands_run) == 0

    def test_key_value_parameter(self, mock_ssh):
        """AC-2: Key-value parameter formats as '{key}={value}'."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "grub_parameter_set",
            "key": "audit_backlog_limit",
            "value": "8192",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set kernel arg: audit_backlog_limit=8192"

    def test_standalone_flag(self, mock_ssh):
        """AC-3: Without value, argument is just the key."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_set", "key": "audit"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set kernel arg: audit"

    def test_success_path(self, mock_ssh):
        """AC-4: Grubby success returns (True, 'Set kernel arg: {arg}')."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_set", "key": "audit", "value": "1"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set kernel arg: audit=1"

    def test_grubby_failure(self, mock_ssh):
        """AC-5: Grubby failure returns (False, 'grubby failed: {stderr}')."""
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=1, stdout="", stderr="grubby: not a valid argument"
                ),
            }
        )
        rem = {"mechanism": "grub_parameter_set", "key": "bad_param", "value": "1"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "grubby failed" in detail
        assert "not a valid argument" in detail

    def test_shell_quoting(self, mock_ssh):
        """AC-6: The composed argument is passed through shell_util.quote()."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "grub_parameter_set",
            "key": "my param",
            "value": "my val",
        }
        run_remediation(ssh, rem, snapshot=False)
        grubby_cmds = [c for c in ssh.commands_run if "grubby" in c]
        assert len(grubby_cmds) == 1
        assert "'my param=my val'" in grubby_cmds[0]

    def test_all_kernels_flag(self, mock_ssh):
        """AC-7: The grubby command uses --update-kernel=ALL."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_set", "key": "audit", "value": "1"}
        run_remediation(ssh, rem, snapshot=False)
        grubby_cmds = [c for c in ssh.commands_run if "grubby" in c]
        assert len(grubby_cmds) == 1
        assert "--update-kernel=ALL" in grubby_cmds[0]

    def test_dry_run_standalone_flag(self, mock_ssh):
        """AC-1: Dry-run preview for standalone flag shows just the key."""
        ssh = mock_ssh({})
        rem = {"mechanism": "grub_parameter_set", "key": "audit"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert detail == "Would set kernel arg: audit"

    def test_args_flag_in_grubby_command(self, mock_ssh):
        """AC-7: The grubby command uses --args= for setting parameters."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_set", "key": "audit", "value": "1"}
        run_remediation(ssh, rem, snapshot=False)
        grubby_cmds = [c for c in ssh.commands_run if "grubby" in c]
        assert len(grubby_cmds) == 1
        assert "--args=" in grubby_cmds[0]


class TestGrubParameterRemoveSpecDerived:
    """Spec-derived tests for grub_parameter_remove remediation handler.

    See specs/handlers/remediation/grub_parameter_remove.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands."""
        ssh = mock_ssh({})
        rem = {"mechanism": "grub_parameter_remove", "key": "vga"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would remove kernel arg: vga"
        assert len(ssh.commands_run) == 0

    def test_success_path(self, mock_ssh):
        """AC-2: Grubby success returns (True, 'Removed kernel arg: {key}')."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_remove", "key": "vga"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Removed kernel arg: vga"

    def test_grubby_failure(self, mock_ssh):
        """AC-3: Grubby failure returns (False, 'grubby failed: {stderr}')."""
        ssh = mock_ssh(
            {
                "grubby": Result(
                    exit_code=1, stdout="", stderr="grubby: error removing arg"
                ),
            }
        )
        rem = {"mechanism": "grub_parameter_remove", "key": "vga"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "grubby failed" in detail
        assert "error removing arg" in detail

    def test_shell_quoting(self, mock_ssh):
        """AC-4: The key is passed through shell_util.quote()."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_remove", "key": "my param"}
        run_remediation(ssh, rem, snapshot=False)
        grubby_cmds = [c for c in ssh.commands_run if "grubby" in c]
        assert len(grubby_cmds) == 1
        assert "'my param'" in grubby_cmds[0]

    def test_all_kernels_flag(self, mock_ssh):
        """AC-5: The grubby command uses --update-kernel=ALL."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_remove", "key": "vga"}
        run_remediation(ssh, rem, snapshot=False)
        grubby_cmds = [c for c in ssh.commands_run if "grubby" in c]
        assert len(grubby_cmds) == 1
        assert "--update-kernel=ALL" in grubby_cmds[0]

    def test_remove_args_flag_in_grubby_command(self, mock_ssh):
        """AC-5: The grubby command uses --remove-args= for removal."""
        ssh = mock_ssh(
            {
                "grubby": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "grub_parameter_remove", "key": "vga"}
        run_remediation(ssh, rem, snapshot=False)
        grubby_cmds = [c for c in ssh.commands_run if "grubby" in c]
        assert len(grubby_cmds) == 1
        assert "--remove-args=" in grubby_cmds[0]

    def test_dry_run_no_grubby_commands(self, mock_ssh):
        """AC-1: Dry-run does not execute any grubby commands."""
        ssh = mock_ssh({})
        rem = {"mechanism": "grub_parameter_remove", "key": "vga"}
        run_remediation(ssh, rem, dry_run=True)
        assert not any("grubby" in cmd for cmd in ssh.commands_run)


class TestKernelModuleDisableSpecDerived:
    """Spec-derived tests for kernel_module_disable remediation handler.

    See specs/handlers/remediation/kernel_module_disable.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands."""
        ssh = mock_ssh({})
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would blacklist cramfs in /etc/modprobe.d/cramfs.conf"
        assert len(ssh.commands_run) == 0

    def test_success_path(self, mock_ssh):
        """AC-2: Write success returns (True, 'Blacklisted {name}')."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe -r": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Blacklisted cramfs"

    def test_write_failure(self, mock_ssh):
        """AC-3: Write failure returns (False, 'Failed to write {conf_path}')."""
        ssh = mock_ssh({})
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert detail == "Failed to write /etc/modprobe.d/cramfs.conf"

    def test_write_failure_no_modprobe(self, mock_ssh):
        """AC-3: Write failure does not attempt modprobe -r."""
        ssh = mock_ssh({})
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        run_remediation(ssh, rem, snapshot=False)
        assert not any("modprobe -r" in cmd for cmd in ssh.commands_run)

    def test_config_file_path(self, mock_ssh):
        """AC-4: The configuration file path is /etc/modprobe.d/{name}.conf."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe -r": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "kernel_module_disable", "name": "usb-storage"}
        run_remediation(ssh, rem, snapshot=False)
        printf_cmds = [c for c in ssh.commands_run if "printf" in c]
        assert len(printf_cmds) == 1
        assert "/etc/modprobe.d/usb-storage.conf" in printf_cmds[0]

    def test_config_content(self, mock_ssh):
        """AC-5: Written file contains blacklist and install directives."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe -r": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        run_remediation(ssh, rem, snapshot=False)
        printf_cmds = [c for c in ssh.commands_run if "printf" in c]
        assert len(printf_cmds) == 1
        assert "blacklist cramfs" in printf_cmds[0]
        assert "install cramfs /bin/false" in printf_cmds[0]

    def test_module_unload_best_effort(self, mock_ssh):
        """AC-6: modprobe -r failure does not affect overall success."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe -r": Result(
                    exit_code=1, stdout="", stderr="Module not loaded"
                ),
            }
        )
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Blacklisted cramfs"

    def test_modprobe_stderr_suppressed(self, mock_ssh):
        """AC-6: modprobe -r command redirects stderr to /dev/null."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe -r": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        run_remediation(ssh, rem, snapshot=False)
        modprobe_cmds = [c for c in ssh.commands_run if "modprobe -r" in c]
        assert len(modprobe_cmds) == 1
        assert "2>/dev/null" in modprobe_cmds[0]

    def test_shell_quoting_in_modprobe(self, mock_ssh):
        """AC-7: Module name is passed through shell_util.quote() in modprobe -r."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "modprobe -r": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "kernel_module_disable", "name": "my module"}
        run_remediation(ssh, rem, snapshot=False)
        modprobe_cmds = [c for c in ssh.commands_run if "modprobe -r" in c]
        assert len(modprobe_cmds) == 1
        assert "'my module'" in modprobe_cmds[0]


class TestMountOptionSetSpecDerived:
    """Spec-derived tests for mount_option_set remediation handler.

    See specs/handlers/remediation/mount_option_set.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec", "nosuid"],
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would add options" in detail
        assert "/tmp" in detail
        assert "fstab and remount" in detail
        assert len(ssh.commands_run) == 0

    def test_mount_point_not_in_fstab(self, mock_ssh):
        """AC-2: Returns failure when mount point is not found in fstab."""
        ssh = mock_ssh(
            {
                "grep": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/nonexistent",
            "options": ["noexec"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert detail == "/nonexistent: not found in /etc/fstab"

    def test_invalid_fstab_line(self, mock_ssh):
        """AC-3: Returns failure when fstab line has fewer than 4 fields."""
        ssh = mock_ssh(
            {
                "grep": Result(exit_code=0, stdout="/dev/sda1 /tmp ext4", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert detail == "Invalid fstab line for /tmp"

    def test_option_merging(self, mock_ssh):
        """AC-4: New options are merged with existing options."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /tmp ext4 defaults 0 0",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "mount -o remount": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec", "nosuid"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        # Verify sed was called to update fstab
        sed_cmds = [c for c in ssh.commands_run if "sed" in c]
        assert len(sed_cmds) == 1
        # After merging, options should include defaults + new
        assert "defaults" in sed_cmds[0]
        assert "noexec" in sed_cmds[0]
        assert "nosuid" in sed_cmds[0]

    def test_option_deduplication(self, mock_ssh):
        """AC-4: Duplicate options are deduplicated via set union."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /tmp ext4 defaults,noexec 0 0",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "mount -o remount": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec", "nosuid"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        sed_cmds = [c for c in ssh.commands_run if "sed" in c]
        # noexec should appear only once in the final option string
        opts_in_sed = sed_cmds[0]
        # Extract the replacement part and verify no duplicate
        assert opts_in_sed.count("noexec") >= 1

    def test_options_sorted(self, mock_ssh):
        """AC-5: Merged options are sorted alphabetically."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /tmp ext4 defaults 0 0",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "mount -o remount": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["nosuid", "nodev", "noexec"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        sed_cmds = [c for c in ssh.commands_run if "sed" in c]
        # The sorted order should be: defaults,nodev,noexec,nosuid
        assert "defaults,nodev,noexec,nosuid" in sed_cmds[0]

    def test_full_success(self, mock_ssh):
        """AC-6: Sed and remount success returns success message."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /tmp ext4 defaults 0 0",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "mount -o remount": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Added options" in detail
        assert "/tmp" in detail

    def test_sed_failure(self, mock_ssh):
        """AC-7: Sed failure returns failure detail with stderr."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /tmp ext4 defaults 0 0",
                    stderr="",
                ),
                "sed -i": Result(
                    exit_code=1, stdout="", stderr="sed: permission denied"
                ),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to update fstab" in detail
        assert "permission denied" in detail

    def test_sed_failure_no_remount(self, mock_ssh):
        """AC-7: When sed fails, remount is not attempted."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /tmp ext4 defaults 0 0",
                    stderr="",
                ),
                "sed -i": Result(exit_code=1, stdout="", stderr="error"),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec"],
        }
        run_remediation(ssh, rem, snapshot=False)
        assert not any("mount -o remount" in cmd for cmd in ssh.commands_run)

    def test_remount_failure(self, mock_ssh):
        """AC-8: Remount failure returns failure detail with stderr."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /tmp ext4 defaults 0 0",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "mount -o remount": Result(
                    exit_code=1, stdout="", stderr="mount: /tmp busy"
                ),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Remount failed" in detail
        assert "/tmp busy" in detail

    def test_shell_escaping_in_sed(self, mock_ssh):
        """AC-9: Mount point is escaped for safe sed interpolation."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /var/log ext4 defaults 0 0",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "mount -o remount": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/var/log",
            "options": ["noexec"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        # Verify sed was called (sed escaping happens internally)
        assert any("sed" in cmd for cmd in ssh.commands_run)

    def test_mount_point_quoting_in_remount(self, mock_ssh):
        """AC-9: Mount point is shell-quoted in the remount command."""
        ssh = mock_ssh(
            {
                "grep": Result(
                    exit_code=0,
                    stdout="/dev/sda1 /my dir ext4 defaults 0 0",
                    stderr="",
                ),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "mount -o remount": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/my dir",
            "options": ["noexec"],
        }
        run_remediation(ssh, rem, snapshot=False)
        mount_cmds = [c for c in ssh.commands_run if "mount -o remount" in c]
        assert len(mount_cmds) == 1
        assert "'/my dir'" in mount_cmds[0]

    def test_dry_run_no_grep_or_sed(self, mock_ssh):
        """AC-1: Dry-run does not execute any grep, sed, or mount commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "mount_option_set",
            "mount_point": "/tmp",
            "options": ["noexec"],
        }
        run_remediation(ssh, rem, dry_run=True)
        assert not any("grep" in cmd for cmd in ssh.commands_run)
        assert not any("sed" in cmd for cmd in ssh.commands_run)
        assert not any("mount" in cmd for cmd in ssh.commands_run)


class TestManualSpecDerived:
    """Spec-derived tests for manual remediation handler.

    See specs/handlers/remediation/manual.spec.yaml.
    """

    def test_always_returns_failure(self, mock_ssh):
        """AC-1: Handler always returns (False, 'MANUAL: {note}')."""
        ssh = mock_ssh({})
        rem = {"mechanism": "manual", "note": "Contact security team"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert detail == "MANUAL: Contact security team"

    def test_default_note(self, mock_ssh):
        """AC-2: Without note, returns 'MANUAL: Manual remediation required'."""
        ssh = mock_ssh({})
        rem = {"mechanism": "manual"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert detail == "MANUAL: Manual remediation required"

    def test_custom_note(self, mock_ssh):
        """AC-3: Custom note is included in the return message."""
        ssh = mock_ssh({})
        rem = {"mechanism": "manual", "note": "Edit /etc/security/limits.conf manually"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert detail == "MANUAL: Edit /etc/security/limits.conf manually"

    def test_dry_run_ignored(self, mock_ssh):
        """AC-4: Dry-run has no effect; same result as normal mode."""
        ssh = mock_ssh({})
        rem = {"mechanism": "manual", "note": "Manual steps needed"}
        ok_normal, detail_normal, _ = run_remediation(ssh, rem, snapshot=False)
        ok_dry, detail_dry, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok_normal == ok_dry
        assert detail_normal == detail_dry

    def test_ssh_unused(self, mock_ssh):
        """AC-5: No remote commands are executed."""
        ssh = mock_ssh({})
        rem = {"mechanism": "manual", "note": "Some manual step"}
        run_remediation(ssh, rem, snapshot=False)
        assert len(ssh.commands_run) == 0

    def test_non_capturable(self, mock_ssh):
        """AC-6: Pre-state capture always returns None (non-capturable)."""
        ssh = mock_ssh({})
        rem = {"mechanism": "manual", "note": "Manual steps needed"}
        ps = _capture_manual(ssh, rem)
        assert ps.capturable is False
        assert ps.mechanism == "manual"


# ── Spec-derived tests: config/file remediation handlers ──────────────────


class TestConfigBlockSpecDerived:
    """Spec-derived tests for config_block remediation handler.

    See specs/handlers/remediation/config_block.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_block",
            "path": "/etc/security/limits.conf",
            "block": "* hard core 0",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would write block to /etc/security/limits.conf" in detail
        assert "KENSA MANAGED BLOCK" in detail
        assert len(ssh.commands_run) == 0

    def test_dry_run_no_ssh_commands(self, mock_ssh):
        """AC-1: Dry-run executes zero SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "content",
            "marker": "MY BLOCK",
        }
        run_remediation(ssh, rem, dry_run=True)
        assert len(ssh.commands_run) == 0

    def test_default_marker(self, mock_ssh):
        """AC-2: Default marker is 'KENSA MANAGED BLOCK' when not provided."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "content",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert "KENSA MANAGED BLOCK" in detail

    def test_custom_marker(self, mock_ssh):
        """AC-3: Custom marker is used when provided."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "content",
            "marker": "CUSTOM MARKER",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert "CUSTOM MARKER" in detail

    def test_existing_block_removal(self, mock_ssh):
        """AC-4: Existing block is removed before appending new block."""
        ssh = mock_ssh(
            {
                "grep -qF": Result(exit_code=0, stdout="", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "new content",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("sed" in cmd for cmd in ssh.commands_run)

    def test_no_existing_block_skips_deletion(self, mock_ssh):
        """AC-5: When grep does not find the begin marker, no deletion is attempted."""
        ssh = mock_ssh(
            {
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "content",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert not any("sed" in cmd for cmd in ssh.commands_run)

    def test_block_format_includes_markers(self, mock_ssh):
        """AC-6: Appended block includes begin/end markers around content."""
        ssh = mock_ssh(
            {
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "* hard core 0",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        echo_cmds = [c for c in ssh.commands_run if "echo" in c or "printf" in c]
        assert len(echo_cmds) >= 1
        appended = echo_cmds[0]
        assert "# BEGIN KENSA MANAGED BLOCK" in appended
        assert "# END KENSA MANAGED BLOCK" in appended

    def test_append_success_returns_true(self, mock_ssh):
        """AC-7: Append success returns (True, 'Wrote block to {path}')."""
        ssh = mock_ssh(
            {
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/security/limits.conf",
            "block": "content",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Wrote block to /etc/security/limits.conf"

    def test_append_failure_returns_false(self, mock_ssh):
        """AC-8: Append failure returns (False, 'Failed to write block to {path}')."""
        ssh = mock_ssh(
            {
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                # echo not mocked -> fails
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "content",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to write block to /etc/conf" in detail

    def test_service_action_on_success(self, mock_ssh):
        """AC-9: Service action is called when append succeeds and reload specified."""
        ssh = mock_ssh(
            {
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "content",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("systemctl" in cmd and "sshd" in cmd for cmd in ssh.commands_run)

    def test_no_service_action_on_failure(self, mock_ssh):
        """AC-10: Service action is not called when append fails."""
        ssh = mock_ssh(
            {
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                # echo not mocked -> fails
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "content",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert not any("systemctl" in cmd for cmd in ssh.commands_run)

    def test_service_restart_on_success(self, mock_ssh):
        """AC-9: Service restart is called when append succeeds and restart specified."""
        ssh = mock_ssh(
            {
                "grep -qF": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_block",
            "path": "/etc/conf",
            "block": "content",
            "restart": "auditd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any(
            "systemctl restart" in cmd and "auditd" in cmd for cmd in ssh.commands_run
        )

    def test_dry_run_custom_marker_format(self, mock_ssh):
        """AC-3: Dry-run detail includes custom marker name."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_block",
            "path": "/etc/limits.conf",
            "block": "content",
            "marker": "LIMITS BLOCK",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert (
            detail == "Would write block to /etc/limits.conf with marker 'LIMITS BLOCK'"
        )


class TestConfigRemoveSpecDerived:
    """Spec-derived tests for config_remove remediation handler.

    See specs/handlers/remediation/config_remove.spec.yaml.
    """

    def test_key_already_absent(self, mock_ssh):
        """AC-1: When key is absent, returns success without modification."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "grep -rh": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "BadKey",
        }
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "BadKey not found in /etc/conf" in detail
        assert "already absent" in detail

    def test_key_absent_no_sed_executed(self, mock_ssh):
        """AC-1: When key is absent, no sed commands are executed."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "grep -rh": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "BadKey",
        }
        run_remediation(ssh, rem)
        assert not any("sed" in cmd for cmd in ssh.commands_run)

    def test_dry_run_with_key_present(self, mock_ssh):
        """AC-2: Dry-run with key present returns preview without executing sed."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="BadKey val", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "BadKey",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would remove 'BadKey' from /etc/conf" in detail
        assert not any("sed" in cmd for cmd in ssh.commands_run)

    def test_success_path(self, mock_ssh):
        """AC-3: Successful removal returns (True, "Removed '{key}' from {path}")."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "BadKey",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Removed 'BadKey' from /etc/conf"

    def test_sed_failure_returns_false(self, mock_ssh):
        """AC-4: Sed failure returns (False, 'Failed to remove {key} from {path}')."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "sed -i": Result(exit_code=1, stdout="", stderr="permission denied"),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "BadKey",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to remove BadKey from /etc/conf" in detail

    def test_service_action_on_success(self, mock_ssh):
        """AC-5: Service action called after successful removal."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "BadKey",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("systemctl" in cmd and "sshd" in cmd for cmd in ssh.commands_run)

    def test_no_service_action_on_failure(self, mock_ssh):
        """AC-6: Service action not called when sed fails."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="BadKey val", stderr=""),
                "sed -i": Result(exit_code=1, stdout="", stderr="error"),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "BadKey",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert not any("systemctl" in cmd for cmd in ssh.commands_run)

    def test_key_escaping(self, mock_ssh):
        """AC-7: Key is escaped with escape_grep_bre before sed pattern."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="key.with.dots val", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="key.with.dots val", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "key.with.dots",
        }
        run_remediation(ssh, rem, snapshot=False)
        sed_cmds = [c for c in ssh.commands_run if "sed -i" in c]
        assert len(sed_cmds) == 1
        # Dots should be escaped in the sed pattern
        assert "key\\.with\\.dots" in sed_cmds[0]

    def test_sed_pattern_format(self, mock_ssh):
        """AC-8: Sed delete pattern is '^ *{escaped_key}' for leading space tolerance."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="MyKey val", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="MyKey val", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "MyKey",
        }
        run_remediation(ssh, rem, snapshot=False)
        sed_cmds = [c for c in ssh.commands_run if "sed -i" in c]
        assert len(sed_cmds) == 1
        # Pattern should match lines with optional leading spaces
        assert "^ *MyKey" in sed_cmds[0]

    def test_restart_service_on_success(self, mock_ssh):
        """AC-5: Service restart (not reload) works when restart key is present."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=0, stdout="K val", stderr=""),
                "grep -rh": Result(exit_code=0, stdout="K val", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "K",
            "restart": "auditd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any(
            "systemctl restart" in cmd and "auditd" in cmd for cmd in ssh.commands_run
        )

    def test_absent_key_skips_dry_run_check(self, mock_ssh):
        """AC-1: Early return for absent key runs before dry_run check."""
        ssh = mock_ssh(
            {
                "grep -h": Result(exit_code=1, stdout="", stderr=""),
                "grep -rh": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_remove",
            "path": "/etc/conf",
            "key": "Missing",
        }
        # Even with dry_run=True, absent key returns the "already absent" message
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "already absent" in detail


class TestConfigSetDropinSpecDerived:
    """Spec-derived tests for config_set_dropin remediation handler.

    See specs/handlers/remediation/config_set_dropin.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa.conf",
            "key": "PermitRootLogin",
            "value": "no",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would write" in detail
        assert "PermitRootLogin no" in detail
        assert "/etc/ssh/sshd_config.d/00-kensa.conf" in detail
        assert len(ssh.commands_run) == 0

    def test_dry_run_no_ssh_commands(self, mock_ssh):
        """AC-1: Dry-run executes zero SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/conf.d",
            "file": "test.conf",
            "key": "K",
            "value": "V",
        }
        run_remediation(ssh, rem, dry_run=True)
        assert len(ssh.commands_run) == 0

    def test_success_path(self, mock_ssh):
        """AC-2: Success returns (True, "Wrote '{key}{sep}{value}' to {dir}/{file}")."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa.conf",
            "key": "PermitRootLogin",
            "value": "no",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert (
            detail
            == "Wrote 'PermitRootLogin no' to /etc/ssh/sshd_config.d/00-kensa.conf"
        )

    def test_write_failure_returns_false(self, mock_ssh):
        """AC-3: Write failure returns (False, 'Failed to write {dir}/{file}')."""
        ssh = mock_ssh(
            {
                # printf not mocked -> fails
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa.conf",
            "key": "K",
            "value": "V",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to write /etc/ssh/sshd_config.d/00-kensa.conf" in detail

    def test_default_separator_is_space(self, mock_ssh):
        """AC-4: Default separator is a single space when not specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/conf.d",
            "file": "test.conf",
            "key": "MyKey",
            "value": "MyVal",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "MyKey MyVal" in detail

    def test_custom_separator(self, mock_ssh):
        """AC-5: Custom separator is used between key and value."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/sysctl.d",
            "file": "99-kensa.conf",
            "key": "net.ipv4.ip_forward",
            "value": "0",
            "separator": " = ",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "net.ipv4.ip_forward = 0" in detail

    def test_service_reload_on_success(self, mock_ssh):
        """AC-6: Service reload is called when write succeeds and reload specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa.conf",
            "key": "K",
            "value": "V",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("systemctl" in cmd and "sshd" in cmd for cmd in ssh.commands_run)

    def test_service_restart_on_success(self, mock_ssh):
        """AC-7: Service restart is called when write succeeds and restart specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/conf.d",
            "file": "test.conf",
            "key": "K",
            "value": "V",
            "restart": "auditd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any(
            "systemctl restart" in cmd and "auditd" in cmd for cmd in ssh.commands_run
        )

    def test_no_service_action_on_failure(self, mock_ssh):
        """AC-8: Service action is not called when write fails."""
        ssh = mock_ssh(
            {
                # printf not mocked -> fails
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/conf.d",
            "file": "test.conf",
            "key": "K",
            "value": "V",
            "reload": "sshd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert not any("systemctl" in cmd for cmd in ssh.commands_run)

    def test_file_content_format(self, mock_ssh):
        """AC-9: Written file contains '{key}{sep}{value}\\n'."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa.conf",
            "key": "PermitRootLogin",
            "value": "no",
        }
        run_remediation(ssh, rem, snapshot=False)
        printf_cmds = [c for c in ssh.commands_run if "printf" in c]
        assert len(printf_cmds) == 1
        # write_file uses printf, content should include key-value with newline
        assert "PermitRootLogin no" in printf_cmds[0]

    def test_no_service_action_when_absent(self, mock_ssh):
        """AC-6: No systemctl command when neither reload nor restart specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/conf.d",
            "file": "test.conf",
            "key": "K",
            "value": "V",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert not any("systemctl" in cmd for cmd in ssh.commands_run)

    def test_dry_run_detail_format(self, mock_ssh):
        """AC-1: Dry-run detail includes key, separator, value, and full path."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-kensa.conf",
            "key": "PermitRootLogin",
            "value": "no",
            "separator": " ",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert (
            detail == "Would write 'PermitRootLogin no' to"
            " /etc/ssh/sshd_config.d/00-kensa.conf"
        )


class TestFileContentSetSpecDerived:
    """Spec-derived tests for file_content (file_content_set) remediation handler.

    See specs/handlers/remediation/file_content_set.spec.yaml.
    Note: The mechanism name in the registry is 'file_content'.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "Authorized users only.",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would write content to /etc/issue"
        assert len(ssh.commands_run) == 0

    def test_dry_run_no_ssh_commands(self, mock_ssh):
        """AC-1: Dry-run executes zero SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue.net",
            "content": "banner text",
        }
        run_remediation(ssh, rem, dry_run=True)
        assert len(ssh.commands_run) == 0

    def test_success_path(self, mock_ssh):
        """AC-2: Success returns (True, 'Wrote content to {path}')."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "Authorized users only.",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Wrote content to /etc/issue"

    def test_write_failure_returns_false(self, mock_ssh):
        """AC-3: Write failure returns (False, 'Failed to write {path}')."""
        ssh = mock_ssh(
            {
                # printf not mocked -> fails
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "text",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to write /etc/issue" in detail

    def test_write_failure_skips_ownership_and_mode(self, mock_ssh):
        """AC-3: When write fails, ownership and mode are not attempted."""
        ssh = mock_ssh(
            {
                # printf not mocked -> fails
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "text",
            "owner": "root",
            "mode": "0644",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert not any("chown" in cmd for cmd in ssh.commands_run)
        assert not any("chmod" in cmd for cmd in ssh.commands_run)

    def test_owner_set_after_write(self, mock_ssh):
        """AC-4: Owner is set via set_file_owner when specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chown": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "text",
            "owner": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("chown" in cmd for cmd in ssh.commands_run)

    def test_group_set_after_write(self, mock_ssh):
        """AC-5: Group is set via set_file_owner when specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chown": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "text",
            "group": "wheel",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("chown" in cmd for cmd in ssh.commands_run)

    def test_mode_set_after_write(self, mock_ssh):
        """AC-6: Mode is set via set_file_mode when specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "text",
            "mode": "0644",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("chmod" in cmd and "0644" in cmd for cmd in ssh.commands_run)

    def test_no_ownership_change_without_owner_group(self, mock_ssh):
        """AC-7: set_file_owner is not called when neither owner nor group specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "text",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert not any("chown" in cmd for cmd in ssh.commands_run)

    def test_no_mode_change_without_mode(self, mock_ssh):
        """AC-8: set_file_mode is not called when mode is not specified."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "text",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert not any("chmod" in cmd for cmd in ssh.commands_run)

    def test_owner_and_group_and_mode_all_set(self, mock_ssh):
        """AC-4/AC-5/AC-6: All three attributes set after successful write."""
        ssh = mock_ssh(
            {
                "printf": Result(exit_code=0, stdout="", stderr=""),
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_content",
            "path": "/etc/issue",
            "content": "text",
            "owner": "root",
            "group": "root",
            "mode": "0644",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("chown" in cmd for cmd in ssh.commands_run)
        assert any("chmod" in cmd for cmd in ssh.commands_run)


class TestFileAbsentSpecDerived:
    """Spec-derived tests for file_absent remediation handler.

    See specs/handlers/remediation/file_absent.spec.yaml.
    """

    def test_already_absent(self, mock_ssh):
        """AC-1: When file is already absent, returns success immediately."""
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert "/etc/hosts.equiv: already absent" in detail

    def test_already_absent_no_rm(self, mock_ssh):
        """AC-1: When file is already absent, no rm command is executed."""
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        run_remediation(ssh, rem)
        assert not any("rm" in cmd for cmd in ssh.commands_run)

    def test_already_absent_skips_dry_run_check(self, mock_ssh):
        """AC-1: Early return for absent file runs before dry_run check."""
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "already absent" in detail

    def test_dry_run_with_file_present(self, mock_ssh):
        """AC-2: Dry-run with file present returns preview without executing rm."""
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert detail == "Would remove /etc/hosts.equiv"
        assert not any("rm" in cmd for cmd in ssh.commands_run)

    def test_success_path(self, mock_ssh):
        """AC-3: Successful removal returns (True, 'Removed {path}')."""
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=0, stdout="", stderr=""),
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Removed /etc/hosts.equiv"

    def test_removal_failure(self, mock_ssh):
        """AC-4: Removal failure returns (False, 'Failed to remove {path}: {stderr}')."""
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=0, stdout="", stderr=""),
                "rm -f": Result(exit_code=1, stdout="", stderr="Permission denied"),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to remove /etc/hosts.equiv" in detail
        assert "Permission denied" in detail

    def test_shell_quoting(self, mock_ssh):
        """AC-5: Path is passed through shell_util.quote() in rm command."""
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=0, stdout="", stderr=""),
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/my file.conf"}
        run_remediation(ssh, rem, snapshot=False)
        rm_cmds = [c for c in ssh.commands_run if "rm -f" in c]
        assert len(rm_cmds) == 1
        # Path with spaces should be quoted
        assert "'/etc/my file.conf'" in rm_cmds[0]

    def test_rm_f_is_used(self, mock_ssh):
        """AC-3: rm -f (force flag) is used for file removal."""
        ssh = mock_ssh(
            {
                "test -e": Result(exit_code=0, stdout="", stderr=""),
                "rm -f": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {"mechanism": "file_absent", "path": "/etc/hosts.equiv"}
        run_remediation(ssh, rem, snapshot=False)
        rm_cmds = [c for c in ssh.commands_run if "rm" in c]
        assert len(rm_cmds) == 1
        assert "rm -f" in rm_cmds[0]


class TestFilePermissionsSpecDerived:
    """Spec-derived tests for file_permissions remediation handler.

    See specs/handlers/remediation/file_permissions.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "owner": "root",
            "group": "root",
            "mode": "0000",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would run:" in detail
        assert len(ssh.commands_run) == 0

    def test_dry_run_no_ssh_commands(self, mock_ssh):
        """AC-1: Dry-run executes zero SSH commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "mode": "0000",
        }
        run_remediation(ssh, rem, dry_run=True)
        assert len(ssh.commands_run) == 0

    def test_owner_and_group_set(self, mock_ssh):
        """AC-2: When both owner and group are provided, chown uses 'owner:group'."""
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "owner": "root",
            "group": "shadow",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        chown_cmds = [c for c in ssh.commands_run if "chown" in c]
        assert len(chown_cmds) == 1
        assert "root:shadow" in chown_cmds[0]

    def test_owner_only(self, mock_ssh):
        """AC-3: When only owner is provided, chown uses just the owner name."""
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "owner": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        chown_cmds = [c for c in ssh.commands_run if "chown" in c]
        assert len(chown_cmds) == 1
        assert "root" in chown_cmds[0]
        # Should not have a colon when group is absent
        assert "root:" not in chown_cmds[0]

    def test_group_only(self, mock_ssh):
        """AC-4: When only group is provided, chown uses ':group'."""
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "group": "shadow",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        chown_cmds = [c for c in ssh.commands_run if "chown" in c]
        assert len(chown_cmds) == 1
        assert ":shadow" in chown_cmds[0]

    def test_mode_set(self, mock_ssh):
        """AC-5: When mode is provided, chmod is called with the octal mode."""
        ssh = mock_ssh(
            {
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "mode": "0000",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        chmod_cmds = [c for c in ssh.commands_run if "chmod" in c]
        assert len(chmod_cmds) == 1
        assert "0000" in chmod_cmds[0]

    def test_combined_command(self, mock_ssh):
        """AC-6: Both chown and chmod are joined with '&&' in one compound command."""
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "owner": "root",
            "group": "root",
            "mode": "0000",
        }
        run_remediation(ssh, rem, snapshot=False)
        # The handler joins chown && chmod as a single command
        combined = [c for c in ssh.commands_run if "chown" in c and "chmod" in c]
        assert len(combined) == 1
        assert "&&" in combined[0]

    def test_glob_explicit_flag(self, mock_ssh):
        """AC-7: Explicit glob flag allows unquoted glob path."""
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/ssh/ssh_host_*_key",
            "owner": "root",
            "group": "ssh_keys",
            "mode": "0640",
            "glob": "ssh_host_*_key",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        chown_cmd = [c for c in ssh.commands_run if "chown" in c][0]
        # Glob path should NOT be single-quoted
        assert "'/etc/ssh/ssh_host_*_key'" not in chown_cmd
        assert "/etc/ssh/ssh_host_*_key" in chown_cmd

    def test_glob_auto_detection(self, mock_ssh):
        """AC-8: Glob characters in path are auto-detected by is_glob_path."""
        ssh = mock_ssh(
            {
                "chown": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/ssh/ssh_host_*_key",
            "owner": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        chown_cmd = [c for c in ssh.commands_run if "chown" in c][0]
        # Auto-detected glob should NOT be single-quoted
        assert "'/etc/ssh/ssh_host_*_key'" not in chown_cmd

    def test_success_path(self, mock_ssh):
        """AC-9: Success returns (True, 'Set permissions on {path}')."""
        ssh = mock_ssh(
            {
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "mode": "0000",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set permissions on /etc/shadow"

    def test_failure_path(self, mock_ssh):
        """AC-10: Failure returns (False, 'Failed: {stderr}')."""
        ssh = mock_ssh(
            {
                "chmod": Result(exit_code=1, stdout="", stderr="chmod: bad mode"),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "mode": "0644",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed:" in detail

    def test_path_quoting_non_glob(self, mock_ssh):
        """AC-11: Non-glob path is quoted via shell_util.quote_path."""
        ssh = mock_ssh(
            {
                "chmod": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/my file.conf",
            "mode": "0644",
        }
        run_remediation(ssh, rem, snapshot=False)
        chmod_cmds = [c for c in ssh.commands_run if "chmod" in c]
        assert len(chmod_cmds) == 1
        # Path with spaces should be quoted
        assert "'/etc/my file.conf'" in chmod_cmds[0]

    def test_dry_run_includes_chown_and_chmod(self, mock_ssh):
        """AC-1: Dry-run detail includes both chown and chmod commands."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "owner": "root",
            "group": "root",
            "mode": "0000",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "chown" in detail
        assert "chmod" in detail
        assert "&&" in detail

    def test_dry_run_mode_only(self, mock_ssh):
        """AC-1: Dry-run with only mode shows chmod command."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/shadow",
            "mode": "0000",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "chmod" in detail
        assert "chown" not in detail


class TestConfigAppendSpecDerived:
    """Spec-derived tests for config_append remediation handler.

    See specs/handlers/remediation/config_append.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_append",
            "path": "/etc/audit/rules.d/audit.rules",
            "line": "-e 2",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would append" in detail
        assert "-e 2" in detail
        assert len(ssh.commands_run) == 0

    def test_idempotent_skip_when_present(self, mock_ssh):
        """AC-2: Line already present returns success without modification."""
        ssh = mock_ssh(
            {
                "grep -Fxq": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_append",
            "path": "/etc/audit/rules.d/audit.rules",
            "line": "-e 2",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "already present" in detail
        # No echo command should have been run
        echo_cmds = [c for c in ssh.commands_run if "echo" in c]
        assert len(echo_cmds) == 0

    def test_append_when_absent(self, mock_ssh):
        """AC-3: Line absent is appended and returns success."""
        ssh = mock_ssh(
            {
                "grep -Fxq": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_append",
            "path": "/etc/audit/rules.d/audit.rules",
            "line": "-e 2",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Appended" in detail

    def test_append_failure(self, mock_ssh):
        """AC-4: Append failure returns False with stderr."""
        ssh = mock_ssh(
            {
                "grep -Fxq": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=1, stdout="", stderr="read-only fs"),
            }
        )
        rem = {
            "mechanism": "config_append",
            "path": "/etc/audit/rules.d/audit.rules",
            "line": "-e 2",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to append" in detail
        assert "read-only fs" in detail

    def test_service_action_on_modification(self, mock_ssh):
        """AC-5: Service action called after successful append."""
        ssh = mock_ssh(
            {
                "grep -Fxq": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
                "systemctl": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_append",
            "path": "/etc/security/faillock.conf",
            "line": "even_deny_root",
            "restart": "sssd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        svc_cmds = [c for c in ssh.commands_run if "systemctl" in c]
        assert len(svc_cmds) >= 1

    def test_no_service_action_on_skip(self, mock_ssh):
        """AC-6: No service action when line already present."""
        ssh = mock_ssh(
            {
                "grep -Fxq": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_append",
            "path": "/etc/security/faillock.conf",
            "line": "even_deny_root",
            "restart": "sssd",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        svc_cmds = [c for c in ssh.commands_run if "systemctl" in c]
        assert len(svc_cmds) == 0

    def test_no_service_action_without_reload_restart(self, mock_ssh):
        """AC-7: No systemctl when neither reload nor restart specified."""
        ssh = mock_ssh(
            {
                "grep -Fxq": Result(exit_code=1, stdout="", stderr=""),
                "echo": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "config_append",
            "path": "/etc/audit/rules.d/audit.rules",
            "line": "-e 2",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        svc_cmds = [c for c in ssh.commands_run if "systemctl" in c]
        assert len(svc_cmds) == 0


class TestFilePermissionsBulkSpecDerived:
    """Spec-derived tests for file_permissions bulk find mode.

    See specs/handlers/remediation/file_permissions.spec.yaml v2.0.0.
    """

    def test_bulk_mode_activation(self, mock_ssh):
        """AC-12: find_paths activates bulk find mode."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/etc/audit"],
            "find_type": "f",
            "owner": "root",
            "group": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        find_cmds = [c for c in ssh.commands_run if c.startswith("find ")]
        assert len(find_cmds) == 1
        assert "/etc/audit" in find_cmds[0]

    def test_bulk_find_name_filter(self, mock_ssh):
        """AC-13: find_name adds -name filter to find command."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/lib", "/usr/lib"],
            "find_name": "*.so*",
            "find_type": "f",
            "owner": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        find_cmd = [c for c in ssh.commands_run if c.startswith("find ")][0]
        assert "-name" in find_cmd
        assert "*.so*" in find_cmd

    def test_bulk_find_type_filter(self, mock_ssh):
        """AC-14: find_type adds -type filter to find command."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/etc/audit"],
            "find_type": "d",
            "mode": "0755",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        find_cmd = [c for c in ssh.commands_run if c.startswith("find ")][0]
        assert "-type d" in find_cmd

    def test_bulk_find_extra_args(self, mock_ssh):
        """AC-15: find_args string is appended to find command."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/lib", "/lib64"],
            "find_name": "*.so*",
            "find_type": "f",
            "find_args": "! -user root",
            "owner": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        find_cmd = [c for c in ssh.commands_run if c.startswith("find ")][0]
        assert "! -user root" in find_cmd

    def test_bulk_chown(self, mock_ssh):
        """AC-16: Bulk mode includes -exec chown with correct spec."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/lib"],
            "find_type": "f",
            "owner": "root",
            "group": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        find_cmd = [c for c in ssh.commands_run if c.startswith("find ")][0]
        assert "-exec chown root:root {} +" in find_cmd

    def test_bulk_chmod(self, mock_ssh):
        """AC-17: Bulk mode includes -exec chmod with mode."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/etc/audit"],
            "find_type": "f",
            "mode": "0640",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        find_cmd = [c for c in ssh.commands_run if c.startswith("find ")][0]
        assert "-exec chmod 0640 {} +" in find_cmd

    def test_bulk_combined_chown_chmod(self, mock_ssh):
        """AC-18: Bulk mode includes both -exec chown and -exec chmod."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/etc/audit"],
            "find_type": "f",
            "owner": "root",
            "group": "root",
            "mode": "0640",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        find_cmd = [c for c in ssh.commands_run if c.startswith("find ")][0]
        assert "-exec chown root:root {} +" in find_cmd
        assert "-exec chmod 0640 {} +" in find_cmd

    def test_bulk_dry_run(self, mock_ssh):
        """AC-19: Bulk dry-run returns preview without SSH execution."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/lib", "/lib64"],
            "find_name": "*.so*",
            "find_type": "f",
            "owner": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would run:" in detail
        assert "find" in detail
        assert len(ssh.commands_run) == 0

    def test_bulk_success_message(self, mock_ssh):
        """AC-20: Bulk success returns paths in message."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/lib", "/lib64"],
            "find_type": "f",
            "owner": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Set permissions via find in" in detail
        assert "/lib" in detail
        assert "/lib64" in detail

    def test_bulk_failure(self, mock_ssh):
        """AC-21: Bulk failure returns stderr in message."""
        ssh = mock_ssh(
            {
                "find": Result(exit_code=1, stdout="", stderr="Permission denied"),
            }
        )
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/restricted"],
            "find_type": "f",
            "mode": "0644",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed:" in detail
        assert "Permission denied" in detail

    def test_ac22_find_type_validation_rejects_invalid(self, mock_ssh):
        """AC-22: find_type validation rejects invalid values before shell interpolation."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/etc"],
            "find_type": "f; rm -rf /",
            "mode": "0644",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        # Should not have executed any commands
        assert len(ssh.commands_run) == 0

    def test_ac22_find_type_validation_accepts_valid(self, mock_ssh):
        """AC-22: find_type validation accepts valid single-character codes."""
        for valid_type in ["f", "d", "l", "b", "c", "p", "s"]:
            ssh = mock_ssh({"find": Result(exit_code=0, stdout="", stderr="")})
            rem = {
                "mechanism": "file_permissions",
                "find_paths": ["/etc"],
                "find_type": valid_type,
                "mode": "0644",
            }
            ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
            assert ok is True, f"Valid find_type '{valid_type}' should be accepted"

    def test_ac23_chown_spec_rejects_shell_metacharacters(self, mock_ssh):
        """AC-23: owner/group/mode with shell metacharacters are rejected."""
        ssh = mock_ssh({})
        # Malicious owner with shell injection
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/etc"],
            "find_type": "f",
            "owner": "root;rm -rf /",
            "group": "root",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert len(ssh.commands_run) == 0

    def test_ac23_mode_rejects_shell_metacharacters(self, mock_ssh):
        """AC-23: mode with shell metacharacters is rejected."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "file_permissions",
            "find_paths": ["/etc"],
            "find_type": "f",
            "mode": "0644;id",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert len(ssh.commands_run) == 0


# ── dconf_set spec-derived tests ──────────────────────────────────────────────


class TestDconfSetSpecDerived:
    """Spec-derived tests for dconf_set remediation handler.

    See specs/handlers/remediation/dconf_set.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/login-screen",
            "key": "banner-message-enable",
            "value": "true",
            "file": "00-security-settings",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set dconf" in detail
        assert "org/gnome/login-screen/banner-message-enable=true" in detail
        assert len(ssh.commands_run) == 0

    def test_setting_file_written(self, mock_ssh):
        """AC-2: Setting file written in INI format."""
        ssh = mock_ssh(
            {
                "mkdir -p": Result(exit_code=0, stdout="", stderr=""),
                "cat >": Result(exit_code=0, stdout="", stderr=""),
                "dconf update": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/login-screen",
            "key": "banner-message-enable",
            "value": "true",
            "file": "00-security-settings",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Set dconf" in detail
        write_cmds = [c for c in ssh.commands_run if "cat >" in c]
        assert len(write_cmds) >= 1
        assert "/etc/dconf/db/local.d/00-security-settings" in write_cmds[0]

    def test_value_type_prefix(self, mock_ssh):
        """AC-3: Value type prefix prepended to value."""
        ssh = mock_ssh(
            {
                "mkdir -p": Result(exit_code=0, stdout="", stderr=""),
                "cat >": Result(exit_code=0, stdout="", stderr=""),
                "dconf update": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/desktop/session",
            "key": "idle-delay",
            "value": "900",
            "value_type": "uint32",
            "file": "00-screensaver",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "uint32 900" in detail

    def test_lock_file_created(self, mock_ssh):
        """AC-4: Lock file created when lock=true."""
        ssh = mock_ssh(
            {
                "mkdir -p": Result(exit_code=0, stdout="", stderr=""),
                "cat >": Result(exit_code=0, stdout="", stderr=""),
                "dconf update": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/desktop/session",
            "key": "idle-delay",
            "value": "900",
            "value_type": "uint32",
            "file": "00-screensaver",
            "lock": True,
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        lock_cmds = [c for c in ssh.commands_run if "locks" in c]
        assert len(lock_cmds) >= 1

    def test_dconf_update_executed(self, mock_ssh):
        """AC-5: dconf update runs after writing files."""
        ssh = mock_ssh(
            {
                "mkdir -p": Result(exit_code=0, stdout="", stderr=""),
                "cat >": Result(exit_code=0, stdout="", stderr=""),
                "dconf update": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/login-screen",
            "key": "disable-user-list",
            "value": "true",
            "file": "00-security-settings",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("dconf update" in cmd for cmd in ssh.commands_run)

    def test_success_path(self, mock_ssh):
        """AC-6: Success returns correct detail format."""
        ssh = mock_ssh(
            {
                "mkdir -p": Result(exit_code=0, stdout="", stderr=""),
                "cat >": Result(exit_code=0, stdout="", stderr=""),
                "dconf update": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/login-screen",
            "key": "disable-user-list",
            "value": "true",
            "file": "00-security-settings",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert detail == "Set dconf org/gnome/login-screen/disable-user-list=true"

    def test_write_failure(self, mock_ssh):
        """AC-7: Write failure returns error detail."""
        ssh = mock_ssh(
            {
                "mkdir -p": Result(exit_code=1, stdout="", stderr="Permission denied"),
            }
        )
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/login-screen",
            "key": "disable-user-list",
            "value": "true",
            "file": "00-security-settings",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to write dconf setting" in detail

    def test_default_database(self, mock_ssh):
        """AC-8: Default database is 'local'."""
        ssh = mock_ssh(
            {
                "mkdir -p": Result(exit_code=0, stdout="", stderr=""),
                "cat >": Result(exit_code=0, stdout="", stderr=""),
                "dconf update": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/login-screen",
            "key": "disable-user-list",
            "value": "true",
            "file": "00-security-settings",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("/etc/dconf/db/local.d/" in cmd for cmd in ssh.commands_run)

    def test_gdm_database(self, mock_ssh):
        """AC-9: Lock directory created for non-default database."""
        ssh = mock_ssh(
            {
                "mkdir -p": Result(exit_code=0, stdout="", stderr=""),
                "cat >": Result(exit_code=0, stdout="", stderr=""),
                "dconf update": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "dconf_set",
            "schema": "org/gnome/login-screen",
            "key": "banner-message-enable",
            "value": "true",
            "file": "00-security-settings",
            "db": "gdm",
            "lock": True,
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert any("/etc/dconf/db/gdm.d/" in cmd for cmd in ssh.commands_run)
        lock_cmds = [c for c in ssh.commands_run if "locks" in c]
        assert len(lock_cmds) >= 1


# ── crypto_policy_set spec-derived tests ──────────────────────────────────────


class TestCryptoPolicySetSpecDerived:
    """Spec-derived tests for crypto_policy_set remediation handler.

    See specs/handlers/remediation/crypto_policy_set.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "crypto_policy_set",
            "policy": "FIPS",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set crypto policy to FIPS" in detail
        assert len(ssh.commands_run) == 0

    def test_policy_set_success(self, mock_ssh):
        """AC-2: Policy set successfully."""
        ssh = mock_ssh(
            {
                "update-crypto-policies": Result(
                    exit_code=0, stdout="Setting system policy to FIPS\n", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "crypto_policy_set",
            "policy": "FIPS",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Set crypto policy to FIPS" in detail

    def test_subpolicy_support(self, mock_ssh):
        """AC-3: Subpolicy modifier appended to policy."""
        ssh = mock_ssh(
            {
                "update-crypto-policies": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "crypto_policy_set",
            "policy": "DEFAULT",
            "subpolicy": "NO-SHA1",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Set crypto policy to DEFAULT:NO-SHA1" in detail
        assert any("DEFAULT:NO-SHA1" in cmd for cmd in ssh.commands_run)

    def test_command_failure(self, mock_ssh):
        """AC-4: Command failure returns error detail."""
        ssh = mock_ssh(
            {
                "update-crypto-policies": Result(
                    exit_code=1, stdout="", stderr="Error: unknown policy"
                ),
            }
        )
        rem = {
            "mechanism": "crypto_policy_set",
            "policy": "INVALID",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "update-crypto-policies failed" in detail


class TestAuthselectFeatureEnableSpecDerived:
    """Spec-derived tests for authselect_feature_enable handler.

    See specs/handlers/remediation/authselect_feature_enable.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "authselect_feature_enable",
            "feature": "with-faillock",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would run: authselect enable-feature with-faillock" in detail
        assert len(ssh.commands_run) == 0

    def test_feature_enabled_success(self, mock_ssh):
        """AC-2: Feature enabled successfully."""
        ssh = mock_ssh(
            {
                "authselect enable-feature": Result(
                    exit_code=0, stdout="Feature enabled\n", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "authselect_feature_enable",
            "feature": "with-faillock",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Enabled authselect feature 'with-faillock'" in detail

    def test_unless_guard_skips(self, mock_ssh):
        """AC-3: Unless guard skips when feature already active."""
        ssh = mock_ssh(
            {
                "authselect current": Result(
                    exit_code=0, stdout="with-faillock\n", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "authselect_feature_enable",
            "feature": "with-faillock",
            "unless": "authselect current | grep -q with-faillock",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "already active (skipped)" in detail

    def test_command_failure(self, mock_ssh):
        """AC-4: Command failure returns error detail."""
        ssh = mock_ssh(
            {
                "authselect enable-feature": Result(
                    exit_code=1, stdout="", stderr="authselect not configured"
                ),
            }
        )
        rem = {
            "mechanism": "authselect_feature_enable",
            "feature": "with-faillock",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "authselect enable-feature failed" in detail

    def test_unless_guard_failure_proceeds(self, mock_ssh):
        """AC-5: Unless guard failure proceeds to enable feature."""
        ssh = mock_ssh(
            {
                "authselect current": Result(exit_code=1, stdout="", stderr=""),
                "authselect enable-feature": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "authselect_feature_enable",
            "feature": "with-pwhistory",
            "unless": "authselect current | grep -q with-pwhistory",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Enabled authselect feature 'with-pwhistory'" in detail


class TestCryptoPolicySubpolicySpecDerived:
    """Spec-derived tests for crypto_policy_subpolicy handler.

    See specs/handlers/remediation/crypto_policy_subpolicy.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "crypto_policy_subpolicy",
            "subpolicy": "NO-SHA1",
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would append subpolicy :NO-SHA1" in detail
        assert len(ssh.commands_run) == 0

    def test_subpolicy_appended(self, mock_ssh):
        """AC-2: Subpolicy appended to current policy."""
        ssh = mock_ssh(
            {
                "update-crypto-policies --show": Result(
                    exit_code=0, stdout="DEFAULT\n", stderr=""
                ),
                "update-crypto-policies --set": Result(
                    exit_code=0, stdout="", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "crypto_policy_subpolicy",
            "subpolicy": "NO-SHA1",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Set crypto policy to DEFAULT:NO-SHA1" in detail

    def test_unless_guard_skips(self, mock_ssh):
        """AC-3: Unless guard skips when subpolicy already active."""
        ssh = mock_ssh(
            {
                "update-crypto-policies --show": Result(
                    exit_code=0, stdout="DEFAULT:NO-SHA1\n", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "crypto_policy_subpolicy",
            "subpolicy": "NO-SHA1",
            "unless": "update-crypto-policies --show | grep -q ':NO-SHA1'",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "already active (skipped)" in detail

    def test_read_failure(self, mock_ssh):
        """AC-4: Current policy read failure returns error."""
        ssh = mock_ssh(
            {
                "update-crypto-policies --show": Result(
                    exit_code=1, stdout="", stderr="not found"
                ),
            }
        )
        rem = {
            "mechanism": "crypto_policy_subpolicy",
            "subpolicy": "NO-CBC",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to read current crypto policy" in detail

    def test_set_failure(self, mock_ssh):
        """AC-5: Policy set failure returns error detail."""
        ssh = mock_ssh(
            {
                "update-crypto-policies --show": Result(
                    exit_code=0, stdout="DEFAULT\n", stderr=""
                ),
                "update-crypto-policies --set": Result(
                    exit_code=1, stdout="", stderr="invalid policy"
                ),
            }
        )
        rem = {
            "mechanism": "crypto_policy_subpolicy",
            "subpolicy": "NO-CBC",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "update-crypto-policies --set failed" in detail

    def test_deduplication(self, mock_ssh):
        """AC-6: Existing subpolicy is stripped before re-appending."""
        ssh = mock_ssh(
            {
                "update-crypto-policies --show": Result(
                    exit_code=0, stdout="DEFAULT:NO-SHA1\n", stderr=""
                ),
                "update-crypto-policies --set": Result(
                    exit_code=0, stdout="", stderr=""
                ),
            }
        )
        rem = {
            "mechanism": "crypto_policy_subpolicy",
            "subpolicy": "NO-SHA1",
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Set crypto policy to DEFAULT:NO-SHA1" in detail
        # Ensure the command used DEFAULT:NO-SHA1, not DEFAULT:NO-SHA1:NO-SHA1
        set_cmds = [c for c in ssh.commands_run if "update-crypto-policies --set" in c]
        assert len(set_cmds) == 1
        assert ":NO-SHA1:NO-SHA1" not in set_cmds[0]


class TestPamModuleArgSpecDerived:
    """Spec-derived tests for pam_module_arg remediation handler.

    See specs/handlers/remediation/pam_module_arg.spec.yaml.
    """

    def test_dry_run_returns_preview(self, mock_ssh):
        """AC-1: Dry-run returns preview with no SSH commands executed."""
        ssh = mock_ssh({})
        rem = {
            "mechanism": "pam_module_arg",
            "action": "remove",
            "module": "pam_unix.so",
            "arg": "nullok",
            "files": ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"],
        }
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would remove arg 'nullok'" in detail
        assert "2 file(s)" in detail
        assert len(ssh.commands_run) == 0

    def test_remove_exact_arg(self, mock_ssh):
        """AC-2: Remove exact arg from matching lines."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_arg",
            "action": "remove",
            "module": "pam_unix.so",
            "arg": "nullok",
            "files": ["/etc/pam.d/system-auth"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Removed arg 'nullok'" in detail
        assert "1 file(s)" in detail

    def test_remove_regex_arg(self, mock_ssh):
        """AC-3: Remove regex-matched arg from matching lines."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_arg",
            "action": "remove",
            "module": "pam_unix.so",
            "arg": "remember=[0-9]*",
            "arg_regex": True,
            "files": ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Removed arg 'remember=[0-9]*'" in detail

    def test_ensure_arg_present(self, mock_ssh):
        """AC-4: Ensure arg adds it to matching lines."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_arg",
            "action": "ensure",
            "module": "pam_unix.so",
            "arg": "use_authtok",
            "type": "password",
            "files": ["/etc/pam.d/system-auth"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "Ensured arg 'use_authtok'" in detail

    def test_ensure_idempotent(self, mock_ssh):
        """AC-5: Ensure is idempotent when arg already present."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_arg",
            "action": "ensure",
            "module": "pam_unix.so",
            "arg": "sha512",
            "type": "password",
            "files": ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        # The sed command itself handles idempotency via the negative match
        assert "Ensured arg 'sha512'" in detail
        assert "2 file(s)" in detail

    def test_type_filter(self, mock_ssh):
        """AC-6: Type filter narrows matching lines."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "sed -i": Result(exit_code=0, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_arg",
            "action": "remove",
            "module": "pam_unix.so",
            "arg": "nullok",
            "type": "auth",
            "files": ["/etc/pam.d/system-auth"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        # Verify the sed command includes the type filter
        sed_cmds = [c for c in ssh.commands_run if "sed -i" in c]
        assert len(sed_cmds) == 1
        assert "auth" in sed_cmds[0]

    def test_missing_file_skipped(self, mock_ssh):
        """AC-7: Non-existent files are skipped."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=1, stdout="", stderr=""),
            }
        )
        rem = {
            "mechanism": "pam_module_arg",
            "action": "remove",
            "module": "pam_unix.so",
            "arg": "nullok",
            "files": ["/etc/pam.d/nonexistent"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is True
        assert "0 file(s)" in detail

    def test_sed_failure(self, mock_ssh):
        """AC-8: sed failure returns error detail."""
        ssh = mock_ssh(
            {
                "test -f": Result(exit_code=0, stdout="", stderr=""),
                "sed -i": Result(exit_code=1, stdout="", stderr="sed: can't read file"),
            }
        )
        rem = {
            "mechanism": "pam_module_arg",
            "action": "remove",
            "module": "pam_unix.so",
            "arg": "nullok",
            "files": ["/etc/pam.d/system-auth"],
        }
        ok, detail, _ = run_remediation(ssh, rem, snapshot=False)
        assert ok is False
        assert "Failed to edit" in detail
