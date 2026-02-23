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
        ssh = mock_ssh({})
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set" in detail


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
    def test_restores_pam_file(self, mock_ssh):
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
    def test_captures_existing_file(self, mock_ssh):
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
        assert "Failed" in detail
