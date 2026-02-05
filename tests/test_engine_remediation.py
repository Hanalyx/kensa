"""Tests for remediation handlers in runner/engine.py."""

from __future__ import annotations

from runner.engine import evaluate_rule, remediate_rule, run_remediation
from runner.ssh import Result


class TestConfigSet:
    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "bar", "separator": " "}
        ok, detail = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set" in detail

    def test_replaces_existing_key(self, mock_ssh):
        ssh = mock_ssh({
            "grep -q": Result(exit_code=0, stdout="", stderr=""),
            "sed -i": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "bar", "separator": " "}
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert any("sed" in cmd for cmd in ssh.commands_run)

    def test_appends_when_key_absent(self, mock_ssh):
        ssh = mock_ssh({
            "grep -q": Result(exit_code=1, stdout="", stderr=""),
            "echo": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "bar", "separator": " "}
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert any("echo" in cmd and ">>" in cmd for cmd in ssh.commands_run)

    def test_calls_reload(self, mock_ssh):
        ssh = mock_ssh({
            "grep -q": Result(exit_code=1, stdout="", stderr=""),
            "echo": Result(exit_code=0, stdout="", stderr=""),
            "systemctl": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "K", "value": "V", "separator": " ", "reload": "sshd"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert any("systemctl" in cmd and "sshd" in cmd for cmd in ssh.commands_run)


class TestConfigSetDropin:
    def test_writes_file(self, mock_ssh):
        ssh = mock_ssh({
            "echo": Result(exit_code=0, stdout="", stderr=""),
            "systemctl": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-aegis-test.conf",
            "key": "PermitRootLogin",
            "value": "no",
            "reload": "sshd",
        }
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert "00-aegis-test.conf" in detail

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {
            "mechanism": "config_set_dropin",
            "dir": "/etc/ssh/sshd_config.d",
            "file": "00-aegis-test.conf",
            "key": "K",
            "value": "V",
        }
        ok, detail = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would write" in detail


class TestCommandExec:
    def test_runs_command(self, mock_ssh):
        ssh = mock_ssh({
            "aide --init": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "command_exec", "run": "aide --init"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is True

    def test_unless_guard_skips(self, mock_ssh):
        ssh = mock_ssh({
            "test -f /var/lib/aide/aide.db.gz": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {
            "mechanism": "command_exec",
            "run": "aide --init",
            "unless": "test -f /var/lib/aide/aide.db.gz",
        }
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert "Skipped" in detail

    def test_onlyif_guard_skips(self, mock_ssh):
        ssh = mock_ssh({
            "which aide": Result(exit_code=1, stdout="", stderr=""),
        })
        rem = {
            "mechanism": "command_exec",
            "run": "aide --init",
            "onlyif": "which aide",
        }
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert "Skipped" in detail

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "command_exec", "run": "dangerous-command"}
        ok, detail = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would run" in detail

    def test_command_failure(self, mock_ssh):
        ssh = mock_ssh({
            "bad-cmd": Result(exit_code=127, stdout="", stderr="not found"),
        })
        rem = {"mechanism": "command_exec", "run": "bad-cmd"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is False
        assert "failed" in detail.lower()


class TestFilePermissions:
    def test_sets_owner_group_mode(self, mock_ssh):
        ssh = mock_ssh({
            "chown": Result(exit_code=0, stdout="", stderr=""),
            "chmod": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "file_permissions", "path": "/etc/shadow", "owner": "root", "group": "root", "mode": "0000"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert any("chown" in cmd for cmd in ssh.commands_run)
        assert any("chmod" in cmd for cmd in ssh.commands_run)

    def test_glob_path_not_quoted(self, mock_ssh):
        ssh = mock_ssh({
            "chown": Result(exit_code=0, stdout="", stderr=""),
            "chmod": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {
            "mechanism": "file_permissions",
            "path": "/etc/ssh/ssh_host_*_key",
            "owner": "root",
            "group": "ssh_keys",
            "mode": "0640",
            "glob": "ssh_host_*_key",
        }
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        # The path should NOT be quoted (no single quotes around it)
        chown_cmd = [c for c in ssh.commands_run if "chown" in c][0]
        assert "'/etc/ssh/ssh_host_*_key'" not in chown_cmd
        assert "/etc/ssh/ssh_host_*_key" in chown_cmd

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "file_permissions", "path": "/etc/shadow", "mode": "0000"}
        ok, detail = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would run" in detail


class TestSysctlSet:
    def test_applies_and_persists(self, mock_ssh):
        ssh = mock_ssh({
            "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
            "echo": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert any("sysctl -w" in cmd for cmd in ssh.commands_run)
        assert any("echo" in cmd and "sysctl.d" in cmd for cmd in ssh.commands_run)

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set" in detail


class TestPackagePresent:
    def test_installs(self, mock_ssh):
        ssh = mock_ssh({
            "dnf install": Result(exit_code=0, stdout="Complete!", stderr=""),
        })
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert "Installed" in detail

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would install" in detail

    def test_failure(self, mock_ssh):
        ssh = mock_ssh({
            "dnf install": Result(exit_code=1, stdout="", stderr="No package aide available"),
        })
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is False


class TestKernelModuleDisable:
    def test_blacklists_and_unloads(self, mock_ssh):
        ssh = mock_ssh({
            "printf": Result(exit_code=0, stdout="", stderr=""),
            "modprobe -r": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is True
        assert "Blacklisted" in detail

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "kernel_module_disable", "name": "cramfs"}
        ok, detail = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would blacklist" in detail


class TestManual:
    def test_returns_false_with_note(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "manual", "note": "Contact security team"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is False
        assert "MANUAL" in detail
        assert "Contact security team" in detail


class TestMultiStepRemediation:
    def test_sequential_execution(self, mock_ssh):
        ssh = mock_ssh({
            "dnf install": Result(exit_code=0, stdout="", stderr=""),
            "aide --init": Result(exit_code=0, stdout="", stderr=""),
            "test -f": Result(exit_code=1, stdout="", stderr=""),
        })
        rem = {
            "steps": [
                {"mechanism": "package_present", "name": "aide"},
                {"mechanism": "command_exec", "run": "aide --init", "unless": "test -f /var/lib/aide/aide.db.gz"},
            ]
        }
        ok, detail = run_remediation(ssh, rem)
        assert ok is True

    def test_stops_on_failure(self, mock_ssh):
        ssh = mock_ssh({
            "dnf install": Result(exit_code=1, stdout="", stderr="Error"),
        })
        rem = {
            "steps": [
                {"mechanism": "package_present", "name": "aide"},
                {"mechanism": "command_exec", "run": "aide --init"},
            ]
        }
        ok, detail = run_remediation(ssh, rem)
        assert ok is False


class TestUnknownMechanism:
    def test_unknown_mechanism(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "nonexistent_mechanism"}
        ok, detail = run_remediation(ssh, rem)
        assert ok is False
        assert "Unknown" in detail


class TestFullCycle:
    def test_evaluate_and_remediate(self, mock_ssh, sample_rule):
        """check → fail → remediate → re-check → pass."""
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
