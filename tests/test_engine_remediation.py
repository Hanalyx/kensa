"""Tests for remediation handlers in runner/engine.py."""

from __future__ import annotations

from runner.engine import (
    PreState,
    StepResult,
    evaluate_rule,
    remediate_rule,
    run_remediation,
    _capture_config_set,
    _capture_config_set_dropin,
    _capture_command_exec,
    _capture_file_permissions,
    _capture_sysctl_set,
    _capture_package_present,
    _capture_kernel_module_disable,
    _capture_manual,
    _rollback_config_set,
    _rollback_config_set_dropin,
    _rollback_command_exec,
    _rollback_file_permissions,
    _rollback_sysctl_set,
    _rollback_package_present,
    _rollback_kernel_module_disable,
    _rollback_manual,
    _execute_rollback,
)
from runner.ssh import Result


# ── Existing remediation handler tests (updated for 3-tuple return) ────────


class TestConfigSet:
    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "bar", "separator": " "}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set" in detail

    def test_replaces_existing_key(self, mock_ssh):
        ssh = mock_ssh({
            "grep -q": Result(exit_code=0, stdout="", stderr=""),
            "sed -i": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "bar", "separator": " "}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("sed" in cmd for cmd in ssh.commands_run)

    def test_appends_when_key_absent(self, mock_ssh):
        ssh = mock_ssh({
            "grep -q": Result(exit_code=1, stdout="", stderr=""),
            "echo": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "bar", "separator": " "}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("echo" in cmd and ">>" in cmd for cmd in ssh.commands_run)

    def test_calls_reload(self, mock_ssh):
        ssh = mock_ssh({
            "grep -q": Result(exit_code=1, stdout="", stderr=""),
            "echo": Result(exit_code=0, stdout="", stderr=""),
            "systemctl": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "K", "value": "V", "separator": " ", "reload": "sshd"}
        ok, detail, _ = run_remediation(ssh, rem)
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
        ok, detail, _ = run_remediation(ssh, rem)
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
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would write" in detail


class TestCommandExec:
    def test_runs_command(self, mock_ssh):
        ssh = mock_ssh({
            "aide --init": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "command_exec", "run": "aide --init"}
        ok, detail, _ = run_remediation(ssh, rem)
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
        ok, detail, _ = run_remediation(ssh, rem)
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
        ssh = mock_ssh({
            "bad-cmd": Result(exit_code=127, stdout="", stderr="not found"),
        })
        rem = {"mechanism": "command_exec", "run": "bad-cmd"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False
        assert "failed" in detail.lower()


class TestFilePermissions:
    def test_sets_owner_group_mode(self, mock_ssh):
        ssh = mock_ssh({
            "chown": Result(exit_code=0, stdout="", stderr=""),
            "chmod": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "file_permissions", "path": "/etc/shadow", "owner": "root", "group": "root", "mode": "0000"}
        ok, detail, _ = run_remediation(ssh, rem)
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
        ssh = mock_ssh({
            "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
            "echo": Result(exit_code=0, stdout="", stderr=""),
        })
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is True
        assert any("sysctl -w" in cmd for cmd in ssh.commands_run)
        assert any("echo" in cmd and "sysctl.d" in cmd for cmd in ssh.commands_run)

    def test_dry_run(self, mock_ssh):
        ssh = mock_ssh({})
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ok, detail, _ = run_remediation(ssh, rem, dry_run=True)
        assert ok is True
        assert "Would set" in detail


class TestPackagePresent:
    def test_installs(self, mock_ssh):
        ssh = mock_ssh({
            "dnf install": Result(exit_code=0, stdout="Complete!", stderr=""),
        })
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
        ssh = mock_ssh({
            "dnf install": Result(exit_code=1, stdout="", stderr="No package aide available"),
        })
        rem = {"mechanism": "package_present", "name": "aide"}
        ok, detail, _ = run_remediation(ssh, rem)
        assert ok is False


class TestKernelModuleDisable:
    def test_blacklists_and_unloads(self, mock_ssh):
        ssh = mock_ssh({
            "printf": Result(exit_code=0, stdout="", stderr=""),
            "modprobe -r": Result(exit_code=0, stdout="", stderr=""),
        })
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
        ok, detail, _ = run_remediation(ssh, rem)
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


# ── Capture tests ──────────────────────────────────────────────────────────


class TestCaptureConfigSet:
    def test_key_exists(self, mock_ssh):
        ssh = mock_ssh({
            "grep '^ *Foo'": Result(exit_code=0, stdout="Foo bar", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "baz"}
        ps = _capture_config_set(ssh, rem)
        assert ps.mechanism == "config_set"
        assert ps.capturable is True
        assert ps.data["old_line"] == "Foo bar"
        assert ps.data["existed"] is True

    def test_key_absent(self, mock_ssh):
        ssh = mock_ssh({
            "grep '^ *Foo'": Result(exit_code=1, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "baz"}
        ps = _capture_config_set(ssh, rem)
        assert ps.data["old_line"] is None
        assert ps.data["existed"] is False

    def test_stores_reload_restart(self, mock_ssh):
        ssh = mock_ssh({
            "grep '^ *K'": Result(exit_code=1, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "K", "value": "V", "reload": "sshd"}
        ps = _capture_config_set(ssh, rem)
        assert ps.data["reload"] == "sshd"
        assert ps.data["restart"] is None


class TestCaptureConfigSetDropin:
    def test_file_exists(self, mock_ssh):
        ssh = mock_ssh({
            "test -f": Result(exit_code=0, stdout="", stderr=""),
            "cat": Result(exit_code=0, stdout="OldContent", stderr=""),
        })
        rem = {"mechanism": "config_set_dropin", "dir": "/etc/ssh/sshd_config.d", "file": "test.conf", "key": "K", "value": "V"}
        ps = _capture_config_set_dropin(ssh, rem)
        assert ps.data["existed"] is True
        assert ps.data["old_content"] == "OldContent"

    def test_file_absent(self, mock_ssh):
        ssh = mock_ssh({
            "test -f": Result(exit_code=1, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set_dropin", "dir": "/etc/ssh/sshd_config.d", "file": "test.conf", "key": "K", "value": "V"}
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
        ssh = mock_ssh({
            "stat -c": Result(exit_code=0, stdout="root root 644 /etc/shadow", stderr=""),
        })
        rem = {"mechanism": "file_permissions", "path": "/etc/shadow", "owner": "root", "mode": "0000"}
        ps = _capture_file_permissions(ssh, rem)
        assert ps.mechanism == "file_permissions"
        assert len(ps.data["entries"]) == 1
        assert ps.data["entries"][0]["owner"] == "root"
        assert ps.data["entries"][0]["group"] == "root"
        assert ps.data["entries"][0]["mode"] == "644"
        assert ps.data["entries"][0]["path"] == "/etc/shadow"

    def test_multiple_files(self, mock_ssh):
        ssh = mock_ssh({
            "stat -c": Result(exit_code=0, stdout="root ssh_keys 640 /etc/ssh/ssh_host_rsa_key\nroot ssh_keys 640 /etc/ssh/ssh_host_ed25519_key", stderr=""),
        })
        rem = {"mechanism": "file_permissions", "path": "/etc/ssh/ssh_host_*_key", "glob": True}
        ps = _capture_file_permissions(ssh, rem)
        assert len(ps.data["entries"]) == 2


class TestCaptureSysctlSet:
    def test_captures_value_and_persist(self, mock_ssh):
        ssh = mock_ssh({
            "sysctl -n": Result(exit_code=0, stdout="1", stderr=""),
            "cat": Result(exit_code=0, stdout="net.ipv4.ip_forward = 1", stderr=""),
        })
        rem = {"mechanism": "sysctl_set", "key": "net.ipv4.ip_forward", "value": "0"}
        ps = _capture_sysctl_set(ssh, rem)
        assert ps.data["old_value"] == "1"
        assert ps.data["persist_existed"] is True
        assert "net.ipv4.ip_forward = 1" in ps.data["old_persist"]


class TestCapturePackagePresent:
    def test_installed(self, mock_ssh):
        ssh = mock_ssh({
            "rpm -q": Result(exit_code=0, stdout="aide-0.16-1.el9", stderr=""),
        })
        rem = {"mechanism": "package_present", "name": "aide"}
        ps = _capture_package_present(ssh, rem)
        assert ps.data["was_installed"] is True

    def test_not_installed(self, mock_ssh):
        ssh = mock_ssh({
            "rpm -q": Result(exit_code=1, stdout="", stderr=""),
        })
        rem = {"mechanism": "package_present", "name": "aide"}
        ps = _capture_package_present(ssh, rem)
        assert ps.data["was_installed"] is False


class TestCaptureKernelModuleDisable:
    def test_conf_and_loaded(self, mock_ssh):
        ssh = mock_ssh({
            "cat": Result(exit_code=0, stdout="blacklist cramfs\ninstall cramfs /bin/false", stderr=""),
            "lsmod": Result(exit_code=0, stdout="", stderr=""),
        })
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
        ssh = mock_ssh({
            "sed -i": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="config_set", data={
            "path": "/etc/conf", "key": "Foo", "old_line": "Foo oldval",
            "existed": True, "reload": None, "restart": None,
        })
        ok, detail = _rollback_config_set(ssh, ps)
        assert ok is True
        assert "Restored" in detail
        assert any("sed" in cmd for cmd in ssh.commands_run)

    def test_removes_appended_line(self, mock_ssh):
        ssh = mock_ssh({
            "sed -i": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="config_set", data={
            "path": "/etc/conf", "key": "Foo", "old_line": None,
            "existed": False, "reload": "sshd", "restart": None,
        })
        ok, detail = _rollback_config_set(ssh, ps)
        assert ok is True
        assert any("sed" in cmd and "/d" in cmd for cmd in ssh.commands_run)


class TestRollbackConfigSetDropin:
    def test_removes_new_file(self, mock_ssh):
        ssh = mock_ssh({
            "rm -f": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="config_set_dropin", data={
            "path": "/etc/ssh/sshd_config.d/test.conf", "old_content": None,
            "existed": False, "reload": "sshd", "restart": None,
        })
        ok, detail = _rollback_config_set_dropin(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_restores_old_content(self, mock_ssh):
        ssh = mock_ssh({
            "printf": Result(exit_code=0, stdout="", stderr=""),
            "systemctl": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="config_set_dropin", data={
            "path": "/etc/ssh/sshd_config.d/test.conf", "old_content": "OldLine",
            "existed": True, "reload": "sshd", "restart": None,
        })
        ok, detail = _rollback_config_set_dropin(ssh, ps)
        assert ok is True
        assert "Restored" in detail


class TestRollbackCommandExec:
    def test_cannot_rollback(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(mechanism="command_exec", data={"note": "arbitrary"}, capturable=False)
        ok, detail = _rollback_command_exec(ssh, ps)
        assert ok is False
        assert "Cannot rollback" in detail


class TestRollbackFilePermissions:
    def test_restores_permissions(self, mock_ssh):
        ssh = mock_ssh({
            "chown": Result(exit_code=0, stdout="", stderr=""),
            "chmod": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="file_permissions", data={
            "entries": [{"path": "/etc/shadow", "owner": "root", "group": "root", "mode": "640"}],
        })
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
        ssh = mock_ssh({
            "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
            "printf": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="sysctl_set", data={
            "key": "net.ipv4.ip_forward", "old_value": "1",
            "persist_file": "/etc/sysctl.d/99-aegis-net-ipv4-ip-forward.conf",
            "old_persist": "net.ipv4.ip_forward = 1", "persist_existed": True,
        })
        ok, detail = _rollback_sysctl_set(ssh, ps)
        assert ok is True
        assert any("sysctl -w" in cmd for cmd in ssh.commands_run)

    def test_removes_persist_if_not_existed(self, mock_ssh):
        ssh = mock_ssh({
            "sysctl -w": Result(exit_code=0, stdout="", stderr=""),
            "rm -f": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="sysctl_set", data={
            "key": "net.ipv4.ip_forward", "old_value": "1",
            "persist_file": "/etc/sysctl.d/99-aegis-net-ipv4-ip-forward.conf",
            "old_persist": None, "persist_existed": False,
        })
        ok, detail = _rollback_sysctl_set(ssh, ps)
        assert ok is True
        assert any("rm -f" in cmd for cmd in ssh.commands_run)


class TestRollbackPackagePresent:
    def test_removes_if_not_installed(self, mock_ssh):
        ssh = mock_ssh({
            "dnf remove": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="package_present", data={"name": "aide", "was_installed": False})
        ok, detail = _rollback_package_present(ssh, ps)
        assert ok is True
        assert "Removed" in detail

    def test_noop_if_was_installed(self, mock_ssh):
        ssh = mock_ssh({})
        ps = PreState(mechanism="package_present", data={"name": "aide", "was_installed": True})
        ok, detail = _rollback_package_present(ssh, ps)
        assert ok is True
        assert "already installed" in detail


class TestRollbackKernelModuleDisable:
    def test_restores_conf_and_reloads(self, mock_ssh):
        ssh = mock_ssh({
            "printf": Result(exit_code=0, stdout="", stderr=""),
            "modprobe": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="kernel_module_disable", data={
            "name": "cramfs", "conf_path": "/etc/modprobe.d/cramfs.conf",
            "old_conf": "# nothing", "conf_existed": True, "was_loaded": True,
        })
        ok, detail = _rollback_kernel_module_disable(ssh, ps)
        assert ok is True
        assert any("modprobe" in cmd and "cramfs" in cmd for cmd in ssh.commands_run)

    def test_removes_conf_if_not_existed(self, mock_ssh):
        ssh = mock_ssh({
            "rm -f": Result(exit_code=0, stdout="", stderr=""),
        })
        ps = PreState(mechanism="kernel_module_disable", data={
            "name": "cramfs", "conf_path": "/etc/modprobe.d/cramfs.conf",
            "old_conf": None, "conf_existed": False, "was_loaded": False,
        })
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
        ssh = mock_ssh({
            "grep -q": Result(exit_code=1, stdout="", stderr=""),
            "echo": Result(exit_code=0, stdout="", stderr=""),
            "grep '^ *Foo'": Result(exit_code=1, stdout="", stderr=""),
        })
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "bar", "separator": " "}
        ok, detail, step_results = run_remediation(ssh, rem)
        assert ok is True
        assert len(step_results) == 1
        assert step_results[0].step_index == 0
        assert step_results[0].mechanism == "config_set"
        assert step_results[0].success is True
        assert step_results[0].pre_state is not None
        assert step_results[0].pre_state.mechanism == "config_set"

    def test_multi_step_returns_step_results(self, mock_ssh):
        ssh = mock_ssh({
            "dnf install": Result(exit_code=0, stdout="", stderr=""),
            "aide --init": Result(exit_code=0, stdout="", stderr=""),
            "test -f": Result(exit_code=1, stdout="", stderr=""),
            "rpm -q": Result(exit_code=1, stdout="", stderr=""),
        })
        rem = {
            "steps": [
                {"mechanism": "package_present", "name": "aide"},
                {"mechanism": "command_exec", "run": "aide --init", "unless": "test -f /var/lib/aide/aide.db.gz"},
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
        rem = {"mechanism": "config_set", "path": "/etc/conf", "key": "Foo", "value": "bar", "separator": " "}
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
                if "grep '^ *deny'" in cmd and "tail" in cmd:
                    # Capture grep
                    return Result(exit_code=1, stdout="", stderr="")
                if "grep -q" in cmd:
                    # Remediation grep
                    return Result(exit_code=1, stdout="", stderr="")
                if "echo" in cmd:
                    return Result(exit_code=0, stdout="", stderr="")
                if "grep -h" in cmd or "grep -rh" in cmd:
                    # Check: config_value
                    call_count["check"] += 1
                    if call_count["check"] <= 1:
                        return Result(exit_code=0, stdout="deny = 5", stderr="")
                    return Result(exit_code=0, stdout="deny = 5", stderr="")
                if "test -d" in cmd:
                    return Result(exit_code=1, stdout="", stderr="")
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
        ssh = mock_ssh({
            # Capture config_set
            "grep '^ *deny'": Result(exit_code=0, stdout="deny = 3", stderr=""),
            # Remediate config_set
            "grep -q": Result(exit_code=0, stdout="", stderr=""),
            "sed -i": Result(exit_code=0, stdout="", stderr=""),
            # Capture command_exec (no SSH call needed)
            # Remediate command_exec fails
            "authselect apply-changes": Result(exit_code=1, stdout="", stderr="authselect error"),
        })
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
        cmd_rollback = [rb for rb in result.rollback_results if rb.mechanism == "command_exec"]
        assert all(rb.detail == "skipped" for rb in cmd_rollback)
        # The config_set step (succeeded) should have been rolled back
        cfg_rollback = [rb for rb in result.rollback_results if rb.mechanism == "config_set"]
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
                if "echo" in cmd:
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
