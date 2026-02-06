"""Shared fixtures for aegis test suite."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from runner.ssh import Result


class MockSSHSession:
    """Mock SSH session that returns pre-configured responses."""

    def __init__(self, responses: dict[str, Result] | None = None):
        self.responses: dict[str, Result] = responses or {}
        self.commands_run: list[str] = []
        self.sudo = False

    def run(self, cmd: str, *, timeout: int | None = None) -> Result:
        self.commands_run.append(cmd)
        # Try exact match first, then substring match
        if cmd in self.responses:
            return self.responses[cmd]
        for pattern, result in self.responses.items():
            if pattern in cmd:
                return result
        return Result(exit_code=1, stdout="", stderr="command not mocked")

    def connect(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass


@pytest.fixture
def mock_ssh():
    """Factory fixture — returns a MockSSHSession with given responses."""

    def _factory(responses: dict[str, Result] | None = None) -> MockSSHSession:
        return MockSSHSession(responses)

    return _factory


@pytest.fixture
def ok():
    """Shorthand for a successful Result."""
    return Result(exit_code=0, stdout="", stderr="")


@pytest.fixture
def fail():
    """Shorthand for a failed Result."""
    return Result(exit_code=1, stdout="", stderr="")


@pytest.fixture
def sample_caps():
    """Capabilities dict matching a typical hardened RHEL 9 host."""
    return {
        "sshd_config_d": True,
        "authselect": True,
        "authselect_sssd": False,
        "crypto_policies": True,
        "crypto_policy_modules": True,
        "fips_mode": False,
        "firewalld_nftables": True,
        "firewalld_iptables": False,
        "systemd_resolved": False,
        "pam_faillock": True,
        "grub_bls": True,
        "grub_legacy": False,
        "journald_primary": True,
        "rsyslog_active": True,
        "fapolicyd": False,
        "selinux": True,
        "aide": True,
        "tpm2": False,
        "usbguard": False,
        "dnf_automatic": False,
        "gdm": False,
        "tmux": True,
    }


@pytest.fixture
def sample_rule():
    """Minimal single-implementation rule."""
    return {
        "id": "test-sysctl-rule",
        "title": "Test sysctl rule",
        "description": "A test rule.",
        "rationale": "Testing.",
        "severity": "medium",
        "category": "kernel",
        "tags": ["sysctl", "test"],
        "platforms": [{"family": "rhel", "min_version": 8}],
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


@pytest.fixture
def sample_rule_gated():
    """Rule with a capability-gated implementation + default fallback."""
    return {
        "id": "test-gated-rule",
        "title": "Test gated rule",
        "description": "A test rule with gates.",
        "rationale": "Testing.",
        "severity": "high",
        "category": "access-control",
        "tags": ["ssh", "test"],
        "platforms": [{"family": "rhel", "min_version": 8}],
        "implementations": [
            {
                "when": "sshd_config_d",
                "check": {
                    "method": "config_value",
                    "path": "/etc/ssh/sshd_config.d",
                    "key": "PermitRootLogin",
                    "expected": "no",
                    "scan_pattern": "*.conf",
                },
                "remediation": {
                    "mechanism": "config_set_dropin",
                    "dir": "/etc/ssh/sshd_config.d",
                    "file": "00-aegis-permit-root-login.conf",
                    "key": "PermitRootLogin",
                    "value": "no",
                    "reload": "sshd",
                },
            },
            {
                "default": True,
                "check": {
                    "method": "config_value",
                    "path": "/etc/ssh/sshd_config",
                    "key": "PermitRootLogin",
                    "expected": "no",
                },
                "remediation": {
                    "mechanism": "config_set",
                    "path": "/etc/ssh/sshd_config",
                    "key": "PermitRootLogin",
                    "value": "no",
                    "separator": " ",
                    "reload": "sshd",
                },
            },
        ],
    }


@pytest.fixture
def sample_rule_multistep():
    """Rule with a 2-step remediation (config_set + command_exec)."""
    return {
        "id": "test-multistep-rule",
        "title": "Test multistep rule",
        "description": "A test rule with multi-step remediation.",
        "rationale": "Testing.",
        "severity": "high",
        "category": "access-control",
        "tags": ["pam", "test"],
        "platforms": [{"family": "rhel", "min_version": 8}],
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


@pytest.fixture
def tmp_rule_file(tmp_path):
    """Factory: write a rule dict to a temp YAML file, return path."""

    def _factory(rule: dict, filename: str | None = None) -> Path:
        name = filename or f"{rule['id']}.yml"
        p = tmp_path / name
        p.write_text(yaml.dump(rule, default_flow_style=False))
        return p

    return _factory


@pytest.fixture
def tmp_rule_dir(tmp_path):
    """Factory: write multiple rules to a temp directory, return dir path."""

    def _factory(rules: list[dict]) -> Path:
        for rule in rules:
            p = tmp_path / f"{rule['id']}.yml"
            p.write_text(yaml.dump(rule, default_flow_style=False))
        return tmp_path

    return _factory
