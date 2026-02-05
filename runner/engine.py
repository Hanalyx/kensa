"""Rule loading, implementation selection, check and remediation dispatch."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from runner.ssh import SSHSession


# ── Data types ──────────────────────────────────────────────────────────────


@dataclass
class CheckResult:
    """Outcome of a single check."""

    passed: bool
    detail: str = ""


@dataclass
class RuleResult:
    """Outcome of evaluating one rule on one host."""

    rule_id: str
    title: str
    severity: str
    passed: bool
    skipped: bool = False
    skip_reason: str = ""
    detail: str = ""
    remediated: bool = False
    remediation_detail: str = ""


# ── Rule loading ────────────────────────────────────────────────────────────


def load_rules(
    path: str | None = None,
    *,
    severity: list[str] | None = None,
    tags: list[str] | None = None,
    category: str | None = None,
) -> list[dict]:
    """Load rules from a file or directory (recursive). Apply optional filters."""
    if path is None:
        raise ValueError("No rules path specified")

    p = Path(path)
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml"))
    else:
        raise FileNotFoundError(f"Rules path not found: {path}")

    rules = []
    for f in files:
        try:
            data = yaml.safe_load(f.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "id" not in data:
            continue
        rules.append(data)

    # Apply filters
    if severity:
        sev_set = {s.lower() for s in severity}
        rules = [r for r in rules if r.get("severity", "").lower() in sev_set]
    if tags:
        tag_set = {t.lower() for t in tags}
        rules = [r for r in rules if tag_set & {t.lower() for t in r.get("tags", [])}]
    if category:
        rules = [r for r in rules if r.get("category", "").lower() == category.lower()]

    return rules


# ── Platform filtering ──────────────────────────────────────────────────────


def rule_applies_to_platform(rule: dict, family: str, version: int) -> bool:
    """Check if a rule's platforms: constraint matches the detected host.

    Returns True (rule applies) when:
      - The rule has no platforms field at all
      - Any platform entry matches the given family and version range
    """
    platforms = rule.get("platforms")
    if platforms is None:
        return True
    if not platforms:
        return False

    for p in platforms:
        if p.get("family", "") != family:
            continue
        min_v = p.get("min_version", 0)
        max_v = p.get("max_version", 99)
        if min_v <= version <= max_v:
            return True
    return False


# ── Implementation selection ────────────────────────────────────────────────


def evaluate_when(when, capabilities: dict[str, bool]) -> bool:
    """Evaluate a capability gate.

    Supports:
        when: "cap_name"           → single capability
        when: { all: [...] }       → all must be true
        when: { any: [...] }       → at least one true
    """
    if when is None:
        return True
    if isinstance(when, str):
        return capabilities.get(when, False)
    if isinstance(when, dict):
        if "all" in when:
            return all(capabilities.get(c, False) for c in when["all"])
        if "any" in when:
            return any(capabilities.get(c, False) for c in when["any"])
    return False


def select_implementation(
    rule: dict, capabilities: dict[str, bool]
) -> dict | None:
    """Select the first matching implementation by capability gate.

    Non-default implementations are checked in order; the first whose `when`
    gate passes wins.  If none match, the `default: true` implementation is
    returned.
    """
    default_impl = None
    for impl in rule.get("implementations", []):
        if impl.get("default"):
            default_impl = impl
            continue
        if evaluate_when(impl.get("when"), capabilities):
            return impl
    return default_impl


# ── Check dispatch ──────────────────────────────────────────────────────────


def run_check(ssh: SSHSession, check: dict) -> CheckResult:
    """Dispatch a single check definition to the right handler."""
    # Multi-condition check (AND semantics)
    if "checks" in check:
        details = []
        for sub in check["checks"]:
            r = _dispatch_check(ssh, sub)
            if not r.passed:
                return CheckResult(passed=False, detail=r.detail)
            details.append(r.detail)
        return CheckResult(passed=True, detail="; ".join(d for d in details if d))

    return _dispatch_check(ssh, check)


def _dispatch_check(ssh: SSHSession, check: dict) -> CheckResult:
    method = check.get("method", "")
    handler = CHECK_HANDLERS.get(method)
    if handler is None:
        return CheckResult(passed=False, detail=f"Unknown check method: {method}")
    return handler(ssh, check)


# ── Individual check handlers ──────────────────────────────────────────────


def _check_config_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check key=value in a config file or .d directory."""
    path = c["path"]
    key = c["key"]
    expected = str(c["expected"])

    # If path is a directory, scan files matching pattern
    scan_pattern = c.get("scan_pattern", "*.conf")
    result = ssh.run(f"test -d {shlex.quote(path)}")
    if result.ok:
        # Directory mode: grep across files
        cmd = (
            f"grep -rh '^ *{key}' {shlex.quote(path)}/{scan_pattern} 2>/dev/null"
            f" | tail -1"
        )
    else:
        cmd = f"grep -h '^ *{key}' {shlex.quote(path)} 2>/dev/null | tail -1"

    result = ssh.run(cmd)
    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{key} not found in {path}")

    # Extract value: handle both 'key value' and 'key=value' and 'key = value'
    line = result.stdout.strip()
    # Remove the key prefix, then separators
    after_key = line[len(key):].strip() if key in line else line.split(None, 1)[-1]
    actual = after_key.lstrip("= \t").strip().strip('"').strip("'")

    if actual.lower() == expected.lower():
        return CheckResult(passed=True, detail=f"{key}={actual}")
    return CheckResult(passed=False, detail=f"{key}={actual} (expected {expected})")


def _check_file_permission(ssh: SSHSession, c: dict) -> CheckResult:
    """Check file ownership and mode. Supports glob paths."""
    path = c["path"]
    is_glob = "glob" in c or any(ch in path for ch in "*?[")

    if is_glob:
        # Don't quote — let the shell expand the glob
        result = ssh.run(f"stat -c '%U %G %a %n' {path} 2>/dev/null")
    else:
        result = ssh.run(f"stat -c '%U %G %a %n' {shlex.quote(path)} 2>/dev/null")

    if not result.ok or not result.stdout.strip():
        return CheckResult(passed=False, detail=f"{path}: not found or not accessible")

    all_failures = []
    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        actual_owner, actual_group, actual_mode = parts[0], parts[1], parts[2]
        file_path = " ".join(parts[3:])
        failures = []

        if "owner" in c and actual_owner != c["owner"]:
            failures.append(f"owner={actual_owner} (expected {c['owner']})")
        if "group" in c and actual_group != c["group"]:
            failures.append(f"group={actual_group} (expected {c['group']})")
        if "mode" in c:
            expected_mode = c["mode"].lstrip("0") or "0"
            actual_mode_norm = actual_mode.lstrip("0") or "0"
            if actual_mode_norm != expected_mode:
                failures.append(f"mode={actual_mode} (expected {c['mode']})")

        if failures:
            all_failures.append(f"{file_path}: {', '.join(failures)}")

    if all_failures:
        return CheckResult(passed=False, detail="; ".join(all_failures))
    return CheckResult(passed=True, detail=f"{path}: ok")


def _check_command(ssh: SSHSession, c: dict) -> CheckResult:
    """Run arbitrary command and check exit code / stdout."""
    cmd = c["run"]
    result = ssh.run(cmd)

    expected_exit = c.get("expected_exit", 0)
    if result.exit_code != expected_exit:
        return CheckResult(
            passed=False,
            detail=f"exit {result.exit_code} (expected {expected_exit}): {result.stderr or result.stdout}",
        )

    if "expected_stdout" in c:
        if c["expected_stdout"] not in result.stdout:
            return CheckResult(
                passed=False,
                detail=f"stdout mismatch: got {result.stdout!r}",
            )

    return CheckResult(passed=True, detail=result.stdout[:200] if result.stdout else "ok")


def _check_sysctl_value(ssh: SSHSession, c: dict) -> CheckResult:
    """Check a sysctl kernel parameter value."""
    key = c["key"]
    expected = str(c["expected"])
    result = ssh.run(f"sysctl -n {shlex.quote(key)} 2>/dev/null")
    if not result.ok:
        return CheckResult(passed=False, detail=f"sysctl {key}: not available")

    actual = result.stdout.strip()
    if actual == expected:
        return CheckResult(passed=True, detail=f"{key}={actual}")
    return CheckResult(passed=False, detail=f"{key}={actual} (expected {expected})")


def _check_kernel_module_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check if a kernel module is loaded or blacklisted."""
    name = c["name"]
    state = c.get("state", "blacklisted")

    if state == "blacklisted":
        # Module should NOT be loaded and should be blacklisted
        loaded = ssh.run(f"lsmod | grep -q '^{name} '")
        if loaded.ok:
            return CheckResult(passed=False, detail=f"{name}: still loaded")

        blacklisted = ssh.run(
            f"modprobe -n -v {shlex.quote(name)} 2>&1 | grep -q 'install /bin/true\\|install /bin/false\\|blacklist'"
        )
        if not blacklisted.ok:
            return CheckResult(passed=False, detail=f"{name}: not blacklisted")

        return CheckResult(passed=True, detail=f"{name}: blacklisted")

    elif state == "loaded":
        loaded = ssh.run(f"lsmod | grep -q '^{name} '")
        if loaded.ok:
            return CheckResult(passed=True, detail=f"{name}: loaded")
        return CheckResult(passed=False, detail=f"{name}: not loaded")

    return CheckResult(passed=False, detail=f"Unknown module state: {state}")


def _check_package_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check if a package is installed or absent."""
    name = c["name"]
    state = c.get("state", "present")

    result = ssh.run(f"rpm -q {shlex.quote(name)} 2>/dev/null")

    if state == "present":
        if result.ok:
            return CheckResult(passed=True, detail=f"{name}: {result.stdout.strip()}")
        return CheckResult(passed=False, detail=f"{name}: not installed")
    elif state == "absent":
        if not result.ok:
            return CheckResult(passed=True, detail=f"{name}: not installed (as required)")
        return CheckResult(passed=False, detail=f"{name}: installed (should be absent)")

    return CheckResult(passed=False, detail=f"Unknown package state: {state}")


def _check_file_exists(ssh: SSHSession, c: dict) -> CheckResult:
    """Check if a file exists."""
    path = c["path"]
    result = ssh.run(f"test -f {shlex.quote(path)}")
    if result.ok:
        return CheckResult(passed=True, detail=f"{path}: exists")
    return CheckResult(passed=False, detail=f"{path}: not found")


CHECK_HANDLERS = {
    "config_value": _check_config_value,
    "file_permission": _check_file_permission,
    "command": _check_command,
    "sysctl_value": _check_sysctl_value,
    "kernel_module_state": _check_kernel_module_state,
    "package_state": _check_package_state,
    "file_exists": _check_file_exists,
}


# ── Remediation dispatch ───────────────────────────────────────────────────


def run_remediation(
    ssh: SSHSession, remediation: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Dispatch a remediation definition. Returns (success, detail)."""
    # Multi-step remediation
    if "steps" in remediation:
        details = []
        for step in remediation["steps"]:
            ok, detail = _dispatch_remediation(ssh, step, dry_run=dry_run)
            details.append(detail)
            if not ok:
                return False, "; ".join(details)
        return True, "; ".join(details)

    return _dispatch_remediation(ssh, remediation, dry_run=dry_run)


def _dispatch_remediation(
    ssh: SSHSession, rem: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    mechanism = rem.get("mechanism", "")
    handler = REMEDIATION_HANDLERS.get(mechanism)
    if handler is None:
        return False, f"Unknown remediation mechanism: {mechanism}"
    return handler(ssh, rem, dry_run=dry_run)


# ── Individual remediation handlers ────────────────────────────────────────


def _remediate_config_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set key=value in a config file."""
    path = r["path"]
    key = r["key"]
    value = r["value"]
    sep = r.get("separator", " ")

    line = f"{key}{sep}{value}"

    if dry_run:
        return True, f"Would set '{line}' in {path}"

    # Replace existing line or append
    check = ssh.run(f"grep -q '^ *{key}' {shlex.quote(path)} 2>/dev/null")
    if check.ok:
        # Replace in place — escape sed delimiters
        escaped_line = line.replace("/", "\\/")
        cmd = f"sed -i 's/^ *{key}.*/{escaped_line}/' {shlex.quote(path)}"
    else:
        cmd = f"echo {shlex.quote(line)} >> {shlex.quote(path)}"

    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to set {key} in {path}: {result.stderr}"

    _reload_service(ssh, r)
    return True, f"Set '{line}' in {path}"


def _remediate_config_set_dropin(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Write key=value to a drop-in directory file."""
    dir_path = r["dir"]
    filename = r["file"]
    key = r["key"]
    value = r["value"]
    sep = r.get("separator", " ")

    full_path = f"{dir_path}/{filename}"
    line = f"{key}{sep}{value}"

    if dry_run:
        return True, f"Would write '{line}' to {full_path}"

    cmd = f"echo {shlex.quote(line)} > {shlex.quote(full_path)}"
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed to write {full_path}: {result.stderr}"

    _reload_service(ssh, r)
    return True, f"Wrote '{line}' to {full_path}"


def _remediate_command_exec(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Run a command with optional unless/onlyif guards."""
    cmd = r["run"]

    # Check unless guard (skip if it succeeds)
    if "unless" in r:
        guard = ssh.run(r["unless"])
        if guard.ok:
            return True, f"Skipped (unless guard passed): {r['unless']}"

    # Check onlyif guard (skip if it fails)
    if "onlyif" in r:
        guard = ssh.run(r["onlyif"])
        if not guard.ok:
            return True, f"Skipped (onlyif guard failed): {r['onlyif']}"

    if dry_run:
        return True, f"Would run: {cmd}"

    result = ssh.run(cmd, timeout=120)
    if not result.ok:
        return False, f"Command failed (exit {result.exit_code}): {result.stderr or result.stdout}"

    _reload_service(ssh, r)
    return True, f"Executed: {cmd}"


def _remediate_file_permissions(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set file ownership and permissions. Supports glob paths."""
    path = r["path"]
    is_glob = "glob" in r or any(ch in path for ch in "*?[")
    quoted = path if is_glob else shlex.quote(path)
    parts = []

    if "owner" in r or "group" in r:
        owner = r.get("owner", "")
        group = r.get("group", "")
        chown_spec = f"{owner}:{group}" if group else owner
        parts.append(f"chown {chown_spec} {quoted}")

    if "mode" in r:
        parts.append(f"chmod {r['mode']} {quoted}")

    if dry_run:
        return True, f"Would run: {' && '.join(parts)}"

    cmd = " && ".join(parts)
    result = ssh.run(cmd)
    if not result.ok:
        return False, f"Failed: {result.stderr}"
    return True, f"Set permissions on {path}"


def _remediate_sysctl_set(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Set sysctl value and persist it."""
    key = r["key"]
    value = r["value"]
    persist_file = r.get("persist_file", f"/etc/sysctl.d/99-aegis-{key.replace('.', '-')}.conf")

    if dry_run:
        return True, f"Would set sysctl {key}={value} and persist to {persist_file}"

    # Apply immediately
    result = ssh.run(f"sysctl -w {shlex.quote(key)}={shlex.quote(str(value))}")
    if not result.ok:
        return False, f"sysctl -w failed: {result.stderr}"

    # Persist
    line = f"{key} = {value}"
    result = ssh.run(f"echo {shlex.quote(line)} > {shlex.quote(persist_file)}")
    if not result.ok:
        return False, f"Failed to persist {persist_file}: {result.stderr}"

    return True, f"Set {key}={value}, persisted to {persist_file}"


def _remediate_package_present(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Install a package via dnf."""
    name = r["name"]

    if dry_run:
        return True, f"Would install {name}"

    result = ssh.run(f"dnf install -y {shlex.quote(name)}", timeout=300)
    if not result.ok:
        return False, f"dnf install failed: {result.stderr}"
    return True, f"Installed {name}"


def _remediate_kernel_module_disable(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Blacklist a kernel module."""
    name = r["name"]
    conf_path = f"/etc/modprobe.d/{name}.conf"

    if dry_run:
        return True, f"Would blacklist {name} in {conf_path}"

    content = f"blacklist {name}\ninstall {name} /bin/false\n"
    result = ssh.run(f"printf %s {shlex.quote(content)} > {shlex.quote(conf_path)}")
    if not result.ok:
        return False, f"Failed to write {conf_path}: {result.stderr}"

    # Unload if currently loaded
    ssh.run(f"modprobe -r {shlex.quote(name)} 2>/dev/null")
    return True, f"Blacklisted {name}"


def _remediate_manual(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Manual remediation — no automated action."""
    note = r.get("note", "Manual remediation required")
    return False, f"MANUAL: {note}"


def _reload_service(ssh: SSHSession, r: dict) -> None:
    """Reload or restart a service if specified in the remediation."""
    if "reload" in r:
        ssh.run(f"systemctl reload {shlex.quote(r['reload'])} 2>/dev/null || systemctl restart {shlex.quote(r['reload'])} 2>/dev/null")
    elif "restart" in r:
        ssh.run(f"systemctl restart {shlex.quote(r['restart'])} 2>/dev/null")


REMEDIATION_HANDLERS = {
    "config_set": _remediate_config_set,
    "config_set_dropin": _remediate_config_set_dropin,
    "command_exec": _remediate_command_exec,
    "file_permissions": _remediate_file_permissions,
    "sysctl_set": _remediate_sysctl_set,
    "package_present": _remediate_package_present,
    "kernel_module_disable": _remediate_kernel_module_disable,
    "manual": _remediate_manual,
}


# ── Top-level evaluation ───────────────────────────────────────────────────


def evaluate_rule(
    ssh: SSHSession, rule: dict, capabilities: dict[str, bool]
) -> RuleResult:
    """Evaluate a single rule: select implementation and run its check."""
    rule_id = rule["id"]
    title = rule.get("title", rule_id)
    severity = rule.get("severity", "unknown")

    impl = select_implementation(rule, capabilities)
    if impl is None:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            skipped=True,
            skip_reason="No matching implementation",
        )

    check = impl.get("check")
    if check is None:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            skipped=True,
            skip_reason="Implementation has no check",
        )

    try:
        cr = run_check(ssh, check)
    except Exception as exc:
        return RuleResult(
            rule_id=rule_id,
            title=title,
            severity=severity,
            passed=False,
            detail=f"Error: {exc}",
        )

    return RuleResult(
        rule_id=rule_id,
        title=title,
        severity=severity,
        passed=cr.passed,
        detail=cr.detail,
    )


def remediate_rule(
    ssh: SSHSession, rule: dict, capabilities: dict[str, bool], *, dry_run: bool = False
) -> RuleResult:
    """Check a rule, remediate if failing, then re-check."""
    # Initial check
    result = evaluate_rule(ssh, rule, capabilities)
    if result.passed or result.skipped:
        return result

    impl = select_implementation(rule, capabilities)
    remediation = impl.get("remediation") if impl else None
    if remediation is None:
        result.remediation_detail = "No remediation defined"
        return result

    try:
        ok, detail = run_remediation(ssh, remediation, dry_run=dry_run)
    except Exception as exc:
        result.remediation_detail = f"Error: {exc}"
        return result

    result.remediated = True
    result.remediation_detail = detail

    if not ok:
        return result

    if dry_run:
        result.remediation_detail = detail
        return result

    # Re-check after remediation
    check = impl.get("check")
    if check:
        try:
            cr = run_check(ssh, check)
            result.passed = cr.passed
            result.detail = cr.detail
        except Exception as exc:
            result.detail = f"Re-check error: {exc}"

    return result
