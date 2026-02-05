# Code Patterns

Concrete templates for the most common development tasks in Aegis. Copy, adapt, register.

## Adding a Check Handler

Check handlers live in `runner/_checks.py`. Each takes an `SSHSession` and a check dict (from the rule YAML), returns a `CheckResult`.

### Template

```python
def _check_service_state(ssh: SSHSession, c: dict) -> CheckResult:
    """Check systemd service state."""
    name = c["name"]

    # Use shlex.quote on values from rule YAML
    result = ssh.run(f"systemctl is-enabled {shlex.quote(name)} 2>/dev/null")
    actual_enabled = result.stdout.strip()

    expected_enabled = c.get("enabled")
    if expected_enabled is not None:
        expected = "enabled" if expected_enabled else "not-enabled"
        if (expected_enabled and actual_enabled != "enabled") or \
           (not expected_enabled and actual_enabled == "enabled"):
            return CheckResult(passed=False, detail=f"{name}: {actual_enabled} (expected {expected})")

    return CheckResult(passed=True, detail=f"{name}: {actual_enabled}")
```

### Registration

Add to the `CHECK_HANDLERS` dict at the bottom of the check handlers section:

```python
CHECK_HANDLERS = {
    # ... existing handlers ...
    "service_state": _check_service_state,
}
```

### Conventions

- Function name: `_check_<method_name>` where method_name matches the YAML `method:` value
- Always `shlex.quote()` values from rule YAML before shell interpolation
- Exception: glob paths — check for `"glob" in c or any(ch in path for ch in "*?[")`
- Return `CheckResult(passed=True/False, detail="human-readable explanation")`
- Detail on failure should show actual vs expected
- Never raise exceptions for expected conditions — return a failing CheckResult
- Keep commands simple: one concept per `ssh.run()` call when possible


## Adding a Remediation Handler

Remediation handlers live in `runner/_remediation.py`. They take an `SSHSession`, a remediation dict, and a `dry_run` flag. Return `(success: bool, detail: str)`.

### Template

```python
def _remediate_service_enabled(
    ssh: SSHSession, r: dict, *, dry_run: bool = False
) -> tuple[bool, str]:
    """Enable and start a systemd service."""
    name = r["name"]

    if dry_run:
        return True, f"Would enable and start {name}"

    result = ssh.run(f"systemctl enable --now {shlex.quote(name)}")
    if not result.ok:
        return False, f"Failed to enable {name}: {result.stderr}"

    # Call _reload_service for mechanisms that support reload/restart fields
    _reload_service(ssh, r)
    return True, f"Enabled and started {name}"
```

### Registration

```python
REMEDIATION_HANDLERS = {
    # ... existing handlers ...
    "service_enabled": _remediate_service_enabled,
}
```

### Conventions

- Function name: `_remediate_<mechanism_name>`
- Check `dry_run` early — return a description of what would happen
- Return `(True, detail)` on success, `(False, detail)` on failure
- Call `_reload_service(ssh, r)` if the mechanism type supports `reload:` / `restart:` fields
- For multi-step operations, check idempotency guards (`unless`, `onlyif`) before acting
- Use `timeout=300` for slow operations (package installs)


## Adding a Capability Probe

Probes live in `runner/detect.py` as entries in the `CAPABILITY_PROBES` dict.

### Template

```python
CAPABILITY_PROBES: dict[str, str] = {
    # ... existing probes ...

    # New probe: check if chrony is the active NTP implementation
    "chrony": "systemctl is-active chronyd >/dev/null 2>&1",
}
```

### Conventions

- Value is a single shell command (or `&&`/`||` chain)
- Exit code 0 = capability present, non-zero = absent
- Suppress stderr with `2>/dev/null` to keep probe output clean
- Probes must be **fast** (< 2 seconds) and **side-effect free**
- Probes run on every host before any rules — keep the total count reasonable
- Name should match what rule `when:` gates reference


## Adding a Rule

### File Location

`rules/<category>/<id>.yml` — category must match one of: access-control, audit, filesystem, kernel, logging, network, services, system.

### Minimal Rule (Single Implementation)

```yaml
id: sysctl-net-ipv4-tcp-syncookies
title: Enable TCP SYN cookies
description: >
  TCP SYN cookies must be enabled to protect against SYN flood attacks
  when the SYN backlog queue fills up.
rationale: >
  Without SYN cookies, an attacker can exhaust server resources by
  sending a flood of SYN packets without completing the handshake.
severity: medium
category: kernel
tags: [sysctl, networking, dos-protection]

references:
  cis:
    rhel9_v2: { section: "3.3.8", level: "L1", type: "Automated" }
  nist_800_53: ["SC-5"]

platforms:
  - family: rhel
    min_version: 8

implementations:
  - default: true
    check:
      method: sysctl_value
      key: "net.ipv4.tcp_syncookies"
      expected: "1"
    remediation:
      mechanism: sysctl_set
      key: "net.ipv4.tcp_syncookies"
      value: "1"
```

### Capability-Gated Rule (Two Implementations)

```yaml
implementations:
  - when: sshd_config_d                    # Gate: use if capability detected
    check:
      method: config_value
      path: "/etc/ssh/sshd_config.d"
      key: "SomeKey"
      expected: "some_value"
      scan_pattern: "*.conf"
    remediation:
      mechanism: config_set_dropin
      dir: "/etc/ssh/sshd_config.d"
      file: "00-aegis-some-key.conf"
      key: "SomeKey"
      value: "some_value"
      reload: "sshd"

  - default: true                           # Fallback: always matches
    check:
      method: config_value
      path: "/etc/ssh/sshd_config"
      key: "SomeKey"
      expected: "some_value"
    remediation:
      mechanism: config_set
      path: "/etc/ssh/sshd_config"
      key: "SomeKey"
      value: "some_value"
      separator: " "
      reload: "sshd"
```

### Multi-Condition Check + Multi-Step Remediation

```yaml
implementations:
  - default: true
    check:
      checks:                               # AND semantics — all must pass
        - method: package_state
          name: "aide"
          state: "present"
        - method: file_exists
          path: "/var/lib/aide/aide.db.gz"
    remediation:
      steps:                                # Sequential execution
        - mechanism: package_present
          name: "aide"
        - mechanism: command_exec
          run: "aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
          unless: "test -f /var/lib/aide/aide.db.gz"
```

### Validation

```bash
python3 schema/validate.py rules/<category>/<id>.yml
```

Checks JSON Schema compliance plus business rules (id/filename match, category/directory match, exactly one default implementation).


## Pattern: Handling Glob Paths

Some rules reference multiple files via shell globs (e.g., `/etc/ssh/ssh_host_*_key`). These paths must NOT be quoted with `shlex.quote()` or the glob won't expand.

### Detection

```python
is_glob = "glob" in c or any(ch in path for ch in "*?[")
quoted = path if is_glob else shlex.quote(path)
```

### In Check Handlers

When stat-ing glob paths, use `%n` to get the filename and iterate results:

```python
result = ssh.run(f"stat -c '%U %G %a %n' {path} 2>/dev/null")  # unquoted
for line in result.stdout.strip().splitlines():
    parts = line.split()
    owner, group, mode, filepath = parts[0], parts[1], parts[2], " ".join(parts[3:])
    # ... validate each file
```


## Pattern: When Gate Evaluation

The `when:` field in implementations supports three forms:

```yaml
when: sshd_config_d                     # String: single capability
when: { all: [authselect, pam_faillock] } # All must be true
when: { any: [grub_bls, grub_legacy] }   # At least one true
```

The `evaluate_when()` function in `runner/_selection.py` handles all three. When adding a new capability, just add the probe — no changes needed to the gate evaluator.


## Adding a Capture Handler

Capture handlers live in `runner/_capture.py`. Each takes an `SSHSession` and a remediation dict, returns a `PreState`. They run **read-only** SSH commands to snapshot the host's current state before a remediation step modifies it.

### Template

```python
def _capture_service_enabled(ssh: SSHSession, r: dict) -> PreState:
    """Capture current service enable/active state."""
    name = r["name"]
    enabled = ssh.run(f"systemctl is-enabled {shlex.quote(name)} 2>/dev/null")
    active = ssh.run(f"systemctl is-active {shlex.quote(name)} 2>/dev/null")
    return PreState(
        mechanism="service_enabled",
        data={
            "name": name,
            "was_enabled": enabled.stdout.strip() if enabled.ok else None,
            "was_active": active.stdout.strip() if active.ok else None,
        },
    )
```

### Registration

```python
CAPTURE_HANDLERS = {
    # ... existing handlers ...
    "service_enabled": _capture_service_enabled,
}
```

### Conventions

- Function name: `_capture_<mechanism_name>` — matches the remediation mechanism
- **Read-only**: capture handlers must never modify host state
- Return `PreState(mechanism=..., data={...})` with enough info to rollback
- Store `reload`/`restart` keys from the remediation dict in `data` so rollback can call `_reload_service`
- Set `capturable=False` for mechanisms where pre-state cannot be meaningfully captured (e.g., `command_exec`, `manual`)
- Keep commands fast — capture runs before every remediation step


## Adding a Rollback Handler

Rollback handlers live in `runner/_rollback.py`. Each takes an `SSHSession` and a `PreState`, returns `(success: bool, detail: str)`. They restore the host to the state captured before remediation.

### Template

```python
def _rollback_service_enabled(ssh: SSHSession, pre_state: PreState) -> tuple[bool, str]:
    """Restore service to its previous enable/active state."""
    d = pre_state.data
    name = d["name"]
    if d["was_enabled"] and d["was_enabled"] != "enabled":
        ssh.run(f"systemctl disable {shlex.quote(name)}")
    if d["was_active"] and d["was_active"] != "active":
        ssh.run(f"systemctl stop {shlex.quote(name)}")
    return True, f"Restored {name} to previous state"
```

### Registration

```python
ROLLBACK_HANDLERS = {
    # ... existing handlers ...
    "service_enabled": _rollback_service_enabled,
}
```

### Conventions

- Function name: `_rollback_<mechanism_name>` — matches the capture/remediation mechanism
- Read `PreState.data` to determine what to restore
- Return `(False, "reason")` for mechanisms that cannot be rolled back (e.g., `command_exec`)
- Call `_reload_service(ssh, {"reload": d.get("reload"), "restart": d.get("restart")})` after restoring config files
- Rollback handlers are called in **reverse order** by `_execute_rollback` — only successful, capturable steps are rolled back
