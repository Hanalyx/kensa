# P2-4: Semantic Conflict Detection

## Status: Not Started

## Problem

Two rules in the same run can set contradictory values for the same configuration key. For example:

- Rule A: Set `MaxAuthTries 4` in sshd_config
- Rule B: Set `MaxAuthTries 3` in sshd_config

The current engine runs both without warning. The last one wins, but the result depends on filesystem sort order — silent, non-deterministic behavior.

This is distinct from `P2: Dependency Ordering` which handles explicit `conflicts_with` declarations. This feature detects **implicit semantic conflicts** where two rules target the same resource with different values.

## Solution

Add a conflict detection pass in the RESOLVE phase (after implementation selection, before execution) that identifies when multiple rules would modify the same resource to different states.

### Conflict Types

| Type | Example | Detection |
|------|---------|-----------|
| **Config key conflict** | Two rules set same key in same file to different values | Same `path` + `key`, different `value` |
| **Sysctl conflict** | Two rules set same sysctl to different values | Same `key`, different `value` |
| **File permission conflict** | Two rules set different modes on same file | Same `path`, different `mode`/`owner`/`group` |
| **Service state conflict** | One rule enables, another disables same service | Same service, opposite `state` |
| **Package conflict** | One rule installs, another removes same package | Same package, opposite `state` |

### Non-Conflicts (Idempotent Operations)

These are NOT conflicts — they're redundant but safe:
- Two rules set the same key to the same value
- Two rules both ensure a package is present
- Two rules both blacklist the same kernel module

## CLI Behavior

### Default: Error on Conflict

```bash
./aegis check --rules rules/

ERROR: Conflicting rules detected

  ssh-max-auth-tries vs ssh-max-auth-tries-strict
    Both modify: /etc/ssh/sshd_config :: MaxAuthTries
    Rule 1 sets: 4
    Rule 2 sets: 3

  Resolve by:
    - Remove one rule from the run (--exclude ssh-max-auth-tries-strict)
    - Use --allow-conflicts to run anyway (last rule wins)

Aborting. No changes made.
```

### Override: `--allow-conflicts`

```bash
./aegis remediate --rules rules/ --allow-conflicts

WARNING: Conflicting rules detected (running anyway due to --allow-conflicts)
  ssh-max-auth-tries vs ssh-max-auth-tries-strict → last wins

[... proceeds with remediation ...]
```

### Dry-Run Shows Conflicts

```bash
./aegis remediate --rules rules/ --dry-run

Execution Plan:
  1. ssh-max-auth-tries: Would set MaxAuthTries=4 in /etc/ssh/sshd_config
  2. ssh-max-auth-tries-strict: Would set MaxAuthTries=3 in /etc/ssh/sshd_config
     ⚠ CONFLICT with step 1 (same key, different value)
```

## Technical Approach

### Conflict Key Extraction

Each remediation step produces a "conflict key" — a tuple identifying the resource it modifies:

```python
def get_conflict_key(step: dict) -> tuple | None:
    """Extract the resource identifier for conflict detection."""
    mech = step.get("mechanism", "")

    if mech == "config_set":
        return ("config", step["path"], step["key"])

    if mech == "config_set_dropin":
        return ("config", f"{step['dir']}/{step['file']}", step["key"])

    if mech == "sysctl_set":
        return ("sysctl", step["key"])

    if mech == "file_permissions":
        return ("file_perm", step["path"])

    if mech in ("service_enabled", "service_disabled", "service_masked"):
        return ("service", step["name"])

    if mech in ("package_present", "package_absent"):
        return ("package", step["name"])

    if mech == "kernel_module_disable":
        return ("kmod", step["name"])

    # command_exec, manual: no conflict detection possible
    return None
```

### Conflict Check Phase

```python
def detect_conflicts(
    rules: list[dict],
    capabilities: dict[str, bool],
) -> list[Conflict]:
    """Detect semantic conflicts before execution."""
    resource_map: dict[tuple, list[tuple[str, dict, Any]]] = {}

    for rule in rules:
        impl = select_implementation(rule, capabilities)
        if impl is None:
            continue

        rem = impl.get("remediation")
        if rem is None:
            continue

        steps = rem.get("steps", [rem])
        for step in steps:
            key = get_conflict_key(step)
            if key is None:
                continue
            value = extract_value(step)  # The value being set
            resource_map.setdefault(key, []).append((rule["id"], step, value))

    conflicts = []
    for key, entries in resource_map.items():
        if len(entries) > 1:
            values = {v for _, _, v in entries}
            if len(values) > 1:  # Different values = conflict
                conflicts.append(Conflict(key, entries))

    return conflicts
```

### Integration Point

In `cli.py`, after loading rules and before execution:

```python
rules = load_rules(path, severity=severity, ...)
conflicts = detect_conflicts(rules, capabilities)

if conflicts and not allow_conflicts:
    render_conflicts(conflicts)
    raise SystemExit(1)
elif conflicts:
    console.print("[yellow]WARNING: Conflicts detected, proceeding anyway[/]")
```

## Acceptance Criteria

- [ ] Config key conflicts detected (same file + key, different value)
- [ ] Sysctl conflicts detected
- [ ] Service state conflicts detected (enable vs disable)
- [ ] Package state conflicts detected (present vs absent)
- [ ] File permission conflicts detected (same path, different mode/owner)
- [ ] Redundant operations (same value) are NOT flagged as conflicts
- [ ] `--allow-conflicts` proceeds with warning
- [ ] `--dry-run` shows conflicts inline with execution plan
- [ ] Error message shows exactly which rules conflict and how
- [ ] Exit code is non-zero when conflicts block execution

## Edge Cases

- **Multi-step remediations**: Each step is checked independently
- **Drop-in files**: `sshd_config.d/00-foo.conf` and `sshd_config.d/99-bar.conf` setting same key — technically not a conflict (both files exist), but worth a warning since order matters
- **Glob paths**: `file_permissions` on `/etc/ssh/*` and `/etc/ssh/sshd_config` — detect overlap
