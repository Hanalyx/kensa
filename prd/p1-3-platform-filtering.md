# P1-3: Platform Version Filtering

## Status: Not Started

## Problem
Rules declare platform applicability with `min_version` / `max_version`:
```yaml
platforms:
  - family: rhel
    min_version: 9
    max_version: 10
```

V0 ignores these fields — all rules run on all hosts. A RHEL 8 host will attempt rules that only apply to RHEL 9+, potentially producing false failures.

## Solution
Detect the remote host's OS family and version during capability probing, then filter rules before execution.

## Technical Approach

### OS Detection
Add a version detection step in `detect.py` (not a capability probe, but a separate function):

```python
def detect_platform(ssh: SSHSession) -> tuple[str, int]:
    """Detect OS family and major version. Returns (family, version)."""
    result = ssh.run("cat /etc/os-release")
    # Parse ID (rhel, centos, rocky, almalinux) and VERSION_ID (9.3 → 9)
    ...
    # Map derivatives to rhel if needed
    return "rhel", 9
```

### Rule Filtering
In `engine.py`, add platform check before evaluating a rule:

```python
def rule_applies_to_platform(rule: dict, family: str, version: int) -> bool:
    for p in rule.get("platforms", []):
        if p["family"] != family:
            continue
        min_v = p.get("min_version", 0)
        max_v = p.get("max_version", 99)
        if min_v <= version <= max_v:
            return True
        # Check derivatives flag
        if p.get("derivatives", True) and family in RHEL_DERIVATIVES:
            return True
    return False
```

### Derivative Mapping
```python
RHEL_DERIVATIVES = {"centos", "rocky", "almalinux", "ol"}  # Oracle Linux
```

If `derivatives: true` (the default), rules with `family: rhel` also match these.

### CLI Integration
- Platform detection runs once per host after SSH connection
- Skipped rules show `SKIP  rule-id  (requires RHEL 9+)` with `--verbose`
- No new CLI flags needed — filtering is automatic

## Acceptance Criteria
- [ ] Correctly detects RHEL 8, 9, 10 from `/etc/os-release`
- [ ] Correctly detects derivatives (Rocky, Alma, CentOS Stream, Oracle Linux)
- [ ] `min_version: 9` rule skipped on RHEL 8 host
- [ ] `max_version: 9` rule skipped on RHEL 10 host
- [ ] `derivatives: true` (default) allows Rocky Linux to match `family: rhel` rules
- [ ] `derivatives: false` only matches exact family
- [ ] Skipped rules don't count as failures
- [ ] Platform info shown in verbose output
- [ ] Graceful fallback if `/etc/os-release` can't be read (run all rules with a warning)
