# P1-4: Capability Manual Overrides

## Status: Not Started

## Problem

Capability detection runs automatically and determines which implementation path each rule uses. In rare cases, detection can be wrong or operators need to force a specific path:

1. **False positive**: Detection says `sshd_config_d` is present, but the Include directive was removed — drop-in files won't work.

2. **False negative**: Detection fails because a service is temporarily stopped, but the capability is actually available.

3. **Testing**: Operator wants to verify the fallback implementation works on a system that has the preferred capability.

4. **Staged rollout**: Operator wants to use the conservative (default) implementation even though the system supports the newer mechanism.

The Technical Remediation Master Plan (Section 5, Risks) notes: "Allow manual capability overrides" as a mitigation for detection inaccuracy.

## Solution

Add `--capability` / `-C` flag to override detected capabilities.

```bash
# Force sshd_config_d to false (use main config file even if .d exists)
./aegis check --host 192.168.1.211 --capability sshd_config_d=false

# Force authselect to true (assume it's available even if detection failed)
./aegis remediate --host 192.168.1.211 -C authselect=true

# Multiple overrides
./aegis check --host 192.168.1.211 \
  -C sshd_config_d=false \
  -C crypto_policy_modules=false
```

## CLI Specification

```
--capability, -C KEY=VALUE    Override detected capability (can be repeated)
                              VALUE is true/false (case-insensitive)
```

### Verbose Output

When `--verbose` is set, show overrides clearly:

```
Capabilities for 192.168.1.211:
  rhel9             = true
  sshd_config_d     = false  ← OVERRIDE (detected: true)
  authselect        = true
  crypto_policies   = true
  ...
```

### Validation

- Unknown capability names: **warning** (might be future capability, don't hard-fail)
- Invalid value (not true/false): **error**
- Override to same value as detected: **no-op**, no warning

## Technical Approach

### In `cli.py`

```python
@click.option(
    "--capability", "-C",
    multiple=True,
    metavar="KEY=VALUE",
    help="Override detected capability (e.g., -C sshd_config_d=false)",
)
def check(capability, ...):
    ...
    # Parse overrides
    overrides = parse_capability_overrides(capability)

    # Detect capabilities
    caps = detect_capabilities(ssh)

    # Apply overrides
    caps = apply_overrides(caps, overrides, verbose=verbose)
```

### Helper Functions

```python
def parse_capability_overrides(flags: tuple[str, ...]) -> dict[str, bool]:
    """Parse -C key=value flags into a dict."""
    overrides = {}
    for flag in flags:
        if "=" not in flag:
            raise click.BadParameter(f"Invalid format: {flag} (expected KEY=VALUE)")
        key, value = flag.split("=", 1)
        if value.lower() == "true":
            overrides[key] = True
        elif value.lower() == "false":
            overrides[key] = False
        else:
            raise click.BadParameter(f"Invalid value: {value} (expected true/false)")
    return overrides


def apply_overrides(
    detected: dict[str, bool],
    overrides: dict[str, bool],
    verbose: bool = False,
) -> dict[str, bool]:
    """Apply manual overrides to detected capabilities."""
    result = detected.copy()

    for key, value in overrides.items():
        if key not in detected:
            # Unknown capability — warn but allow
            console.print(f"[yellow]Warning: Unknown capability '{key}'[/]")

        if detected.get(key) != value:
            if verbose:
                console.print(f"  {key} = {value}  ← OVERRIDE (detected: {detected.get(key)})")

        result[key] = value

    return result
```

## Use Cases

### 1. Force Fallback Implementation

```bash
# System has sshd_config.d, but I want to test the main config path
./aegis remediate --host 192.168.1.211 \
  --rule rules/access-control/ssh-disable-root-login.yml \
  -C sshd_config_d=false \
  --dry-run

Would set 'PermitRootLogin no' in /etc/ssh/sshd_config  # Uses default impl
```

### 2. Work Around Detection Bug

```bash
# authselect detection failed because sssd was restarting
./aegis remediate --host 192.168.1.211 \
  --rule rules/access-control/pam-faillock.yml \
  -C authselect=true
```

### 3. Inventory-Wide Override

For inventory-based runs, capability overrides apply to all hosts:

```bash
./aegis check --inventory hosts.ini -C crypto_policy_modules=false
```

Future enhancement: per-host overrides via inventory variables.

## Acceptance Criteria

- [ ] `-C key=true` and `-C key=false` override detection
- [ ] Multiple `-C` flags can be combined
- [ ] `--verbose` shows "OVERRIDE" annotation
- [ ] Unknown capability names produce warning (not error)
- [ ] Invalid values (not true/false) produce error
- [ ] Overrides affect implementation selection
- [ ] Overrides work with `detect`, `check`, and `remediate` subcommands

## Future Extensions

- **Inventory variables**: `ansible_host_vars` style capability overrides per host
- **Capability profiles**: `--capability-profile minimal` to force all optional capabilities off
- **Persist overrides**: `~/.aegis/capability-overrides.yaml` for site-wide defaults
