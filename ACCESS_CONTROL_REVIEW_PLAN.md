# Access-Control Rule Review — Findings & Fix Plan

**Scope:** All 122 rules in `rules/access-control/`
**Date:** 2026-02-17
**Guide:** RULE_REVIEW_GUIDE_V0.md

---

## Executive Summary

Reviewed 122 access-control rules against the 5-dimension criteria in
RULE_REVIEW_GUIDE_V0.md. Found **78 findings** across 60+ rules, organized
into 8 fix categories. The most critical findings are:

1. **17 rules use `command:` instead of `run:`** — These will cause a runtime
   KeyError because the command handler reads `c["run"]` (line 35 of
   `runner/handlers/checks/_command.py`). This is also systemic: 39 rules
   total across all categories have this defect.

2. **26 SSH rules use static `config_value`** instead of `sshd_effective_config`,
   meaning they check the config file but not the running SSH daemon's
   resolved configuration.

3. **8 duplicate rule pairs** — same CIS control implemented by two different
   rules with different IDs.

---

## Table of Contents

1. [FIX-01: Runtime-Breaking Field Names (CRITICAL)](#fix-01)
2. [FIX-02: SSH Static vs Effective Config (HIGH)](#fix-02)
3. [FIX-03: Duplicate Rule Consolidation (HIGH)](#fix-03)
4. [FIX-04: Manual Remediation Field Name (MEDIUM)](#fix-04)
5. [FIX-05: Logic Bugs (HIGH)](#fix-05)
6. [FIX-06: Missing Framework References (LOW)](#fix-06)
7. [FIX-07: Missing Capability Gating & Dependencies (MEDIUM)](#fix-07)
8. [FIX-08: Remediation Quality Issues (MEDIUM)](#fix-08)

---

## FIX-01: Runtime-Breaking Field Names (CRITICAL) {#fix-01}

### Problem

The command check handler at `runner/handlers/checks/_command.py:35` reads:
```python
cmd = c["run"]            # line 35
expected_exit = c.get("expected_exit", 0)  # line 39
```

Rules using `command:` instead of `run:` will fail with **KeyError at runtime**.
Rules using `expected_exit_code:` instead of `expected_exit:` will silently
use the default value of 0, which happens to be correct for all current rules
but is semantically wrong.

### Affected Rules (17 in access-control, 39 total across all categories)

#### Access-control rules using `command:` instead of `run:`:

| Rule File | Line | Also uses `expected_exit_code:`? |
|-----------|------|----------------------------------|
| `accounts-locked-no-shell.yml` | 26 | Yes (line 47) |
| `authselect-profile-pam.yml` | 29 | Yes (line 41) |
| `nologin-not-in-shells.yml` | 26 | Yes (line 34) |
| `pam-pwhistory-enabled.yml` | 26, 47 | Yes (line 39, 54) |
| `pam-pwhistory-root.yml` | 28 | Yes (line 37) |
| `pam-pwhistory-use-authtok.yml` | 28 | Yes (line 36) |
| `pam-unix-enabled.yml` | 26 | Yes (line 35) |
| `pam-unix-no-nullok.yml` | 26 | Yes (line 34) |
| `pam-unix-no-remember.yml` | 26 | Yes (line 33) |
| `pam-unix-use-authtok.yml` | 26 | Yes (line 34) |
| `password-change-past.yml` | 26 | Yes (line 48) |
| `password-hashing-algorithm.yml` | 26 | Yes (line 42) |
| `root-access-controlled.yml` | 26 | Yes (line 40) |
| `root-group-only-gid0.yml` | 26 | Yes (line 35) |
| `root-only-gid0.yml` | 26 | Yes (line 35) |
| `root-umask.yml` | 26 | Yes (line 40) |
| `sudo-reauth-not-disabled.yml` | 26 | Yes (line 40) |
| `sudo-require-password.yml` | 27 | Yes (line 35) |

#### Rules using ONLY `expected_exit_code:` (with correct `run:`):

None in access-control — all rules with `expected_exit_code:` also use `command:`.

#### Rules in OTHER categories (note for future review):

| Category | Count | Files |
|----------|-------|-------|
| system | 3 | crypto-policy-strong-macs, issue-net-configured, motd-configured |
| services | 10 | gdm-screen-lock-idle, gdm-screen-lock-override, gdm-xdmcp-disabled, gdm-automount-disabled, gdm-automount-override, gdm-autorun-never-override, gdm-autorun-never, gdm-disable-user-list, gdm-login-banner |
| logging | 3 | journald-to-rsyslog, logfiles-access-configured, single-logging-system |
| network | 4 | firewall-single-utility, nftables-base-chains, nftables-default-deny, nftables-loopback |
| audit | 2 | auditd-space-low-warning, auditd-tools-integrity |

### Fix

For each affected rule, rename the check field:
- `command:` -> `run:`
- `expected_exit_code:` -> `expected_exit:`

This is a mechanical find-and-replace within the check block of each rule.
The multiline script content stays identical.

### Verification

```bash
# No rules should use command: for checks after fix
grep -rn '^\s\+command: [|>]' rules/access-control/ | wc -l  # expect 0

# No rules should use expected_exit_code after fix
grep -rn 'expected_exit_code:' rules/access-control/ | wc -l  # expect 0

# All rules pass schema validation
python schema/validate.py

# Unit tests pass
pytest tests/ -v
```

---

## FIX-02: SSH Static vs Effective Config (HIGH) {#fix-02}

### Problem

26 of 30 SSH rules use `config_value` (reads `/etc/ssh/sshd_config` file) instead
of `sshd_effective_config` (runs `sshd -T` to get the daemon's resolved config).
Only `ssh-disable-root-login` uses the effective method.

Static file checks can give false results when:
- Drop-in files in `/etc/ssh/sshd_config.d/` override the main config
- The `Include` directive pulls in settings from other files
- Match blocks conditionally override settings

### Affected Rules (26)

All `ssh-*.yml` rules EXCEPT:
- `ssh-disable-root-login.yml` (already correct)
- `ssh-config-permissions.yml` (file_permission check, not applicable)
- `ssh-public-key-permissions.yml` (file_permission check)
- `ssh-private-key-permissions.yml` (file_permission check)

Specific rules:
```
ssh-banner.yml              ssh-client-alive-count-max.yml
ssh-client-alive-interval.yml  ssh-disable-gssapi-auth.yml
ssh-disable-host-auth.yml   ssh-disable-rhosts.yml
ssh-disable-tcp-forwarding.yml ssh-disable-x11-forwarding.yml
ssh-hostbased-auth.yml      ssh-ignore-rhosts.yml
ssh-kex-fips.yml            ssh-log-level.yml
ssh-login-grace-time.yml    ssh-macs-fips.yml
ssh-max-auth-tries.yml      ssh-max-sessions.yml
ssh-max-startups.yml        ssh-ciphers-fips.yml
ssh-pam-enabled.yml         ssh-permit-empty-passwords.yml
ssh-permit-user-environment.yml  ssh-pubkey-auth.yml
ssh-strict-modes.yml        ssh-use-strong-ciphers.yml
ssh-use-strong-kex.yml      ssh-use-strong-macs.yml
```

### Fix

For each rule, change:
```yaml
# Before
check:
  method: config_value
  path: "/etc/ssh/sshd_config"
  key: "PermitEmptyPasswords"
  expected: "no"

# After
check:
  method: sshd_effective_config
  key: "permitemptypasswords"    # sshd -T uses lowercase
  expected: "no"
```

Key differences:
- `method:` changes from `config_value` to `sshd_effective_config`
- Remove `path:` (sshd -T reads all config sources)
- `key:` must be **lowercase** (sshd -T normalizes to lowercase)
- `expected:` value stays the same
- Keep `separator:` only if the handler uses it (check handler code)

### Verification

```bash
# Verify sshd_effective_config handler exists and handles the expected fields
grep -n 'sshd_effective_config' runner/handlers/checks/__init__.py

# Run targeted tests
pytest tests/ -k ssh -v

# Integration: test against a host
./aegis check --inventory inventory.ini --sudo --limit <host> --rule rules/access-control/ssh-permit-empty-passwords.yml
```

---

## FIX-03: Duplicate Rule Consolidation (HIGH) {#fix-03}

### Problem

8 pairs of rules implement the same CIS control with different rule IDs.
This causes double-counting in coverage reports and confusing results.

### Duplicate Pairs

#### Pair 1: pam-faillock-even-deny-root / pam-faillock-root

| | pam-faillock-even-deny-root | pam-faillock-root |
|-|---------------------------|-------------------|
| CIS | (none) | 5.3.3.1.3 |
| STIG | V-257816 / RHEL-09-411085 | (none) |
| Check | config_value: even_deny_root | command: grep even_deny_root |
| Severity | high | medium |

**Action:** Consolidate into `pam-faillock-even-deny-root`. Add CIS reference
from `pam-faillock-root`. Keep STIG reference. Keep `depends_on: [pam-faillock-deny]`.
Delete `pam-faillock-root.yml`.

#### Pair 2: pam-pwquality-dictcheck / pwquality-dictcheck

| | pam-pwquality-dictcheck | pwquality-dictcheck |
|-|------------------------|---------------------|
| CIS RHEL8 | 5.4.1.10 | (none) |
| CIS RHEL9 | 5.4.1 | 5.3.3.2.6 |
| Check | config_value: dictcheck=1 | config_value: dictcheck=1 |

**Action:** Keep `pam-pwquality-dictcheck` (has both RHEL8 and RHEL9 CIS + STIG).
Update CIS RHEL9 section if needed. Delete `pwquality-dictcheck.yml`.

#### Pair 3: pam-latest-version / package-pam-installed

| | pam-latest-version | package-pam-installed |
|-|-------------------|----------------------|
| CIS | 5.3.1.1 | 5.3.1.1 |
| Check | command: rpm -q pam | package_state: pam |
| Platform | RHEL 8+ | RHEL 9+ |

**Action:** Keep `package-pam-installed` (uses typed handler). Expand
`min_version` to 8. Add references from `pam-latest-version`.
Delete `pam-latest-version.yml`.

#### Pair 4: authselect-latest-version / package-authselect-installed

Same pattern as Pair 3.
**Action:** Keep `package-authselect-installed`. Expand to RHEL 8+.
Delete `authselect-latest-version.yml`.

#### Pair 5: libpwquality-latest-version / package-libpwquality-installed

Same pattern as Pair 3.
**Action:** Keep `package-libpwquality-installed`. Expand to RHEL 8+.
Delete `libpwquality-latest-version.yml`.

#### Pair 6: accounts-no-empty-passwords / no-empty-passwords

| | accounts-no-empty-passwords | no-empty-passwords |
|-|---------------------------|-------------------|
| CIS | 7.2.2 | 7.2.2 |
| Severity | critical | high |
| Check | command: awk prints violators | command: awk exit code |

**Action:** Keep `accounts-no-empty-passwords` (critical severity is correct,
better check output). Delete `no-empty-passwords.yml`.

#### Pair 7: login-defs-pass-max-days / password-max-age

| | login-defs-pass-max-days | password-max-age |
|-|------------------------|-----------------|
| CIS RHEL8 | 5.6.1.1 | (none) |
| CIS RHEL9 | 5.6.1.1 | 5.4.1.1 (wrong) |
| STIG | V-258052 | (none) |

**Action:** Keep `login-defs-pass-max-days` (correct CIS sections, STIG).
Delete `password-max-age.yml`.

#### Pair 8: root-gid / default-group-root

| | root-gid | default-group-root |
|-|---------|-------------------|
| CIS | 5.6.6 (RHEL8+9) | 5.6.6 (RHEL8+9) |
| STIG | V-258090 | (none) |
| Check | awk on /etc/passwd | grep/cut on /etc/passwd |

**Action:** Keep `root-gid` (has STIG, cleaner awk). Delete `default-group-root.yml`.

### Files to Delete (8)

```
rules/access-control/pam-faillock-root.yml
rules/access-control/pwquality-dictcheck.yml
rules/access-control/pam-latest-version.yml
rules/access-control/authselect-latest-version.yml
rules/access-control/libpwquality-latest-version.yml
rules/access-control/no-empty-passwords.yml
rules/access-control/password-max-age.yml
rules/access-control/default-group-root.yml
```

### Mapping Updates Required

After deleting duplicate rules, update the CIS mapping files to reference
the surviving rule IDs:
- `mappings/cis/rhel9_v2.0.0.yaml` — update any section pointing to deleted rule IDs
- `mappings/cis/rhel8_v4.0.0.yaml` — same
- `mappings/stig/rhel9_v2r7.yaml` — same

### Verification

```bash
# Confirm no orphan references in mappings
python scripts/sync_cis_mappings.py --mapping mappings/cis/rhel9_v2.0.0.yaml
python scripts/sync_cis_mappings.py --mapping mappings/cis/rhel8_v4.0.0.yaml

# Coverage unchanged
./aegis coverage --framework cis-rhel9-v2.0.0
```

---

## FIX-04: Manual Remediation Field Name (MEDIUM) {#fix-04}

### Problem

The canonical schema specifies `note:` for manual remediation text.
16 rules use `description:` instead, which may not be displayed correctly
by the remediation handler.

### Affected Rules (16)

| Rule | Line |
|------|------|
| `accounts-locked-no-shell.yml` | remediation block |
| `accounts-no-uid-zero.yml` | remediation block |
| `authselect-profile-pam.yml` | remediation block |
| `nologin-system-accounts.yml` | remediation block |
| `pam-pwhistory-enabled.yml` | line 57 |
| `pam-pwhistory-root.yml` | remediation block |
| `pam-pwhistory-use-authtok.yml` | remediation block |
| `pam-unix-enabled.yml` | line 38 |
| `pam-unix-use-authtok.yml` | remediation block |
| `password-change-past.yml` | remediation block |
| `root-access-controlled.yml` | remediation block |
| `root-group-only-gid0.yml` | remediation block |
| `root-only-gid0.yml` | remediation block |
| `root-path-integrity.yml` | remediation block |
| `sudo-reauth-not-disabled.yml` | remediation block |
| `sudo-require-password.yml` | remediation block |

### Fix

For each, rename:
```yaml
# Before
remediation:
  mechanism: manual
  description: "Add pam_pwhistory.so to password stack"

# After
remediation:
  mechanism: manual
  note: "Add pam_pwhistory.so to password stack"
```

### Verification

```bash
# No manual remediations should use description: after fix
grep -rn 'mechanism: manual' rules/access-control/ -A1 | grep 'description:' | wc -l  # expect 0

# Schema validation
python schema/validate.py
```

---

## FIX-05: Logic Bugs (HIGH) {#fix-05}

### 5a: root-umask.yml — Incorrect Umask Comparison

**File:** `rules/access-control/root-umask.yml:34`

**Bug:** Uses integer comparison `[ "$umask_val" -lt 027 ]` to determine if
a umask is "less restrictive." This is wrong because:
- Bash `-lt` does **decimal** comparison (027 → 27, 077 → 77)
- Umask restrictiveness requires **per-digit octal** comparison
- Example: umask `070` (decimal 70 > 27) passes, but it means **others
  have full access** — clearly less restrictive than `027`

**Comment is also wrong:** Line 33 says "007 is most restrictive" but
007 only removes permissions from "others." 077 or 177 are more restrictive.

**Fix:** Replace with per-digit octal comparison:
```bash
# Parse each octal digit
u_digit=${umask_val:0:1}
g_digit=${umask_val:1:1}
o_digit=${umask_val:2:1}
# Each digit must be >= the corresponding digit in 027
if [ "$u_digit" -lt 0 ] || [ "$g_digit" -lt 2 ] || [ "$o_digit" -lt 7 ]; then
  echo "FAIL: Root umask ($umask_val) is less restrictive than 027"
  exit 1
fi
```

Also fix the `command:` → `run:` and `expected_exit_code:` → `expected_exit:`
fields (covered in FIX-01).

### 5b: shell-timeout.yml — No Value Validation

**File:** `rules/access-control/shell-timeout.yml:33`

**Bug:** Check only verifies that `TMOUT=<number>` exists somewhere in
`/etc/profile` or `/etc/profile.d/*.sh`. It does NOT validate the value.
`TMOUT=99999` or `TMOUT=0` would pass despite being non-compliant.

CIS requires TMOUT <= 900 seconds.

**Fix:** Add value validation to the check:
```bash
run: |
  tmout_val=$(grep -rhE '^(export\s+)?TMOUT=' /etc/profile /etc/profile.d/*.sh 2>/dev/null | tail -1 | grep -oE '[0-9]+')
  if [ -z "$tmout_val" ]; then
    echo "FAIL: TMOUT not set"
    exit 1
  fi
  if [ "$tmout_val" -gt 900 ] || [ "$tmout_val" -eq 0 ]; then
    echo "FAIL: TMOUT=$tmout_val (must be 1-900)"
    exit 1
  fi
  echo "OK: TMOUT=$tmout_val"
```

### 5c: pam-faillock-enabled.yml — Remediation Swallows Errors

**File:** `rules/access-control/pam-faillock-enabled.yml:27`

**Bug:** Remediation is:
```yaml
run: "authselect enable-feature with-faillock 2>/dev/null || true"
```
The `|| true` means the remediation always reports success, even if
authselect fails (e.g., no profile selected, permissions error).

**Fix:** Remove `|| true`. If authselect is not available, the rule
should use a capability-gated implementation that falls back to manual.

### Verification

```bash
# Test each fixed rule individually against a host
./aegis check --rule rules/access-control/root-umask.yml --inventory inventory.ini --sudo --limit <host>
./aegis check --rule rules/access-control/shell-timeout.yml --inventory inventory.ini --sudo --limit <host>
```

---

## FIX-06: Missing Framework References (LOW) {#fix-06}

### Problem

Many rules are missing CIS RHEL8, STIG, or other framework references
that exist in the mapping files. This is a coverage gap in the rules
themselves (the mapping files may have the correct associations).

### Findings

This is a lower-priority data enrichment task. The missing references
should be populated by cross-referencing with the mapping files:

| Category | Missing Reference Type | Approx. Count |
|----------|----------------------|---------------|
| SSH rules | STIG (various) | ~5 rules |
| SSH FIPS rules | CIS RHEL9 section | 3 rules |
| PAM rules | CIS RHEL8 | ~10 rules |
| Account rules | CIS RHEL8 | ~8 rules |
| Misc rules | STIG, PCI-DSS | ~15 rules |

### Fix

Cross-reference each rule's CIS RHEL9 section with the RHEL8 mapping to
add the parallel RHEL8 reference. Similarly for STIG.

**Note:** This should be done AFTER FIX-03 (duplicate consolidation) to
avoid enriching rules that will be deleted.

### Verification

```bash
python scripts/sync_cis_mappings.py --mapping mappings/cis/rhel9_v2.0.0.yaml -v
python scripts/sync_cis_mappings.py --mapping mappings/cis/rhel8_v4.0.0.yaml -v
```

---

## FIX-07: Missing Capability Gating & Dependencies (MEDIUM) {#fix-07}

### 7a: SSH FIPS Cipher Rules — Missing conflicts_with

**Rules:** `ssh-ciphers-fips.yml`, `ssh-macs-fips.yml`, `ssh-kex-fips.yml`

**Problem:** These rules enforce specific cipher/MAC/KEX lists, which
conflict with `ssh-crypto-policy.yml` (enforces system crypto policy).
Running both produces contradictory findings. Neither declares
`conflicts_with`.

**Fix:** Add to each FIPS rule:
```yaml
conflicts_with: [ssh-crypto-policy]
```
And add to `ssh-crypto-policy.yml`:
```yaml
conflicts_with: [ssh-ciphers-fips, ssh-macs-fips, ssh-kex-fips]
```

### 7b: PAM Rules — Missing authselect Capability Gate

**Rules:** `pam-pwhistory-enabled.yml`, `pam-pwhistory-root.yml`,
`pam-pwhistory-use-authtok.yml`, `pam-unix-enabled.yml`, `pam-unix-no-nullok.yml`,
`pam-unix-no-remember.yml`, `pam-unix-use-authtok.yml`,
`password-hashing-algorithm.yml`

**Problem:** These rules have a single `default: true` implementation that
uses shell scripts checking PAM files directly. On systems managed by
authselect, the checks should use `authselect current` and the remediation
should use `authselect enable-feature`. Several rules should have two
implementations: `when: authselect` and `default: true`.

**Fix:** For each rule, add a capability-gated authselect implementation:
```yaml
implementations:
  - when: authselect
    check:
      method: command
      run: 'authselect current 2>/dev/null | grep -q with-<feature>'
      expected_exit: 0
    remediation:
      mechanism: command_exec
      run: "authselect enable-feature with-<feature>"
  - default: true
    check:
      # existing direct PAM file check
    remediation:
      # existing direct remediation
```

### 7c: su-require-wheel — Authselect Conflict

**File:** `rules/access-control/su-require-wheel.yml`

**Problem:** Remediation uses `sed` to edit `/etc/pam.d/su` directly.
On authselect-managed systems, this edit will be overwritten.

**Fix:** Add authselect-gated implementation that enables the
`with-wheel` feature (if available) or documents the manual step.

### 7d: Missing depends_on Declarations

| Rule | Should Depend On | Reason |
|------|-----------------|--------|
| `package-sudo-installed` | (none, but should be depended ON) | Foundation for all sudo rules |
| `sudo-reauth-not-disabled` | `package-sudo-installed` | Needs sudo |
| `sudo-require-password` | `package-sudo-installed` | Needs sudo |
| `root-access-controlled` | `ssh-disable-root-login` | Related control |

### Verification

```bash
# Check ordering with dependencies
./aegis list-frameworks
pytest tests/ -k ordering -v
```

---

## FIX-08: Remediation Quality Issues (MEDIUM) {#fix-08}

### 8a: Missing Idempotency Guards

| Rule | Issue |
|------|-------|
| `passwd-shadowed.yml` | `command_exec: pwconv` without `unless` guard |
| `su-require-wheel.yml` | `sed`/`echo` without `unless` guard |

**Fix:** Add `unless:` or `onlyif:` guards to `command_exec` remediations:
```yaml
remediation:
  mechanism: command_exec
  run: "pwconv"
  unless: "awk -F: '$2 != \"x\"' /etc/passwd | grep -q ."
```

### 8b: Incomplete Multi-Source Checks

| Rule | Current Check | Missing Sources |
|------|--------------|----------------|
| `umask-default.yml` | /etc/profile, /etc/bashrc | /etc/login.defs, PAM (pam_umask) |
| `inactive-password-lock.yml` | /etc/default/useradd static | Effective defaults |
| `sshd-config-permissions.yml` | Main sshd_config only | sshd_config.d/ drop-ins |

These are lower priority because the current checks cover the primary
configuration source. Aspirational improvements.

### 8c: login-defs Rules — Static Only

**Rules:** `login-defs-pass-max-days.yml`, `login-defs-pass-min-days.yml`,
`login-defs-pass-min-len.yml`, `login-defs-pass-warn-age.yml`

**Problem:** These check `/etc/login.defs` (defaults for NEW users) but
don't verify existing users comply. A user created before the policy change
retains their old settings.

**Aspirational fix:** Add a second check that runs `chage -l` against
existing user accounts to verify compliance. This is complex and may be
better as a separate rule.

---

## Implementation Order

| Phase | Fix | Rules | Risk | Est. Effort |
|-------|-----|-------|------|-------------|
| 1 | FIX-01: Field names | 17 rules | Low (mechanical) | Small |
| 2 | FIX-04: description → note | 16 rules | Low (mechanical) | Small |
| 3 | FIX-03: Delete duplicates | 8 deletions | Medium (mapping updates) | Medium |
| 4 | FIX-05: Logic bugs | 3 rules | Medium (behavior change) | Small |
| 5 | FIX-02: SSH effective config | 26 rules | High (behavior change) | Large |
| 6 | FIX-07: Capability gating | ~12 rules | Medium (new implementations) | Large |
| 7 | FIX-08: Remediation quality | ~5 rules | Low (additive) | Small |
| 8 | FIX-06: Framework references | ~30 rules | None (data only) | Medium |

### Phase 1-2: Safe mechanical fixes

These are field renames with no behavioral change. Run tests after each.

### Phase 3: Duplicate consolidation

Delete 8 rules, update mapping files. Verify coverage is unchanged.

### Phase 4: Logic bugs

Fix root-umask comparison, shell-timeout value validation,
pam-faillock-enabled error swallowing. These change behavior — test on
a real host.

### Phase 5: SSH migration

The largest change. Migrate 26 rules from `config_value` to
`sshd_effective_config`. This changes which SSH settings are detected
(effective vs file). Test each rule against a real host.

### Phase 6-8: Quality improvements

Additive changes that improve capability gating, remediation safety,
and framework reference coverage.

---

## Systemic Note

The `command:` / `expected_exit_code:` field naming issue exists in **22
additional rules** outside access-control (system, services, logging,
network, audit categories). These should be fixed in the same pass as
FIX-01 to prevent partial inconsistency.

---

## Post-Fix Validation Checklist

```bash
# 1. Schema validation — all rules
python schema/validate.py

# 2. Unit tests
pytest tests/ -v

# 3. Lint
ruff check runner/ schema/ tests/

# 4. Type check
mypy runner/ schema/ --ignore-missing-imports

# 5. CIS coverage unchanged
./aegis coverage --framework cis-rhel9-v2.0.0
./aegis coverage --framework cis-rhel8-v4.0.0

# 6. Mapping sync clean
python scripts/sync_cis_mappings.py --mapping mappings/cis/rhel9_v2.0.0.yaml
python scripts/sync_cis_mappings.py --mapping mappings/cis/rhel8_v4.0.0.yaml

# 7. Integration test (on a real RHEL host)
./aegis check --inventory inventory.ini --sudo --limit <host> --framework cis-rhel9-v2.0.0
```
