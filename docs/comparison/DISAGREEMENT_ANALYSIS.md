# AEGIS vs OpenSCAP Disagreement Analysis

**Date:** 2026-02-09
**Disagreement Rate:** 11.4% (20 of 176 CIS sections where both have coverage)

---

## Summary by Root Cause

| Root Cause | Count | Action Required |
|------------|-------|-----------------|
| **AEGIS Bug** | 3 | Fix handler logic |
| **Different Check Scope** | 8 | Align or document difference |
| **CIS Section Mismapping** | 5 | Fix section references |
| **Different Validation Logic** | 4 | Decide which is correct |

---

## Category 1: AEGIS Bugs (3 issues)

### 1.1 CIS 6.2.1.1 - journald "static" state

**Symptom:** AEGIS FAIL, OpenSCAP PASS

```
AEGIS:    systemd-journald: enabled=static (expected enabled)
OpenSCAP: service_systemd-journald_enabled: pass
```

**Root Cause:** The `_check_service_state` handler does strict string comparison:
```python
if actual_enabled != "enabled":  # Line 57
    failures.append(...)
```

But `systemctl is-enabled` returns `static` for services without an `[Install]` section (like journald). This is a valid "always enabled" state.

**Fix Required:**
```python
# Accept both "enabled" and "static" as valid enabled states
ENABLED_STATES = {"enabled", "static"}
if actual_enabled not in ENABLED_STATES:
    failures.append(...)
```

**Files:** `runner/handlers/checks/_service.py:57`

---

### 1.2 CIS 1.4.2 - GRUB permissions incomplete

**Symptom:** AEGIS PASS (1 rule), OpenSCAP FAIL (13 rules, some passing)

**Root Cause:** AEGIS `grub-config-permissions` only checks `/boot/grub2/grub.cfg`. OpenSCAP also checks:
- `/boot/grub2/user.cfg` (permissions, owner, group)
- Backup files
- Other GRUB-related files

**Fix Required:** Expand AEGIS rule or create additional rules.

---

### 1.3 CIS 5.2.7 - pam_wheel incomplete

**Symptom:** AEGIS PASS, OpenSCAP FAIL

```
AEGIS:    auth required pam_wheel.so use_uid → PASS
OpenSCAP: ensure_pam_wheel_group_empty → FAIL
          use_pam_wheel_group_for_su → FAIL
```

**Root Cause:** CIS 5.2.7 has TWO requirements:
1. pam_wheel.so configured in /etc/pam.d/su ✓ (AEGIS checks this)
2. wheel group has only authorized users ✗ (AEGIS doesn't check)

**Fix Required:** Add check for wheel group membership or create separate rule.

---

## Category 2: Different Check Scope (8 issues)

### 2.1 CIS 1.5.3/1.5.4 - Coredump controls

**Symptom:** AEGIS FAIL, OpenSCAP PASS

| Tool | What it checks |
|------|----------------|
| AEGIS | `limits.conf` → `* hard core 0` and `sysctl fs.suid_dumpable` |
| OpenSCAP | `coredump.conf` → `Storage=none`, `ProcessSizeMax=0` |

**Analysis:** Both are valid approaches. OpenSCAP checks systemd-coredump daemon config. AEGIS checks traditional limits.conf. Modern RHEL 9 uses systemd-coredump.

**Recommendation:** AEGIS should add coredump.conf checks OR document that it uses traditional approach.

---

### 2.2 CIS 3.1.3 - Bluetooth disable

**Symptom:** AEGIS PASS, OpenSCAP FAIL

| Tool | What it checks |
|------|----------------|
| AEGIS | Kernel module blacklisted (`install bluetooth /bin/false`) |
| OpenSCAP | systemd service disabled (`systemctl is-enabled bluetooth`) |

**Analysis:** Both are valid. AEGIS approach is more thorough (module-level), but OpenSCAP also checks service layer.

**Recommendation:** AEGIS should add service check OR document kernel-level is sufficient.

---

### 2.3 CIS 1.6.1 - Crypto policy

**Symptom:** AEGIS PASS, OpenSCAP FAIL

```
AEGIS:    crypto-policy-no-weak: ok (checks policy not NULL/LEGACY)
OpenSCAP: configure_crypto_policy: fail (checks specific policy level)
```

**Analysis:** OpenSCAP may require FIPS or specific policy. AEGIS accepts any non-weak policy.

**Recommendation:** Investigate OpenSCAP's specific requirement.

---

### 2.4 CIS 1.7.3 - Banner content

**Symptom:** AEGIS PASS, OpenSCAP FAIL

```
AEGIS:    banner-dod-consent: "USG-authorized use only" found → PASS
OpenSCAP: banner_etc_issue_net_cis: FAIL (checks /etc/issue.net format)
```

**Analysis:** AEGIS checks `/etc/issue`, OpenSCAP checks `/etc/issue.net`. CIS requires both.

**Recommendation:** AEGIS should check both files.

---

### 2.5-2.8 Audit Rules (6.3.3.x)

Multiple audit rule disagreements stem from format differences:

| AEGIS Format | OpenSCAP Format |
|--------------|-----------------|
| Comma-separated syscalls | Individual syscall rules |
| `auid>=1000` | `auid>=1000 -F auid!=unset` |
| Single combined rule | Multiple granular rules |

**Analysis:** Both produce equivalent audit behavior. The disagreement is about parsing/validation format.

**Recommendation:** AEGIS check logic should accept both formats.

---

## Category 3: CIS Section Mismapping (5 issues)

### 3.1 CIS 2.2.6 - Wrong section

**Symptom:** AEGIS maps `service-disable-named` to 2.2.6, OpenSCAP maps sudo rules to 2.2.6

**Analysis:** CIS section numbering varies between benchmark versions. Need to verify against actual CIS RHEL 9 v2.0.0.

---

### 3.2 CIS 5.1.5 / 5.1.18 - SSH rules misaligned

**Symptom:** Different SSH rules mapped to same sections

```
CIS 5.1.5:  AEGIS=ssh-banner, OpenSCAP=sshd_use_strong_kex
CIS 5.1.18: AEGIS=ssh-use-pam, OpenSCAP=sshd_set_max_sessions
```

**Analysis:** Section numbers don't match between tools. Need CIS benchmark verification.

---

## Category 4: Different Validation Logic (4 issues)

### 4.1 CIS 5.4.1.5 - System accounts

**Symptom:** AEGIS FAIL, OpenSCAP PASS

AEGIS `nologin-system-accounts` checks all system accounts have nologin shell. OpenSCAP may have exceptions.

---

### 4.2 CIS 3.3.1/3.3.6 - Sysctl values

Different sysctl keys mapped to same sections. Need section alignment.

---

## Recommended Fixes

### Priority 1 - AEGIS Bugs (Fix immediately)

1. **service_state handler**: Accept "static" as valid enabled state
2. **journald-service-enabled**: Will auto-fix with handler change

### Priority 2 - Coverage Gaps (Add checks)

1. Add `/etc/issue.net` to banner checks
2. Add wheel group membership check
3. Add coredump.conf checks (Storage, ProcessSizeMax)
4. Add bluetooth service check alongside module check

### Priority 3 - Section Alignment (Update references)

1. Verify CIS section numbers against RHEL 9 v2.0.0 benchmark
2. Update `framework_section` in affected rules

### Priority 4 - Audit Rule Format (Improve parser)

1. Make audit rule checks more flexible on format variations
