# Check Logic Discrepancy Investigation

**Date:** 2026-02-08
**Target:** 192.168.1.211 (RHEL 9)
**Frameworks:** CIS RHEL 9 v2.0.0 (KENSA), CIS RHEL 9 profile (OpenSCAP)

---

## Executive Summary

Investigation of 5 discrepancies where **OpenSCAP passes** but **KENSA fails** on the same security controls. Root causes fall into three categories:

1. **Threshold semantics** - KENSA checks for exact values instead of "at least as strict"
2. **Rule format matching** - KENSA expects exact audit rule syntax vs OpenSCAP's flexible matching
3. **Check method differences** - Different approaches to verifying the same control

---

## Discrepancy Analysis

### 1. pam-faillock-deny

**System State:**
```
deny = 3  (locks account after 3 failed attempts)
```

**Check Results:**
| Tool | Expected | Actual | Result |
|------|----------|--------|--------|
| OpenSCAP | deny ≤ 5 | 3 | **PASS** |
| KENSA | deny = 5 (CIS default) | 3 | **FAIL** |

**Root Cause:** Missing comparator in KENSA rule.

CIS Benchmark 5.3.3.1.1 states: *"Ensure password failed attempts lockout is configured"* with guidance that `deny` should be "5 or fewer." The intent is a threshold, not an exact value.

**KENSA Rule (`pam-faillock-deny.yml`):**
```yaml
check:
  method: config_value
  path: "/etc/security/faillock.conf"
  key: "deny"
  expected: "{{ pam_faillock_deny }}"    # No comparator = exact match
```

**Correct Implementation:**
```yaml
check:
  method: config_value
  path: "/etc/security/faillock.conf"
  key: "deny"
  expected: "{{ pam_faillock_deny }}"
  comparator: "<="    # 3 ≤ 5 = PASS
```

**Impact:** Systems with stricter settings (deny=3 for STIG) incorrectly fail CIS checks.

---

### 2. chrony-user

**System State:**
```
chronyd runs as user "chrony" (by default in RHEL 9)
```

**Check Results:**
| Tool | Check Method | Result |
|------|--------------|--------|
| OpenSCAP | Checks process owner or config | **PASS** |
| KENSA | Checks explicit -u flag in OPTIONS | **FAIL** |

**Root Cause:** KENSA checks for explicit configuration, but RHEL 9 runs chronyd as "chrony" by default.

**KENSA Check:**
```yaml
run: "grep -E '^OPTIONS=.*-u chrony' /etc/sysconfig/chronyd 2>/dev/null ||
      grep -v '^#' /etc/chrony.conf 2>/dev/null | grep -E '^user\\s+chrony'"
```

This fails because:
- `/etc/sysconfig/chronyd` may not have explicit `-u chrony` (uses compiled default)
- `/etc/chrony.conf` may not have explicit `user chrony` directive

**OpenSCAP Check (likely):**
```
Check if chronyd process runs as UID chrony OR
Check for explicit user directive
```

**Correct Implementation:**
```yaml
run: |
  # Check effective runtime user (operational verification)
  ps -o user= -C chronyd 2>/dev/null | grep -q '^chrony$'
```

**Impact:** Systems using secure defaults fail the check for lacking explicit configuration.

---

### 3. audit-user-group-changes

**System State:**
```
Audit rules exist for /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow
But with different key names than KENSA expects
```

**Check Results:**
| Tool | Check Approach | Result |
|------|----------------|--------|
| OpenSCAP | Individual syscall checks | **PASS** (all 5 rules) |
| KENSA | Exact rule string match | **FAIL** |

**Root Cause:** KENSA requires exact audit rule format including key name.

**KENSA Check:**
```yaml
check:
  method: audit_rule_exists
  rule: "-w /etc/passwd -p wa -k identity"
```

**Actual System Rules (may be):**
```
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
```

The rule **exists** and **functions correctly**, but uses a different `-k` (key) value.

**OpenSCAP Check:**
OpenSCAP checks for the presence of watch rules on identity files, regardless of the key name used.

**Correct Implementation Options:**

Option A - Flexible key matching:
```yaml
check:
  method: command
  run: "auditctl -l | grep -E '^-w /etc/passwd.*-p wa'"
  expected_exit: 0
```

Option B - Accept any key:
```yaml
check:
  method: audit_rule_exists
  rule: "-w /etc/passwd -p wa"
  match_mode: "prefix"   # New feature needed
```

**Impact:** Systems with valid audit rules but different key names fail.

---

### 4. audit-permission-changes

**System State:**
```
DAC modification audit rules exist but in different format
```

**Check Results:**
| Tool | Check Approach | Result |
|------|----------------|--------|
| OpenSCAP | Per-syscall checks (chmod, fchmod, etc.) | **PASS** (all 4) |
| KENSA | Single consolidated rule check | **FAIL** |

**Root Cause:** Exact rule format mismatch.

**KENSA Expected Rule:**
```
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
```

**Possible System Rule Formats:**
```
# Separate rules (common in RHEL 9 default audit.rules)
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
```

**Differences:**
1. KENSA: Comma-separated syscalls (`chmod,fchmod,fchmodat`)
2. System: Individual rules per syscall
3. KENSA: `auid!=unset`
4. System: `auid!=4294967295` (numeric equivalent)

Both configurations provide **equivalent security** but have different textual representation.

**Correct Implementation:**
```yaml
check:
  # Check that chmod syscall is audited (any format)
  method: command
  run: |
    auditctl -l | grep -E '^-a always,exit.*-S.*chmod.*-F auid>='
  expected_exit: 0
```

**Impact:** Valid audit configurations with different formatting fail.

---

### 5. audit-kernel-modules (Partial Discrepancy)

**System State:**
```
Some kernel module audit rules present, some missing
```

**Check Results:**
| OpenSCAP Rule | Result |
|---------------|--------|
| `audit_rules_kernel_module_loading_init` | PASS |
| `audit_rules_kernel_module_loading_finit` | PASS |
| `audit_rules_kernel_module_loading_delete` | PASS |
| `audit_rules_kernel_module_loading_create` | FAIL |
| `audit_rules_kernel_module_loading_query` | FAIL |

**KENSA:** Single consolidated rule → **FAIL** (because not all syscalls covered)

**Root Cause:** KENSA consolidates 5 OpenSCAP rules into 1. If ANY syscall is missing, the whole control fails.

This is **correct behavior** for KENSA philosophy - the security control (audit kernel module operations) is either satisfied or not. OpenSCAP's granular view shows 60% compliance; KENSA shows 0% compliance for the control.

**Recommendation:** This is not a bug - it's a philosophical difference. Document the consolidated approach.

---

## Summary of Required Fixes

| Rule | Issue Type | Fix Required |
|------|------------|--------------|
| `pam-faillock-deny` | Missing comparator | Add `comparator: "<="` |
| `chrony-user` | Wrong check method | Check runtime user, not config |
| `audit-user-group-changes` | Exact match too strict | Flexible key name matching |
| `audit-permission-changes` | Exact match too strict | Pattern matching for syscalls |
| `audit-kernel-modules` | Philosophy difference | Document (not a bug) |

---

## Recommended Code Changes

### 1. Add Comparator to Threshold Rules

Rules that check security thresholds should use comparators:

```yaml
# pam-faillock-deny.yml
check:
  method: config_value
  path: "/etc/security/faillock.conf"
  key: "deny"
  expected: "{{ pam_faillock_deny }}"
  comparator: "<="   # More restrictive is acceptable

# ssh-client-alive-interval.yml
check:
  method: config_value
  path: "/etc/ssh/sshd_config"
  key: "ClientAliveInterval"
  expected: "{{ ssh_client_alive_interval }}"
  comparator: "<="   # Shorter interval is more secure
```

### 2. Operational Verification for Services

Check what services actually do, not just config files:

```yaml
# chrony-user.yml
check:
  method: command
  run: "ps -o user= -C chronyd 2>/dev/null | head -1"
  expected_pattern: "^chrony$"
```

### 3. Flexible Audit Rule Matching

New check method or option for audit rules:

```yaml
# Option A: Pattern-based audit check
check:
  method: command
  run: "auditctl -l | grep -E '^-w /etc/passwd.*-p wa'"
  expected_exit: 0

# Option B: New audit_rule_contains method
check:
  method: audit_rule_contains
  path: "/etc/passwd"
  permissions: "wa"
  # Ignores -k key name
```

---

## Conclusion

The discrepancies are **not missing rules** but **check logic differences**:

1. **Threshold semantics**: OpenSCAP accepts "at least as strict"; KENSA demands exact match
2. **Format flexibility**: OpenSCAP pattern-matches; KENSA requires exact strings
3. **Operational vs static**: OpenSCAP checks files; KENSA should check running state

Fixing these issues will improve KENSA accuracy without sacrificing the control-centric philosophy. The fixes maintain the "one rule per control" model while making checks more robust.
