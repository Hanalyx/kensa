# Technical Differences: AEGIS vs OpenSCAP

**Version:** 1.0
**Date:** 2026-02-08
**Status:** Reference Document

---

## Executive Summary

AEGIS and OpenSCAP represent two fundamentally different philosophies for security compliance automation. OpenSCAP follows the **benchmark-centric** model where rules are organized around compliance document structure. AEGIS follows a **control-centric** model where canonical security controls exist independently of any specific framework.

This document explains the architectural differences, check methodologies, trade-offs, and implications for organizations implementing technical compliance programs.

---

## 1. Architectural Philosophy

### 1.1 OpenSCAP: Benchmark-Centric Architecture

OpenSCAP is built around the Security Content Automation Protocol (SCAP), a NIST-standardized specification for expressing security configuration checklists. Its architecture reflects the structure of compliance documents.

```
┌─────────────────────────────────────────────────────────────┐
│                    SCAP Data Stream                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   XCCDF     │  │    OVAL     │  │    CPE      │          │
│  │ (Checklist) │  │  (Checks)   │  │ (Platform)  │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Profile: CIS RHEL 9                         │
│  Rule: xccdf_org.ssgproject.content_rule_sshd_disable_root  │
│  Rule: xccdf_org.ssgproject.content_rule_accounts_tmout     │
│  Rule: xccdf_org.ssgproject.content_rule_grub2_password     │
│  ... (367 rules for CIS RHEL 9 profile)                     │
└─────────────────────────────────────────────────────────────┘
```

**Key characteristics:**

- **One datastream per OS**: `ssg-rhel8-ds.xml`, `ssg-rhel9-ds.xml` are separate artifacts
- **One profile per benchmark**: CIS L1 Server, CIS L2 Server, STIG are distinct profiles
- **Rules named by function**: `sshd_disable_root_login`, `grub2_password`
- **OVAL definitions**: Checks are expressed in Open Vulnerability and Assessment Language (XML)
- **CPE dictionaries**: Platform applicability via Common Platform Enumeration

### 1.2 AEGIS: Control-Centric Architecture

AEGIS is built around the concept of canonical security controls that exist independently of any compliance framework. Frameworks are metadata attached to rules, not organizational structures.

```
┌─────────────────────────────────────────────────────────────┐
│                   Framework Mappings                         │
│   CIS RHEL 8/9/10  ·  STIG RHEL 8/9  ·  NIST 800-53        │
│                  (metadata layer - labels)                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ references
┌──────────────────────────▼──────────────────────────────────┐
│                    Canonical Rules                           │
│                                                              │
│   Rule: ssh-disable-root-login     (one rule, all OSes)     │
│   Rule: grub-password              (one rule, all OSes)     │
│   Rule: audit-time-change          (one rule, all OSes)     │
│   ... (~200 canonical rules covering all frameworks)        │
└──────────────────────────┬──────────────────────────────────┘
                           │ implements
┌──────────────────────────▼──────────────────────────────────┐
│               Capability-Gated Implementations               │
│                                                              │
│   ssh-disable-root-login:                                    │
│     ├── when(sshd_config_d): use drop-in file               │
│     └── default: modify sshd_config directly                │
└─────────────────────────────────────────────────────────────┘
```

**Key characteristics:**

- **One rule set**: Covers all OS versions and all frameworks
- **Capability detection**: Runtime probes determine which implementation to use
- **Framework as metadata**: CIS section numbers are cross-references, not structure
- **YAML definitions**: Human-readable, auditable rule format
- **Forward compatible**: New OS versions work without rule changes

---

## 2. Check Methodology Differences

### 2.1 OpenSCAP Check Approach

OpenSCAP uses OVAL (Open Vulnerability and Assessment Language) for checks. OVAL is an XML-based declarative language that describes system state.

**Example: Checking SSH Root Login**

```xml
<definition id="oval:ssg-sshd_disable_root_login:def:1">
  <criteria operator="OR">
    <criterion test_ref="oval:ssg-test_sshd_disable_root_login:tst:1"/>
    <criterion test_ref="oval:ssg-test_sshd_not_installed:tst:1"/>
  </criteria>
</definition>

<ind:textfilecontent54_test id="oval:ssg-test_sshd_disable_root_login:tst:1">
  <ind:object object_ref="oval:ssg-obj_sshd_disable_root_login:obj:1"/>
  <ind:state state_ref="oval:ssg-state_sshd_disable_root_login:ste:1"/>
</ind:textfilecontent54_test>

<ind:textfilecontent54_object id="oval:ssg-obj_sshd_disable_root_login:obj:1">
  <ind:filepath>/etc/ssh/sshd_config</ind:filepath>
  <ind:pattern operation="pattern match">^\s*PermitRootLogin\s+(\S+)\s*$</ind:pattern>
</ind:textfilecontent54_object>
```

**Characteristics:**

- **Declarative XML**: Checks describe expected state in OVAL schema
- **File-based**: Primarily reads configuration files and parses content
- **Regex matching**: Pattern matching against file contents
- **Boolean logic**: Complex criteria with AND/OR operators
- **Offline capable**: Can scan filesystem images without running services

### 2.2 AEGIS Check Approach

AEGIS uses shell commands executed over SSH to verify system state. Checks are defined in YAML with explicit methods.

**Example: Checking SSH Root Login**

```yaml
id: ssh-disable-root-login
check:
  method: config_value
  path: /etc/ssh/sshd_config
  key: PermitRootLogin
  expected: "no"

implementations:
  - when: sshd_config_d
    check:
      method: command
      run: 'sshd -T 2>/dev/null | grep -i "^permitrootlogin"'
      expected_pattern: "^permitrootlogin no$"
  - default: true
    check:
      method: config_value
      path: /etc/ssh/sshd_config
      key: PermitRootLogin
      expected: "no"
```

**Characteristics:**

- **Operational verification**: Checks what the service actually uses, not just file content
- **Live system**: Queries running configuration via service introspection (`sshd -T`)
- **Capability-aware**: Different checks for systems with `sshd_config.d` support
- **Shell-based**: Uses standard Unix tools (grep, awk, systemctl)
- **Real-time**: Reflects current system state, not cached/compiled content

---

## 3. Fundamental Differences in Check Philosophy

### 3.1 Static vs Operational Verification

| Aspect | OpenSCAP | AEGIS |
|--------|----------|-------|
| **Primary method** | Parse config files | Query running services |
| **SSH example** | Read `/etc/ssh/sshd_config` | Run `sshd -T` to get effective config |
| **Sysctl example** | Read `/etc/sysctl.conf` | Run `sysctl -n <param>` |
| **Service example** | Parse systemd unit files | Run `systemctl is-enabled/is-active` |

**OpenSCAP approach:**
```
Read /etc/ssh/sshd_config → Parse for PermitRootLogin → Compare value
```

**AEGIS approach:**
```
Run sshd -T → Get EFFECTIVE configuration → Compare value
```

**Why this matters:**

SSH configuration can come from multiple sources:
- `/etc/ssh/sshd_config` (main file)
- `/etc/ssh/sshd_config.d/*.conf` (drop-in files)
- Match blocks (conditional configuration)
- Compiled defaults

OpenSCAP checking only `/etc/ssh/sshd_config` may miss:
- Settings in drop-in files that override the main config
- Match blocks that apply different settings per user/host
- Cases where the main file is empty but defaults are secure

AEGIS using `sshd -T` gets the **effective** configuration after all includes and overrides are processed.

### 3.2 Granular vs Consolidated Rules

| Aspect | OpenSCAP | AEGIS |
|--------|----------|-------|
| **Time audit rules** | 5 separate rules | 1 consolidated rule |
| **Cron access control** | 3 separate rules | 1 consolidated rule |
| **Password history** | 2 separate rules | 1 consolidated rule |

**OpenSCAP granularity:**
```
audit_rules_time_settimeofday       → Check for settimeofday syscall
audit_rules_time_clock_settime      → Check for clock_settime syscall
audit_rules_time_adjtimex           → Check for adjtimex syscall
audit_rules_time_stime              → Check for stime syscall
audit_rules_time_watch_localtime    → Check for /etc/localtime watch
```

**AEGIS consolidation:**
```
audit-time-change                   → Check all time-modification audit rules
```

**Why this matters:**

- **OpenSCAP**: One syscall missing = one finding. Precise but verbose.
- **AEGIS**: Time changes are audited or not. Holistic security posture.

The OpenSCAP approach aligns with benchmark document structure (each recommendation is a rule). The AEGIS approach aligns with security intent (time changes must be audited).

### 3.3 Version-Specific vs Capability-Gated

| Aspect | OpenSCAP | AEGIS |
|--------|----------|-------|
| **RHEL 8 vs 9 handling** | Separate datastreams | Same rules, capability detection |
| **New OS support** | New datastream required | Usually works automatically |
| **Derivative distros** | May need separate content | Works if capabilities match |

**OpenSCAP version handling:**
```
ssg-rhel8-ds.xml  → Rules for RHEL 8
ssg-rhel9-ds.xml  → Rules for RHEL 9
ssg-rhel10-ds.xml → Rules for RHEL 10 (when available)
```

**AEGIS capability handling:**
```
Detect capabilities → {sshd_config_d: true, authselect: true, ...}
Select implementation → Based on capabilities, not version string
Execute → Same rule works on RHEL 8, 9, 10, and derivatives
```

---

## 4. Rule Naming and Organization

### 4.1 OpenSCAP Naming Convention

OpenSCAP rule IDs follow a pattern derived from the SCAP Security Guide project:

```
xccdf_org.ssgproject.content_rule_<function>_<specifics>
```

Examples:
- `sshd_disable_root_login` - SSH function, disable root login
- `accounts_password_pam_minlen` - Accounts function, PAM password minimum length
- `audit_rules_dac_modification_chmod` - Audit function, DAC modification via chmod
- `kernel_module_cramfs_disabled` - Kernel function, cramfs module disabled

**Characteristics:**
- Function-based prefix (`sshd_`, `accounts_`, `audit_`, `kernel_`)
- Detailed suffix indicating exact control
- Often mirrors benchmark recommendation naming
- Separate rules for related controls

### 4.2 AEGIS Naming Convention

AEGIS uses kebab-case canonical IDs that describe the security control:

```
<category>/<control-name>.yml
```

Examples:
- `access-control/ssh-disable-root-login.yml`
- `access-control/pam-pwquality-minlen.yml`
- `audit/audit-time-change.yml`
- `kernel/kmod-disable-cramfs.yml`

**Characteristics:**
- Category-based directory structure
- Descriptive control names
- One file per canonical control
- Framework sections in metadata, not filename

### 4.3 Name Mapping Implications

The different naming conventions mean **rules don't map 1:1**:

| OpenSCAP Rules | AEGIS Rule | Notes |
|----------------|------------|-------|
| `audit_rules_time_settimeofday` | `audit-time-change` | Consolidated |
| `audit_rules_time_clock_settime` | `audit-time-change` | Consolidated |
| `audit_rules_time_adjtimex` | `audit-time-change` | Consolidated |
| `file_cron_allow_exists` | `cron-access-control` | Consolidated |
| `file_cron_deny_not_exist` | `cron-access-control` | Consolidated |
| `accounts_password_pam_pwhistory_remember_password_auth` | `password-remember` | Consolidated |
| `accounts_password_pam_pwhistory_remember_system_auth` | `password-remember` | Consolidated |

---

## 5. Pros and Cons

### 5.1 OpenSCAP

**Pros:**

| Advantage | Description |
|-----------|-------------|
| **Industry standard** | SCAP is a NIST standard; widely recognized by auditors |
| **Offline scanning** | Can scan filesystem images, containers, and offline systems |
| **Granular reporting** | Each benchmark recommendation has its own pass/fail |
| **Auditor-friendly output** | Reports match benchmark document structure exactly |
| **Ecosystem integration** | Satellite, Insights, Ansible integration out of box |
| **Formal verification** | OVAL provides mathematically precise state descriptions |
| **CVE checking** | Same tool handles vulnerability assessment |

**Cons:**

| Disadvantage | Description |
|--------------|-------------|
| **Static analysis limitations** | May miss effective configuration from includes/overrides |
| **Version-specific content** | Separate datastreams per OS version |
| **Delayed OS support** | New datastreams lag behind OS releases by months |
| **Complex content format** | OVAL XML is difficult to read and modify |
| **Remediation separate** | Check-only tool; remediation requires separate tooling |
| **False positives** | File-based checks may not reflect operational state |
| **Verbose findings** | 5 rules for "audit time changes" vs 1 security control |

### 5.2 AEGIS

**Pros:**

| Advantage | Description |
|-----------|-------------|
| **Operational verification** | Checks what services actually use, not just file content |
| **Capability-based** | Works across OS versions without modification |
| **Unified check/remediate** | Single tool for assessment and enforcement |
| **Forward compatible** | New OS versions usually work automatically |
| **Human-readable rules** | YAML format readable by compliance engineers |
| **Consolidated controls** | One rule per security intent, not per syscall |
| **Framework-agnostic** | Same rules serve CIS, STIG, NIST, PCI-DSS |

**Cons:**

| Disadvantage | Description |
|--------------|-------------|
| **Requires live system** | Cannot scan offline images or containers |
| **SSH dependency** | Requires network access and credentials |
| **Less auditor familiarity** | Not a NIST-standardized format |
| **Report mapping needed** | Must translate canonical rules to benchmark sections |
| **Newer project** | Less ecosystem integration than OpenSCAP |
| **Different findings count** | Consolidated rules mean different metrics |

---

## 6. Implications for Technical Compliance

### 6.1 Why Results May Differ

When OpenSCAP and AEGIS check the same system, results may differ due to:

#### 6.1.1 Check Method Differences

**SSH Configuration Example:**

```
System state:
  /etc/ssh/sshd_config:          PermitRootLogin yes
  /etc/ssh/sshd_config.d/99.conf: PermitRootLogin no
  Effective (sshd -T):           PermitRootLogin no
```

| Tool | Check Method | Result |
|------|--------------|--------|
| OpenSCAP | Read main config file | **FAIL** (sees "yes") |
| AEGIS | Run `sshd -T` | **PASS** (sees effective "no") |

Both are technically correct given their methodology. The system IS secure (root login disabled), but the main config file has an insecure value that's overridden.

#### 6.1.2 Threshold Interpretation

**Password Length Example:**

```
System state: minlen = 15
CIS RHEL 9 requires: minlen >= 14
```

| Tool | Check | Result |
|------|-------|--------|
| OpenSCAP | minlen == 14 (exact match) | **FAIL** |
| AEGIS | minlen >= 14 (threshold) | **PASS** |

OpenSCAP may check for exact values while AEGIS uses comparators (`>=`, `<=`). A more restrictive setting (15 > 14) should pass, not fail.

#### 6.1.3 Rule Granularity

**Audit Rules Example:**

```
System state: Missing audit rule for adjtimex syscall
              All other time audit rules present
```

| Tool | Rules Checked | Result |
|------|---------------|--------|
| OpenSCAP | 5 separate time rules | 4 PASS, 1 FAIL |
| AEGIS | 1 consolidated rule | **FAIL** (incomplete coverage) |

OpenSCAP reports 80% compliance (4/5 rules). AEGIS reports 0% (control not satisfied). The security posture is the same, but metrics differ.

### 6.2 Choosing the Right Tool

#### Use OpenSCAP When:

1. **Auditors require SCAP format** - Regulatory requirement for SCAP-compliant reports
2. **Scanning offline systems** - Container images, disk forensics, pre-deployment validation
3. **Integration with Red Hat ecosystem** - Satellite, Insights, RHEL built-in tooling
4. **CVE assessment needed** - Combined compliance and vulnerability scanning
5. **Benchmark document alignment required** - Report must match CIS PDF exactly

#### Use AEGIS When:

1. **Operational accuracy matters** - Need to verify what services actually use
2. **Multi-OS environment** - RHEL 8, 9, 10, Rocky, Alma in same estate
3. **Unified check/remediate workflow** - Assessment and enforcement in one tool
4. **Framework flexibility** - Report against CIS, STIG, or custom baseline
5. **Rapid new OS adoption** - Can't wait months for vendor content updates
6. **Security intent focus** - Care about "time changes audited" not "5 syscalls audited"

#### Use Both When:

Many organizations benefit from complementary use:

1. **OpenSCAP for audit evidence** - Formal SCAP reports for auditors
2. **AEGIS for operational enforcement** - Day-to-day compliance maintenance
3. **Cross-validation** - Discrepancies highlight areas needing investigation

### 6.3 Reconciling Discrepancies

When tools disagree, investigate the root cause:

| Discrepancy Type | Resolution |
|------------------|------------|
| Check method difference | Determine which reflects security intent |
| Threshold interpretation | Align on "at least" vs "exactly" semantics |
| Configuration location | Verify effective configuration includes all sources |
| Rule consolidation | Map canonical controls to granular checks |
| False positive | File exists but service doesn't use it |
| False negative | Service uses default, file doesn't exist |

---

## 7. Technical Comparison Summary

| Dimension | OpenSCAP | AEGIS |
|-----------|----------|-------|
| **Philosophy** | Benchmark-centric | Control-centric |
| **Rule structure** | Per-benchmark, per-OS | Canonical, capability-gated |
| **Check method** | File parsing (OVAL) | Operational queries (shell) |
| **Format** | SCAP XML | YAML |
| **Remediation** | Separate tooling | Integrated |
| **OS support** | Datastream per version | Capability detection |
| **Forward compatibility** | Requires new content | Usually automatic |
| **Audit reporting** | SCAP-native format | Framework mapping |
| **Granularity** | Per-recommendation | Per-security-control |
| **Offline capability** | Yes | No |

---

## 8. Conclusion

OpenSCAP and AEGIS are not competitors—they are complementary tools reflecting different philosophies about compliance automation.

**OpenSCAP** answers: *"Does this system match the benchmark document?"*

**AEGIS** answers: *"Is this system secure according to these controls?"*

The distinction matters when:
- A config file has insecure values that are overridden (OpenSCAP may fail, AEGIS passes)
- A service uses secure defaults with no explicit config (OpenSCAP may fail, AEGIS passes)
- Multiple related checks form one security control (OpenSCAP counts 5, AEGIS counts 1)

Organizations should understand these differences when:
1. Interpreting compliance scores between tools
2. Choosing tools for specific use cases
3. Investigating discrepancies in findings
4. Building compliance automation pipelines

Neither tool is "wrong"—they measure different things. Understanding what each measures is essential for effective technical compliance.

---

## References

- [NIST SCAP Specification](https://csrc.nist.gov/projects/security-content-automation-protocol)
- [OVAL Language Specification](https://oval.mitre.org/)
- [ComplianceAsCode Project](https://github.com/ComplianceAsCode/content)
- [AEGIS Technical Remediation Master Plan](../../TECHNICAL_REMEDIATION_MP_V0.md)
- [CIS RHEL 9 Benchmark v2.0.0](https://www.cisecurity.org/benchmark/red_hat_linux)
