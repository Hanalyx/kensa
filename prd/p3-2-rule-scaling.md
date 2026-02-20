# P3-2: Rule Scaling — Full CIS/STIG Coverage

## Status: Largely Complete (superseded)

**Note (2026-02-16):** This PRD targeted 180 rules with 17 check handlers. The codebase
now has 390 rules, 20 check handlers, and 23 remediation handlers. CIS RHEL 9 coverage
is 94% (229/244). The remaining gap is 102 rule IDs referenced in the CIS mapping that
lack rule YAML files, and STIG RHEL 9 at 76% (needs 80%). See `IMPLEMENTATION_PLAN.md`
for the updated status and remaining work.

## Executive Summary (original)

Scale Kensa from 35 canonical rules to ~180 rules covering the full CIS RHEL 9 Benchmark v2.0.0 and DISA STIG RHEL 9 V2R7. The handler infrastructure is complete (17 check handlers, 23 remediation handlers); this PRD focuses on rule authoring, testing, and quality assurance.

## Current State

### Existing Rules (35)

| Category | Rules | Coverage |
|----------|-------|----------|
| access-control | 18 | SSH hardening, PAM |
| audit | 2 | AIDE, auditd |
| filesystem | 5 | Permissions, kernel modules |
| kernel | 4 | Sysctl parameters |
| logging | 2 | Journald, rsyslog |
| network | 0 | — |
| services | 2 | Cron, systemd |
| system | 2 | Crypto policy, bootloader |

### Handler Coverage (100%)

All check methods and remediation mechanisms from the schema are implemented:

**Check Handlers (17):**
- config_value, config_absent, file_exists, file_permission, file_owner
- package_installed, service_state, sysctl_value, mount_option
- kmod_disabled, grub_option, command_output, banner_matches
- cron_job_present, selinux_boolean, audit_rule_exists, login_defs_value

**Remediation Handlers (23):**
- config_set, config_set_dropin, config_absent, file_permission, file_owner
- package_present, package_absent, service_enabled, service_disabled
- service_masked, sysctl_set, sysctl_persist, mount_option
- kmod_blacklist, grub_set, banner_set, cron_job, selinux_boolean
- audit_rule, login_defs_set, config_block, command, custom_script

## Target State

### CIS RHEL 9 Benchmark v2.0.0

| Section | Title | Est. Rules | Priority |
|---------|-------|------------|----------|
| 1.1 | Filesystem Configuration | 25 | Medium |
| 1.2 | Software Updates | 3 | Low |
| 1.3 | Filesystem Integrity | 2 | High |
| 1.4 | Secure Boot | 4 | Medium |
| 2.x | Services | 15 | Medium |
| 3.x | Network Configuration | 30 | High |
| 4.x | Logging and Auditing | 35 | High |
| 5.1 | SSH Server | 20 | High (mostly done) |
| 5.2 | Privilege Escalation | 10 | High |
| 5.3 | PAM Configuration | 12 | High (partially done) |
| 5.4 | User Accounts | 8 | Medium |
| 6.x | System Maintenance | 15 | Low |
| 7.x | System Cryptography | 5 | High (partially done) |

**Total CIS Sections:** ~287 (with ~240 automatable)

### STIG RHEL 9 V2R7

STIG has significant overlap with CIS. Estimated unique STIG-only rules: ~40

**Combined Target:** ~180 canonical rules (deduplicated)

## Approach: Category-First Implementation

Implement rules by category to group related functionality, share testing infrastructure, and enable incremental releases.

### Phase 1: Complete High-Priority Categories (Week 1-2)

**1.1 Network Configuration (30 rules)**
- Sysctl network parameters (ip_forward, send_redirects, etc.)
- Firewall configuration (firewalld rules)
- Network services (NFS, RPC disabled)
- IPv6 configuration

*Mechanisms needed:* sysctl_value/sysctl_set, service_state/service_masked, config_value

**1.2 Logging and Auditing (35 rules)**
- Auditd rules for system calls
- Journald configuration
- Rsyslog remote logging
- Log file permissions

*Mechanisms needed:* audit_rule_exists/audit_rule, config_value/config_set, file_permission

### Phase 2: Filesystem and Services (Week 3-4)

**2.1 Filesystem Configuration (25 rules)**
- Mount options (noexec, nosuid, nodev)
- Kernel module blacklisting (squashfs, udf, etc.)
- Partition configuration
- Sticky bit enforcement

*Mechanisms needed:* mount_option, kmod_disabled/kmod_blacklist, file_permission

**2.2 Services Hardening (15 rules)**
- Remove unnecessary services (avahi, cups, etc.)
- Configure required services (chrony, postfix)
- Systemd unit masking

*Mechanisms needed:* package_absent, service_masked, config_set

### Phase 3: User and Access Control (Week 5-6)

**3.1 PAM Configuration (12 rules)**
- Password complexity (pwquality)
- Account lockout (faillock)
- Password history
- Session limits

*Mechanisms needed:* config_value/config_set, config_block (for complex PAM stacks)

**3.2 User Account Policies (8 rules)**
- Password aging (login.defs)
- UID/GID validation
- Home directory permissions
- Default umask

*Mechanisms needed:* login_defs_value/login_defs_set, file_permission, command_output

**3.3 Privilege Escalation (10 rules)**
- Sudo configuration
- Su restrictions
- Root account hardening

*Mechanisms needed:* config_value/config_set_dropin, file_permission

### Phase 4: Remaining Categories (Week 7-8)

**4.1 Secure Boot (4 rules)**
- GRUB password
- Boot loader permissions

*Mechanisms needed:* grub_option/grub_set, file_permission

**4.2 Software Updates (3 rules)**
- GPG key verification
- Package manager configuration

*Mechanisms needed:* config_value/config_set, command_output

**4.3 System Maintenance (15 rules)**
- File integrity monitoring
- Suid/sgid file auditing
- World-writable file detection

*Mechanisms needed:* command_output, file_permission

### Phase 5: STIG-Only Rules (Week 9)

Rules unique to STIG without CIS equivalent (~40 rules):
- FIPS mode enforcement
- PKI/CAC configuration
- Additional audit requirements
- Banner customization

## Rule Authoring Guidelines

### 1. One Rule Per Control

Each rule addresses exactly one security control. Don't combine related controls.

```yaml
# GOOD: One rule, one control
id: sysctl-net-ipv4-icmp-echo-ignore-broadcasts
title: Ignore ICMP broadcast requests
check:
  method: sysctl_value
  parameter: net.ipv4.icmp_echo_ignore_broadcasts
  expected: "1"

# BAD: Multiple controls in one rule
id: sysctl-icmp-hardening  # Too broad
```

### 2. Use Existing Mechanisms

All 23 remediation mechanisms exist. Use them — don't create custom scripts unless absolutely necessary.

```yaml
# GOOD: Uses existing mechanism
remediation:
  mechanism: sysctl_persist
  parameter: net.ipv4.icmp_echo_ignore_broadcasts
  value: "1"

# BAD: Unnecessary custom script
remediation:
  mechanism: custom_script
  script: |
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
    sysctl -p
```

### 3. Capability Gates for Platform Differences

Use `when:` gates for implementations that require specific capabilities.

```yaml
implementations:
  - name: firewalld
    when: has_firewalld
    check: ...

  - name: iptables
    when: has_iptables
    check: ...

  - name: default
    default: true
    check:
      method: command_output
      command: "echo 'No firewall detected'"
      expected: "SKIP"
```

### 4. Explicit Reload Requirements

Mark rules that need service reload after remediation.

```yaml
remediation:
  mechanism: config_set
  file: /etc/ssh/sshd_config
  key: MaxAuthTries
  value: "4"
  reload: sshd  # Handler calls _reload_service()
```

## Testing Strategy

### Unit Testing (Per Rule)

Each rule YAML is validated:
1. Schema compliance (`python3 schema/validate.py rules/`)
2. Referenced capabilities exist in detect.py
3. Check method and remediation mechanism are implemented

### Integration Testing (Per Category)

Test against clean RHEL 9 VM:
1. Run `kensa check` — baseline state
2. Run `kensa remediate --dry-run` — verify planned changes
3. Run `kensa remediate` — apply changes
4. Run `kensa check` — verify all pass
5. Verify no breaking side effects

### Regression Testing

After each phase:
1. Full rule validation
2. Framework mapping validation
3. Dependency ordering validation
4. Cross-reference integrity check

## Quality Gates

### Per-Rule Quality Checklist

- [ ] Schema validates clean
- [ ] Filename matches `id` field
- [ ] Exactly one `default: true` implementation
- [ ] All `when:` references exist in CAPABILITY_PROBES
- [ ] Check method exists in CHECK_HANDLERS
- [ ] Remediation mechanism exists in REMEDIATION_HANDLERS
- [ ] Rule tested on RHEL 9 target
- [ ] Mapping entry added for CIS/STIG sections

### Per-Phase Quality Gates

| Gate | Criteria |
|------|----------|
| Schema | 0 validation errors |
| Coverage | All CIS sections for category have mapping entries |
| Testing | 100% rules pass check after remediate on test VM |
| Documentation | CHANGELOG updated with new rules |

## Mapping Maintenance

As rules are added, update mapping files:

```yaml
# mappings/cis/rhel9_v2.0.0.yaml
sections:
  "3.1.1":
    rule: sysctl-net-ipv4-ip-forward
    level: L1
    type: Automated
    title: "Ensure IP forwarding is disabled"

  "3.1.2":
    rule: sysctl-net-ipv4-send-redirects
    level: L1
    type: Automated
    title: "Ensure packet redirect sending is disabled"
```

Run coverage check after each phase:
```bash
./kensa coverage --framework cis-rhel9-v2.0.0
```

## Risk Mitigation

### Risk: Handler Gaps

**Mitigation:** Pre-audit identified 100% mechanism coverage. If gaps emerge, add handlers before rules.

### Risk: Complex PAM Rules

**Mitigation:** PAM rules with complex stacks use `config_block` mechanism with careful ordering. Test extensively on isolated VM.

### Risk: Breaking Changes

**Mitigation:** All remediation supports `--dry-run`. Integration tests run remediate + verify cycle.

### Risk: STIG/CIS Conflicts

**Mitigation:** Framework layer handles versioning. Same canonical rule maps to different sections.

## Success Criteria

### Phase Completion Criteria

- [ ] All rules in category validate against schema
- [ ] All rules tested on RHEL 9 VM
- [ ] Mapping entries created for all sections
- [ ] Coverage report shows category at 100%

### Project Completion Criteria

- [ ] 180+ canonical rules implemented
- [ ] CIS RHEL 9 v2.0.0 coverage ≥ 90% (excluding Manual sections)
- [ ] STIG RHEL 9 V2R7 coverage ≥ 85%
- [ ] All rules pass check→remediate→check cycle
- [ ] Zero schema validation errors
- [ ] Framework mappings complete and validated

## Deliverables

1. **~180 canonical rules** in `rules/` directory
2. **Updated mappings** in `mappings/cis/` and `mappings/stig/`
3. **Test results** documenting check/remediate/verify cycle
4. **Coverage report** showing framework coverage percentages
5. **CHANGELOG** documenting rule additions by phase

## Timeline Summary

| Phase | Focus | Rules | Duration |
|-------|-------|-------|----------|
| 1 | Network + Logging/Audit | 65 | 2 weeks |
| 2 | Filesystem + Services | 40 | 2 weeks |
| 3 | Users + PAM + Privilege | 30 | 2 weeks |
| 4 | Boot + Updates + Maintenance | 22 | 2 weeks |
| 5 | STIG-only | 40 | 1 week |

**Total:** ~180 rules over 9 weeks

## Dependencies

- P1-2 (Handler implementations) — Complete
- P2-3 (Framework mappings) — Complete
- Test environment (RHEL 9 VM with SSH access)
- CIS RHEL 9 Benchmark v2.0.0 PDF
- DISA STIG RHEL 9 V2R7 XCCDF

## Future Work

After P3-2 completion:
- P3-3: RHEL 8 rule variants (where different from RHEL 9)
- P3-4: Debian/Ubuntu rule variants
- P4-x: STIG Checklist (.ckl) export
- P4-x: OSCAL export for FedRAMP
