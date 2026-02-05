# P1-2: Full Handler Coverage

## Status: Not Started

## Problem
V0 implements 7 of 17 check methods and 8 of 23 remediation mechanisms defined in the schema. As we write more rules, we'll need the remaining handlers.

## Current State

### Check Handlers (7/17 implemented)
| Method | Status | Notes |
|--------|--------|-------|
| config_value | Done | |
| file_permission | Done | With glob support |
| command | Done | |
| sysctl_value | Done | |
| kernel_module_state | Done | |
| package_state | Done | |
| file_exists | Done | |
| config_absent | **TODO** | Key must NOT exist in file |
| file_not_exists | **TODO** | Inverse of file_exists |
| file_content_match | **TODO** | Regex pattern match |
| file_content_no_match | **TODO** | Regex must not match |
| service_state | **TODO** | systemctl is-enabled/is-active |
| mount_option | **TODO** | findmnt + option check |
| audit_rule_exists | **TODO** | auditctl -l grep |
| grub_parameter | **TODO** | grubby --info or grub2-editenv |
| selinux_boolean | **TODO** | getsebool |
| selinux_state | **TODO** | getenforce |
| pam_module | **TODO** | grep PAM stack files |

### Remediation Handlers (8/23 implemented)
| Mechanism | Status | Notes |
|-----------|--------|-------|
| config_set | Done | |
| config_set_dropin | Done | |
| command_exec | Done | |
| file_permissions | Done | With glob support |
| sysctl_set | Done | |
| package_present | Done | |
| kernel_module_disable | Done | |
| manual | Done | |
| config_remove | **TODO** | Comment out or delete key |
| config_block | **TODO** | Multiline block with markers |
| file_absent | **TODO** | rm -f |
| file_content | **TODO** | Write full file content |
| service_enabled | **TODO** | systemctl enable --now |
| service_disabled | **TODO** | systemctl disable --now |
| service_masked | **TODO** | systemctl mask |
| package_absent | **TODO** | dnf remove -y |
| grub_parameter_set | **TODO** | grubby --update-kernel |
| grub_parameter_remove | **TODO** | grubby --remove-args |
| mount_option_set | **TODO** | Edit fstab + remount |
| pam_module_configure | **TODO** | authselect or direct PAM edit |
| audit_rule_set | **TODO** | auditctl + persist |
| selinux_boolean_set | **TODO** | setsebool -P |
| cron_job | **TODO** | Write crontab or systemd timer |

## Technical Approach

Implement in priority order based on which rules need them:

### Phase 1 — High Value (unblocks most rules)
1. `service_state` check + `service_enabled`/`service_disabled`/`service_masked` remediation
2. `file_content_match` / `file_content_no_match` checks
3. `config_absent` check + `config_remove` remediation
4. `file_not_exists` check + `file_absent` remediation

### Phase 2 — Security Features
5. `selinux_state` / `selinux_boolean` checks + `selinux_boolean_set` remediation
6. `pam_module` check + `pam_module_configure` remediation
7. `audit_rule_exists` check + `audit_rule_set` remediation

### Phase 3 — System Configuration
8. `mount_option` check + `mount_option_set` remediation
9. `grub_parameter` check + `grub_parameter_set`/`grub_parameter_remove` remediation
10. `file_content` remediation + `config_block` remediation
11. `package_absent` remediation
12. `cron_job` remediation

## Acceptance Criteria
- [ ] Each new handler has unit tests against mock SSH
- [ ] Each handler follows the patterns in `context/patterns.md`
- [ ] New rules can be written for any check method / remediation mechanism in the schema
- [ ] All handlers use `shlex.quote()` for interpolated values
- [ ] Remediation handlers support `dry_run`
- [ ] Remediation handlers call `_reload_service()` where applicable
