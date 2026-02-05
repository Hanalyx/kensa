# P1-2: Full Handler Coverage

## Status: In Progress (Phase 1 Complete)

## Problem
V0 implements 7 of 17 check methods and 8 of 23 remediation mechanisms defined in the schema. As we write more rules, we'll need the remaining handlers.

## Current State

### Check Handlers (12/17 implemented)
| Method | Status | Notes |
|--------|--------|-------|
| config_value | Done | |
| config_absent | Done | Key must NOT exist in file |
| file_permission | Done | With glob support |
| file_exists | Done | |
| file_not_exists | Done | Inverse of file_exists |
| file_content_match | Done | Regex pattern match |
| file_content_no_match | Done | Regex must not match |
| command | Done | |
| sysctl_value | Done | |
| kernel_module_state | Done | |
| package_state | Done | |
| service_state | Done | systemctl is-enabled/is-active |
| mount_option | **TODO** | findmnt + option check |
| audit_rule_exists | **TODO** | auditctl -l grep |
| grub_parameter | **TODO** | grubby --info or grub2-editenv |
| selinux_boolean | **TODO** | getsebool |
| selinux_state | **TODO** | getenforce |
| pam_module | **TODO** | grep PAM stack files |

### Remediation Handlers (15/23 implemented)
| Mechanism | Status | Notes |
|-----------|--------|-------|
| config_set | Done | |
| config_set_dropin | Done | |
| config_remove | Done | Delete key from file |
| command_exec | Done | |
| file_permissions | Done | With glob support |
| file_content | Done | Write full file content |
| file_absent | Done | rm -f |
| sysctl_set | Done | |
| package_present | Done | |
| package_absent | Done | dnf remove -y |
| kernel_module_disable | Done | |
| manual | Done | |
| service_enabled | Done | systemctl enable --now |
| service_disabled | Done | systemctl disable --now |
| service_masked | Done | systemctl mask |
| config_block | **TODO** | Multiline block with markers |
| grub_parameter_set | **TODO** | grubby --update-kernel |
| grub_parameter_remove | **TODO** | grubby --remove-args |
| mount_option_set | **TODO** | Edit fstab + remount |
| pam_module_configure | **TODO** | authselect or direct PAM edit |
| audit_rule_set | **TODO** | auditctl + persist |
| selinux_boolean_set | **TODO** | setsebool -P |
| cron_job | **TODO** | Write crontab or systemd timer |

## Technical Approach

Implement in priority order based on which rules need them:

### Phase 1 — High Value (unblocks most rules) ✓ COMPLETE
1. ✓ `service_state` check + `service_enabled`/`service_disabled`/`service_masked` remediation
2. ✓ `file_content_match` / `file_content_no_match` checks + `file_content` remediation
3. ✓ `config_absent` check + `config_remove` remediation
4. ✓ `file_not_exists` check + `file_absent` remediation
5. ✓ `package_absent` remediation

### Phase 2 — Security Features
6. `selinux_state` / `selinux_boolean` checks + `selinux_boolean_set` remediation
7. `pam_module` check + `pam_module_configure` remediation
8. `audit_rule_exists` check + `audit_rule_set` remediation

### Phase 3 — System Configuration
9. `mount_option` check + `mount_option_set` remediation
10. `grub_parameter` check + `grub_parameter_set`/`grub_parameter_remove` remediation
11. `config_block` remediation
12. `cron_job` remediation

## Acceptance Criteria
- [ ] Each new handler has unit tests against mock SSH
- [ ] Each handler follows the patterns in `context/patterns.md`
- [ ] New rules can be written for any check method / remediation mechanism in the schema
- [ ] All handlers use `shlex.quote()` for interpolated values
- [ ] Remediation handlers support `dry_run`
- [ ] Remediation handlers call `_reload_service()` where applicable
