# Spec Registry

Index of behavioral specifications, linking each spec to its source code, test coverage, and status.

## Handlers — Checks

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [config_value](handlers/checks/config_value.spec.yaml) | `runner/handlers/checks/_config.py` → `_check_config_value` | `tests/test_engine_checks.py` → `TestConfigValue`, `TestConfigValueComparator`, `TestConfigValueSpecDerived` | **Active** — 14 ACs, 14 tests |
| [sshd_effective_config](handlers/checks/sshd_effective_config.spec.yaml) | `runner/handlers/checks/_ssh.py` → `_check_sshd_effective_config` | `tests/test_engine_checks.py` → `TestSshdEffectiveConfig`, `TestSshdEffectiveConfigSpecDerived` | **Active** — 13 ACs, 13 tests |
| [file_permission](handlers/checks/file_permission.spec.yaml) | `runner/handlers/checks/_file.py` → `_check_file_permission` | `tests/test_engine_checks.py` → `TestFilePermission`, `TestFilePermissionSpecDerived` | **Active** — 17 ACs, 19 tests |
| [service_state](handlers/checks/service_state.spec.yaml) | `runner/handlers/checks/_service.py` → `_check_service_state` | `tests/test_engine_checks.py` → `TestServiceState`, `TestServiceStateSpecDerived` | **Active** — 18 ACs, 18 tests |
| [command](handlers/checks/command.spec.yaml) | `runner/handlers/checks/_command.py` → `_check_command` | `tests/test_engine_checks.py` → `TestCommand`, `TestCommandSpecDerived` | **Active** — 18 ACs, 29 tests |
| [file_exists](handlers/checks/file_exists.spec.yaml) | `runner/handlers/checks/_file.py` → `_check_file_exists` | `tests/test_engine_checks.py` → `TestFileExists`, `TestFileExistsSpecDerived` | **Active** — 6 ACs, 8 tests |
| [file_not_exists](handlers/checks/file_not_exists.spec.yaml) | `runner/handlers/checks/_file.py` → `_check_file_not_exists` | `tests/test_engine_checks.py` → `TestFileNotExists`, `TestFileNotExistsSpecDerived` | **Active** — 5 ACs, 7 tests |
| [file_content](handlers/checks/file_content.spec.yaml) | `runner/handlers/checks/_file.py` → `_check_file_content` | `tests/test_engine_checks.py` → `TestFileContent`, `TestFileContentSpecDerived` | **Active** — 10 ACs, 14 tests |
| [file_content_match](handlers/checks/file_content_match.spec.yaml) | `runner/handlers/checks/_file.py` → `_check_file_content_match` | `tests/test_engine_checks.py` → `TestFileContentMatch`, `TestFileContentMatchSpecDerived` | **Active** — 8 ACs, 11 tests |
| [file_content_no_match](handlers/checks/file_content_no_match.spec.yaml) | `runner/handlers/checks/_file.py` → `_check_file_content_no_match` | `tests/test_engine_checks.py` → `TestFileContentNoMatch`, `TestFileContentNoMatchSpecDerived` | **Active** — 6 ACs, 9 tests |
| [config_absent](handlers/checks/config_absent.spec.yaml) | `runner/handlers/checks/_config.py` → `_check_config_absent` | `tests/test_engine_checks.py` → `TestConfigAbsent`, `TestConfigAbsentSpecDerived` | **Active** — 6 ACs, 8 tests |
| [sysctl_value](handlers/checks/sysctl_value.spec.yaml) | `runner/handlers/checks/_system.py` → `_check_sysctl_value` | `tests/test_engine_checks.py` → `TestSysctlValue` | **Active** — 6 ACs, 6 tests |
| [kernel_module_state](handlers/checks/kernel_module_state.spec.yaml) | `runner/handlers/checks/_system.py` → `_check_kernel_module_state` | `tests/test_engine_checks.py` → `TestKernelModuleState` | **Active** — 8 ACs, 8 tests |
| [mount_option](handlers/checks/mount_option.spec.yaml) | `runner/handlers/checks/_system.py` → `_check_mount_option` | `tests/test_engine_checks.py` → `TestMountOption` | **Active** — 8 ACs, 8 tests |
| [grub_parameter](handlers/checks/grub_parameter.spec.yaml) | `runner/handlers/checks/_system.py` → `_check_grub_parameter` | `tests/test_engine_checks.py` → `TestGrubParameter` | **Active** — 7 ACs, 7 tests |
| [package_state](handlers/checks/package_state.spec.yaml) | `runner/handlers/checks/_package.py` → `_check_package_state` | `tests/test_engine_checks.py` → `TestPackageState` | **Active** — 6 ACs, 6 tests |
| [selinux_state](handlers/checks/selinux_state.spec.yaml) | `runner/handlers/checks/_security.py` → `_check_selinux_state` | `tests/test_engine_checks.py` → `TestSelinuxState` | **Active** — 5 ACs, 5 tests |
| [selinux_boolean](handlers/checks/selinux_boolean.spec.yaml) | `runner/handlers/checks/_security.py` → `_check_selinux_boolean` | `tests/test_engine_checks.py` → `TestSelinuxBoolean` | **Active** — 6 ACs, 6 tests |
| [audit_rule_exists](handlers/checks/audit_rule_exists.spec.yaml) | `runner/handlers/checks/_security.py` → `_check_audit_rule_exists` | `tests/test_engine_checks.py` → `TestAuditRuleExists` | **Active** — 8 ACs, 8 tests |
| [pam_module](handlers/checks/pam_module.spec.yaml) | `runner/handlers/checks/_security.py` → `_check_pam_module` | `tests/test_engine_checks.py` → `TestPamModule` | **Active** — 8 ACs, 8 tests |
| [systemd_target](handlers/checks/systemd_target.spec.yaml) | `runner/handlers/checks/_service.py` → `_check_systemd_target` | `tests/test_engine_checks.py` → `TestSystemdTarget` | **Active** — 5 ACs, 5 tests |

## Handlers — Remediation

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [config_set](handlers/remediation/config_set.spec.yaml) | `runner/handlers/remediation/_config.py` → `_remediate_config_set` | `tests/test_engine_remediation.py` → `TestConfigSet`, `TestConfigSetSpecDerived` | **Active** — 12 ACs, 17 tests |
| [pam_module_configure](handlers/remediation/pam_module_configure.spec.yaml) | `runner/handlers/remediation/_security.py` → `_remediate_pam_module_configure` | `tests/test_engine_remediation.py` → `TestPamModuleConfigureSpecDerived` | **Active** — 11 ACs, 13 tests |
| [service_lifecycle](handlers/remediation/service_lifecycle.spec.yaml) | `runner/handlers/remediation/_service.py` → `_remediate_service_enabled`, `_remediate_service_disabled` | `tests/test_service_lifecycle.py` → `TestServiceEnabledSpecDerived`, `TestServiceDisabledSpecDerived` | **Active** — 14 ACs, 22 tests |
| [sysctl_set](handlers/remediation/sysctl_set.spec.yaml) | `runner/handlers/remediation/_system.py` → `_remediate_sysctl_set` | `tests/test_engine_remediation.py` → `TestSysctlSet`, `TestSysctlSetSpecDerived` | **Active** — 9 ACs, 15 tests |
| [audit_rule_set](handlers/remediation/audit_rule_set.spec.yaml) | `runner/handlers/remediation/_security.py` → `_remediate_audit_rule_set` | `tests/test_remediation_audit_rule_set.py` → `TestAuditRuleSetSpecDerived` | **Active** — 9 ACs, 16 tests |

## Orchestration

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [evaluate_rule](orchestration/evaluate_rule.spec.yaml) | `runner/_orchestration.py` → `evaluate_rule` | `tests/test_orchestration_evaluate.py` → `TestEvaluateRuleSpecDerived`, `TestExtractFrameworkRefs` | **Active** — 14 ACs, 30 tests |
| [remediate_rule](orchestration/remediate_rule.spec.yaml) | `runner/_orchestration.py` → `remediate_rule` | `tests/test_orchestration_remediate.py` → `TestRemediateRuleSpecDerived` | **Active** — 15 ACs, 23 tests |
| [rollback](orchestration/rollback.spec.yaml) | `runner/handlers/rollback/__init__.py` → `_execute_rollback`; `runner/_orchestration.py` → `rollback_from_stored` | `tests/test_orchestration_rollback.py` → `TestExecuteRollbackSpecDerived`, `TestRollbackFromStoredSpecDerived` | **Active** — 15 ACs, 22 tests |

## CLI Commands

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [check](cli/check.spec.yaml) | `runner/cli.py` → `check()` | `tests/test_cli_spec.py` → `TestCheckSpecDerived` | **Active** — 18 ACs, 14 tests |
| [remediate](cli/remediate.spec.yaml) | `runner/cli.py` → `remediate()` | `tests/test_cli_spec.py` → `TestRemediateSpecDerived` | **Active** — 20 ACs, 15 tests |
| [detect](cli/detect.spec.yaml) | `runner/cli.py` → `detect()` | `tests/test_cli_spec.py` → `TestDetectSpecDerived` | **Active** — 8 ACs, 8 tests |
| [rollback](cli/rollback.spec.yaml) | `runner/cli.py` → `rollback()` | `tests/test_cli_spec.py` → `TestRollbackSpecDerived` | **Active** — 18 ACs, 12 tests |
| [history](cli/history.spec.yaml) | `runner/cli.py` → `history()` | `tests/test_cli_spec.py` → `TestHistorySpecDerived` | **Active** — 12 ACs, 10 tests |
| [diff](cli/diff.spec.yaml) | `runner/cli.py` → `diff()` | `tests/test_cli_spec.py` → `TestDiffSpecDerived` | **Active** — 10 ACs, 7 tests |
| [coverage](cli/coverage.spec.yaml) | `runner/cli.py` → `coverage()` | `tests/test_cli_spec.py` → `TestCoverageSpecDerived` | **Active** — 8 ACs, 8 tests |
| [list-frameworks](cli/list_frameworks.spec.yaml) | `runner/cli.py` → `list_frameworks()` | `tests/test_cli_spec.py` → `TestListFrameworksSpecDerived` | **Active** — 5 ACs, 5 tests |
| [info](cli/info.spec.yaml) | `runner/cli.py` → `info()` | `tests/test_cli_spec.py` → `TestInfoSpecDerived` | **Active** — 15 ACs, 15 tests |

## Data

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [result_store](data/result_store.spec.yaml) | `runner/storage.py` → `ResultStore` | `tests/test_storage_spec.py` → `TestResultStoreSpecDerived` | **Active** — 18 ACs, 18 tests |

## Internal Modules

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [variable_resolution](internal/variable_resolution.spec.yaml) | `runner/_config.py` → `load_config`, `resolve_variables`, `parse_var_overrides` | `tests/test_variable_resolution_spec.py` → `TestVariableResolutionSpecDerived` | **Active** — 14 ACs, 15 tests |

## Legend

- **Active** — Spec written, tests mapped, all ACs covered
- **Draft** — Spec written, test gaps remain
- **Planned** — Spec not yet written
