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
| [config_set_dropin](handlers/remediation/config_set_dropin.spec.yaml) | `runner/handlers/remediation/_config.py` → `_remediate_config_set_dropin` | `tests/test_engine_remediation.py` | **Active** — 9 ACs |
| [config_remove](handlers/remediation/config_remove.spec.yaml) | `runner/handlers/remediation/_config.py` → `_remediate_config_remove` | `tests/test_engine_remediation.py` | **Active** — 8 ACs |
| [config_block](handlers/remediation/config_block.spec.yaml) | `runner/handlers/remediation/_config.py` → `_remediate_config_block` | `tests/test_engine_remediation.py` | **Active** — 10 ACs |
| [file_permissions](handlers/remediation/file_permissions.spec.yaml) | `runner/handlers/remediation/_file.py` → `_remediate_file_permissions` | `tests/test_engine_remediation.py` | **Active** — 11 ACs |
| [file_content_set](handlers/remediation/file_content_set.spec.yaml) | `runner/handlers/remediation/_file.py` → `_remediate_file_content_set` | `tests/test_engine_remediation.py` | **Active** — 8 ACs |
| [file_absent](handlers/remediation/file_absent.spec.yaml) | `runner/handlers/remediation/_file.py` → `_remediate_file_absent` | `tests/test_engine_remediation.py` | **Active** — 5 ACs |
| [package_present](handlers/remediation/package_present.spec.yaml) | `runner/handlers/remediation/_package.py` → `_remediate_package_present` | `tests/test_engine_remediation.py` | **Active** — 5 ACs |
| [package_absent](handlers/remediation/package_absent.spec.yaml) | `runner/handlers/remediation/_package.py` → `_remediate_package_absent` | `tests/test_engine_remediation.py` | **Active** — 7 ACs |
| [service_masked](handlers/remediation/service_masked.spec.yaml) | `runner/handlers/remediation/_service.py` → `_remediate_service_masked` | `tests/test_engine_remediation.py` | **Active** — 8 ACs |
| [kernel_module_disable](handlers/remediation/kernel_module_disable.spec.yaml) | `runner/handlers/remediation/_system.py` → `_remediate_kernel_module_disable` | `tests/test_engine_remediation.py` | **Active** — 7 ACs |
| [mount_option_set](handlers/remediation/mount_option_set.spec.yaml) | `runner/handlers/remediation/_system.py` → `_remediate_mount_option_set` | `tests/test_engine_remediation.py` | **Active** — 9 ACs |
| [grub_parameter_set](handlers/remediation/grub_parameter_set.spec.yaml) | `runner/handlers/remediation/_system.py` → `_remediate_grub_parameter_set` | `tests/test_engine_remediation.py` | **Active** — 7 ACs |
| [grub_parameter_remove](handlers/remediation/grub_parameter_remove.spec.yaml) | `runner/handlers/remediation/_system.py` → `_remediate_grub_parameter_remove` | `tests/test_engine_remediation.py` | **Active** — 5 ACs |
| [cron_job](handlers/remediation/cron_job.spec.yaml) | `runner/handlers/remediation/_system.py` → `_remediate_cron_job` | `tests/test_engine_remediation.py` | **Active** — 8 ACs |
| [selinux_boolean_set](handlers/remediation/selinux_boolean_set.spec.yaml) | `runner/handlers/remediation/_security.py` → `_remediate_selinux_boolean_set` | `tests/test_engine_remediation.py` | **Active** — 11 ACs |
| [selinux_state_set](handlers/remediation/selinux_state_set.spec.yaml) | `runner/handlers/remediation/_security.py` → `_remediate_selinux_state_set` | `tests/test_engine_remediation.py` | **Active** — 6 ACs |
| [command_exec](handlers/remediation/command_exec.spec.yaml) | `runner/handlers/remediation/_command.py` → `_remediate_command_exec` | `tests/test_engine_remediation.py` | **Active** — 11 ACs |
| [manual](handlers/remediation/manual.spec.yaml) | `runner/handlers/remediation/_command.py` → `_remediate_manual` | `tests/test_engine_remediation.py` | **Active** — 6 ACs |

## Orchestration

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [evaluate_rule](orchestration/evaluate_rule.spec.yaml) | `runner/_orchestration.py` → `evaluate_rule` | `tests/test_orchestration_evaluate.py` → `TestEvaluateRuleSpecDerived`, `TestExtractFrameworkRefs` | **Active** — 14 ACs, 30 tests |
| [remediate_rule](orchestration/remediate_rule.spec.yaml) | `runner/_orchestration.py` → `remediate_rule` | `tests/test_orchestration_remediate.py` → `TestRemediateRuleSpecDerived` | **Active** — 15 ACs, 23 tests |
| [rollback](orchestration/rollback.spec.yaml) | `runner/handlers/rollback/__init__.py` → `_execute_rollback`; `runner/_orchestration.py` → `rollback_from_stored` | `tests/test_orchestration_rollback.py` → `TestExecuteRollbackSpecDerived`, `TestRollbackFromStoredSpecDerived` | **Active** — 15 ACs, 22 tests |
| [host_runner](orchestration/host_runner.spec.yaml) | `runner/_host_runner.py` → `run_host` | `tests/test_host_runner_spec.py` → `TestHostRunnerSpecDerived` | **Active** — 12 ACs, 13 tests |

## CLI Commands

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [check](cli/check.spec.yaml) | `runner/cli.py` → `check()` | `tests/test_cli_spec.py` → `TestCheckSpecDerived` | **Active** — 19 ACs, 15 tests |
| [remediate](cli/remediate.spec.yaml) | `runner/cli.py` → `remediate()` | `tests/test_cli_spec.py` → `TestRemediateSpecDerived` | **Active** — 22 ACs, 16 tests |
| [detect](cli/detect.spec.yaml) | `runner/cli.py` → `detect()` | `tests/test_cli_spec.py` → `TestDetectSpecDerived` | **Active** — 8 ACs, 8 tests |
| [rollback](cli/rollback.spec.yaml) | `runner/cli.py` → `rollback()` | `tests/test_cli_spec.py` → `TestRollbackSpecDerived` | **Active** — 19 ACs, 13 tests |
| [history](cli/history.spec.yaml) | `runner/cli.py` → `history()` | `tests/test_cli_spec.py` → `TestHistorySpecDerived` | **Active** — 11 ACs, 9 tests |
| [diff](cli/diff.spec.yaml) | `runner/cli.py` → `diff()` | `tests/test_cli_spec.py` → `TestDiffSpecDerived` | **Active** — 10 ACs, 7 tests |
| [coverage](cli/coverage.spec.yaml) | `runner/cli.py` → `coverage()` | `tests/test_cli_spec.py` → `TestCoverageSpecDerived` | **Active** — 8 ACs, 8 tests |
| [list-frameworks](cli/list_frameworks.spec.yaml) | `runner/cli.py` → `list_frameworks()` | `tests/test_cli_spec.py` → `TestListFrameworksSpecDerived` | **Active** — 5 ACs, 6 tests |
| [info](cli/info.spec.yaml) | `runner/cli.py` → `info()` | `tests/test_cli_spec.py` → `TestInfoSpecDerived` | **Active** — 15 ACs, 15 tests |

## Data

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [result_store](data/result_store.spec.yaml) | `runner/storage.py` → `ResultStore` | `tests/test_storage_spec.py` → `TestResultStoreSpecDerived` | **Active** — 18 ACs, 18 tests |

## System

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [system](system.spec.yaml) | `runner/` → system-level context | `tests/spec/test_system_spec.py` → `TestSystemSpecDerived` | **Active** — 6 ACs |

## Internal Modules

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [variable_resolution](internal/variable_resolution.spec.yaml) | `runner/_config.py` → `load_config`, `resolve_variables`, `parse_var_overrides` | `tests/test_variable_resolution_spec.py` → `TestVariableResolutionSpecDerived` | **Active** — 14 ACs, 15 tests |
| [framework_mappings](internal/framework_mappings.spec.yaml) | `runner/mappings.py` → `FrameworkMapping`, `FrameworkIndex` | `tests/test_framework_mappings_spec.py` → `TestFrameworkMappingsSpecDerived` | **Active** — 12 ACs, 12 tests |
| [detect_capability](internal/detect_capability.spec.yaml) | `runner/detect.py` → `detect_platform`, `detect_capabilities` | `tests/test_detect_capability_spec.py` → `TestDetectCapabilitySpecDerived` | **Active** — 10 ACs, 10 tests |
| [host_resolution](internal/host_resolution.spec.yaml) | `runner/inventory.py` → `resolve_targets` | `tests/test_host_resolution_spec.py` → `TestHostResolutionSpecDerived` | **Active** — 10 ACs, 10 tests |
| [rule_loading](internal/rule_loading.spec.yaml) | `runner/_loading.py` → `load_rules` | `tests/test_rule_loading_spec.py` → `TestRuleLoadingSpecDerived` | **Active** — 10 ACs, 10 tests |
| [risk_classification](internal/risk_classification.spec.yaml) | `runner/risk.py` → `classify_step_risk`, `should_capture` | `tests/test_risk_classification_spec.py` → `TestRiskClassificationSpecDerived` | **Active** — 10 ACs, 10 tests |
| [rule_ordering](internal/rule_ordering.spec.yaml) | `runner/ordering.py` → `order_rules` | `tests/test_rule_ordering_spec.py` → `TestRuleOrderingSpecDerived` | **Active** — 10 ACs, 10 tests |
| [ssh_session](internal/ssh_session.spec.yaml) | `runner/ssh.py` → `SSHSession` | `tests/test_ssh_session_spec.py` → `TestSSHSessionSpecDerived` | **Active** — 11 ACs, 11 tests |
| [output_formatter](internal/output_formatter.spec.yaml) | `runner/output/` → `write_output` | `tests/test_output_formatter_spec.py` → `TestOutputFormatterSpecDerived` | **Active** — 12 ACs, 12 tests |
| [rule_selection](internal/rule_selection.spec.yaml) | `runner/_rule_selection.py` → `select_rules` | `tests/test_rule_selection_spec.py` → `TestRuleSelectionSpecDerived` | **Active** — 10 ACs, 10 tests |
| [shell_util](internal/shell_util.spec.yaml) | `runner/shell_util.py` | `tests/test_shell_util_spec.py` → `TestShellUtilSpecDerived` | **Active** — 10 ACs, 10 tests |
| [path_resolution](internal/path_resolution.spec.yaml) | `runner/` → path resolution logic | `tests/spec/internal/test_path_resolution_spec.py` → `TestPathResolutionSpecDerived` | **Draft** — 7 ACs |
| [run_diagnostics](internal/run_diagnostics.spec.yaml) | `runner/` → diagnostic routines | `tests/spec/internal/test_run_diagnostics_spec.py` → `TestRunDiagnosticsSpecDerived` | **Draft** — 18 ACs |
| [security](internal/security.spec.yaml) | `runner/` → security posture analysis | `tests/spec/internal/test_security_spec.py` → `TestSecuritySpecDerived` | **Active** — 10 ACs |
| [e2e_result_storage](internal/e2e_result_storage.spec.yaml) | `runner/storage.py` → E2E result storage flows | `tests/spec/internal/test_e2e_result_storage_spec.py` → `TestE2eResultStorageSpecDerived` | **Active** — 12 ACs |

## Handlers — Capture

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [capture_config](handlers/capture/config.spec.yaml) | `runner/handlers/capture/_config.py` | `tests/test_capture_config_spec.py` → `TestCaptureConfigSpecDerived` | **Active** — 8 ACs, 8 tests |
| [capture_file](handlers/capture/file.spec.yaml) | `runner/handlers/capture/_file.py` | `tests/test_capture_file_spec.py` → `TestCaptureFileSpecDerived` | **Active** — 8 ACs, 8 tests |
| [capture_package](handlers/capture/package.spec.yaml) | `runner/handlers/capture/_package.py` | `tests/test_capture_package_spec.py` → `TestCapturePackageSpecDerived` | **Active** — 5 ACs, 5 tests |
| [capture_service](handlers/capture/service.spec.yaml) | `runner/handlers/capture/_service.py` | `tests/test_capture_service_spec.py` → `TestCaptureServiceSpecDerived` | **Active** — 7 ACs, 7 tests |
| [capture_system](handlers/capture/system.spec.yaml) | `runner/handlers/capture/_system.py` | `tests/test_capture_system_spec.py` → `TestCaptureSystemSpecDerived` | **Active** — 8 ACs, 8 tests |
| [capture_security](handlers/capture/security.spec.yaml) | `runner/handlers/capture/_security.py` | `tests/test_capture_security_spec.py` → `TestCaptureSecuritySpecDerived` | **Active** — 7 ACs, 7 tests |
| [capture_command](handlers/capture/command.spec.yaml) | `runner/handlers/capture/_command.py` | `tests/test_capture_command_spec.py` → `TestCaptureCommandSpecDerived` | **Active** — 4 ACs, 4 tests |

## Handlers — Rollback

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [rollback_config](handlers/rollback/config.spec.yaml) | `runner/handlers/rollback/_config.py` | `tests/test_rollback_config_spec.py` → `TestRollbackConfigSpecDerived` | **Active** — 10 ACs, 10 tests |
| [rollback_file](handlers/rollback/file.spec.yaml) | `runner/handlers/rollback/_file.py` | `tests/test_rollback_file_spec.py` → `TestRollbackFileSpecDerived` | **Active** — 8 ACs, 8 tests |
| [rollback_package](handlers/rollback/package.spec.yaml) | `runner/handlers/rollback/_package.py` | `tests/test_rollback_package_spec.py` → `TestRollbackPackageSpecDerived` | **Active** — 6 ACs, 6 tests |
| [rollback_service](handlers/rollback/service.spec.yaml) | `runner/handlers/rollback/_service.py` | `tests/test_rollback_service_spec.py` → `TestRollbackServiceSpecDerived` | **Active** — 7 ACs, 7 tests |
| [rollback_system](handlers/rollback/system.spec.yaml) | `runner/handlers/rollback/_system.py` | `tests/test_rollback_system_spec.py` → `TestRollbackSystemSpecDerived` | **Active** — 8 ACs, 8 tests |
| [rollback_security](handlers/rollback/security.spec.yaml) | `runner/handlers/rollback/_security.py` | `tests/test_rollback_security_spec.py` → `TestRollbackSecuritySpecDerived` | **Active** — 8 ACs, 8 tests |
| [rollback_command](handlers/rollback/command.spec.yaml) | `runner/handlers/rollback/_command.py` | `tests/test_rollback_command_spec.py` → `TestRollbackCommandSpecDerived` | **Active** — 4 ACs, 4 tests |

## Legend

- **Active** — Spec written, tests mapped, all ACs covered
- **Draft** — Spec written, test gaps remain
- **Planned** — Spec not yet written
