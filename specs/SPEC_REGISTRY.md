# Spec Registry

Index of behavioral specifications, linking each spec to its source code, test coverage, and status.

## Handlers — Checks

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [config_value](handlers/checks/config_value.spec.md) | `runner/handlers/checks/_config.py` → `_check_config_value` | `tests/test_engine_checks.py` → `TestConfigValue`, `TestConfigValueComparator`, `TestConfigValueSpecDerived` | **Active** — 14 ACs, 14 tests |
| [sshd_effective_config](handlers/checks/sshd_effective_config.spec.md) | `runner/handlers/checks/_ssh.py` → `_check_sshd_effective_config` | `tests/test_engine_checks.py` → `TestSshdEffectiveConfig`, `TestSshdEffectiveConfigSpecDerived` | **Active** — 13 ACs, 13 tests |
| [file_permission](handlers/checks/file_permission.spec.md) | `runner/handlers/checks/_file.py` → `_check_file_permission` | `tests/test_engine_checks.py` → `TestFilePermission`, `TestFilePermissionSpecDerived` | **Active** — 17 ACs, 19 tests |
| [service_state](handlers/checks/service_state.spec.md) | `runner/handlers/checks/_service.py` → `_check_service_state` | `tests/test_engine_checks.py` → `TestServiceState`, `TestServiceStateSpecDerived` | **Active** — 18 ACs, 18 tests |
| [command](handlers/checks/command.spec.md) | `runner/handlers/checks/_command.py` → `_check_command` | `tests/test_engine_checks.py` → `TestCommand`, `TestCommandSpecDerived` | **Active** — 18 ACs, 29 tests |

## Handlers — Remediation

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [config_set](handlers/remediation/config_set.spec.md) | `runner/handlers/remediation/_config.py` → `_remediate_config_set` | `tests/test_engine_remediation.py` → `TestConfigSet`, `TestConfigSetSpecDerived` | **Active** — 12 ACs, 17 tests |
| [pam_module_configure](handlers/remediation/pam_module_configure.spec.md) | `runner/handlers/remediation/_security.py` → `_remediate_pam_module_configure` | `tests/test_engine_remediation.py` → `TestPamModuleConfigureSpecDerived` | **Active** — 11 ACs, 13 tests |
| [service_lifecycle](handlers/remediation/service_lifecycle.spec.md) | `runner/handlers/remediation/_service.py` → `_remediate_service_enabled`, `_remediate_service_disabled` | `tests/test_service_lifecycle.py` → `TestServiceEnabledSpecDerived`, `TestServiceDisabledSpecDerived` | **Active** — 14 ACs, 22 tests |
| [sysctl_set](handlers/remediation/sysctl_set.spec.md) | `runner/handlers/remediation/_system.py` → `_remediate_sysctl_set` | `tests/test_engine_remediation.py` → `TestSysctlSet`, `TestSysctlSetSpecDerived` | **Active** — 9 ACs, 15 tests |
| [audit_rule_set](handlers/remediation/audit_rule_set.spec.md) | `runner/handlers/remediation/_security.py` → `_remediate_audit_rule_set` | `tests/test_remediation_audit_rule_set.py` → `TestAuditRuleSetSpecDerived` | **Active** — 9 ACs, 16 tests |

## Orchestration

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [evaluate_rule](orchestration/evaluate_rule.spec.md) | `runner/_orchestration.py` → `evaluate_rule` | `tests/test_orchestration_evaluate.py` → `TestEvaluateRuleSpecDerived`, `TestExtractFrameworkRefs` | **Active** — 14 ACs, 30 tests |
| [remediate_rule](orchestration/remediate_rule.spec.md) | `runner/_orchestration.py` → `remediate_rule` | `tests/test_orchestration_remediate.py` → `TestRemediateRuleSpecDerived` | **Active** — 15 ACs, 23 tests |
| [rollback](orchestration/rollback.spec.md) | `runner/handlers/rollback/__init__.py` → `_execute_rollback`; `runner/_orchestration.py` → `rollback_from_stored` | `tests/test_orchestration_rollback.py` → `TestExecuteRollbackSpecDerived`, `TestRollbackFromStoredSpecDerived` | **Active** — 15 ACs, 22 tests |

## CLI Commands

| Spec | Source | Tests | Status |
|------|--------|-------|--------|
| [check](cli/check.spec.md) | `runner/cli.py` → `check()` | `tests/test_cli_spec.py` → `TestCheckSpecDerived` | **Active** — 18 ACs, 14 tests |
| [remediate](cli/remediate.spec.md) | `runner/cli.py` → `remediate()` | `tests/test_cli_spec.py` → `TestRemediateSpecDerived` | **Active** — 20 ACs, 15 tests |
| [detect](cli/detect.spec.md) | `runner/cli.py` → `detect()` | `tests/test_cli_spec.py` → `TestDetectSpecDerived` | **Active** — 8 ACs, 8 tests |
| [rollback](cli/rollback.spec.md) | `runner/cli.py` → `rollback()` | `tests/test_cli_spec.py` → `TestRollbackSpecDerived` | **Active** — 18 ACs, 12 tests |
| [history](cli/history.spec.md) | `runner/cli.py` → `history()` | `tests/test_cli_spec.py` → `TestHistorySpecDerived` | **Active** — 12 ACs, 10 tests |
| [diff](cli/diff.spec.md) | `runner/cli.py` → `diff()` | `tests/test_cli_spec.py` → `TestDiffSpecDerived` | **Active** — 10 ACs, 7 tests |

## Legend

- **Active** — Spec written, tests mapped, all ACs covered
- **Draft** — Spec written, test gaps remain
- **Planned** — Spec not yet written
