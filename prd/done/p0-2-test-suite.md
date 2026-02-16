# P0-2: Test Suite (DONE)

## Status: Complete

## Goal
Comprehensive test coverage for the runner package. Tests must run without SSH access to real hosts — mock the SSH layer.

## Results
- 164 tests, all passing
- Covers: SSH session, inventory parsing, capability detection, platform detection, rule loading/filtering, all 7 check handlers, all 8 remediation handlers, implementation selection, platform filtering, CLI integration
- All tests run without SSH access using MockSSHSession

## Structure

```
tests/
  conftest.py               # Shared fixtures: mock SSHSession, sample rules, sample capabilities
  test_ssh.py               # SSHSession unit tests (connection args, sudo wrapping, result parsing)
  test_inventory.py          # Target resolution: all three formats + --limit filtering
  test_detect.py             # Capability probe structure validation + mock execution + platform detection
  test_engine_loading.py     # Rule loading, filtering, implementation selection, platform filtering
  test_engine_checks.py      # Every check handler against mock SSH responses
  test_engine_remediation.py # Every remediation handler (dry-run + real), service reload
  test_cli.py                # CLI integration: Click test runner, output format verification, platform skip
```

## Acceptance Criteria

### test_ssh.py
- [x] `SSHSession.__init__` stores all parameters
- [x] `run()` without sudo sends command verbatim
- [x] `run()` with sudo wraps as `sudo -n sh -c '<cmd>'`
- [x] Sudo wrapping handles commands with single quotes, double quotes, pipes, semicolons
- [x] `Result.ok` returns True for exit_code=0, False otherwise
- [x] Context manager calls `connect()` and `close()`

### test_inventory.py
- [x] `--host` single host
- [x] `--host` comma-separated multiple hosts
- [x] `--host` with port (`host:2222`)
- [x] Ansible INI: groups, host vars (ansible_host, ansible_user, ansible_port, ansible_ssh_private_key_file)
- [x] Ansible INI: host in multiple groups
- [x] Ansible YAML: all.children.{group}.hosts structure
- [ ] Ansible YAML: nested children
- [x] Plain text host list (one per line, comments, blank lines)
- [x] Auto-detection: .yml → YAML, [group] headers → INI, else plain text
- [x] `--limit` by group name
- [x] `--limit` by hostname glob
- [x] `--limit` matching nothing raises ValueError
- [x] CLI defaults applied when inventory doesn't set per-host values
- [x] Inventory per-host vars override CLI defaults
- [x] No hosts specified raises ValueError

### test_detect.py
- [x] All 22 probes are defined in CAPABILITY_PROBES
- [x] All probe names are valid identifiers (lowercase, underscores)
- [x] `detect_capabilities()` returns dict with all probe names as keys
- [x] Probe returning exit 0 → True, non-zero → False
- [ ] Verbose mode prints failed probes to stderr

### test_engine_loading.py
- [x] Load single YAML file
- [x] Load directory recursively (finds all .yml/.yaml)
- [x] Skip non-rule YAML files (no `id` field)
- [x] Skip malformed YAML (parse error)
- [x] Filter by severity (single and multiple)
- [x] Filter by tag (single and multiple, OR semantics)
- [x] Filter by category
- [x] Combined filters (AND across filter types)
- [x] No path raises ValueError

### test_engine_checks.py (per handler)
- [x] `config_value`: key found with correct value → PASS
- [x] `config_value`: key found with wrong value → FAIL with actual vs expected
- [x] `config_value`: key not found → FAIL
- [x] `config_value`: directory mode with scan_pattern
- [x] `config_value`: handles key=value and key value and key = value separators
- [x] `file_permission`: correct owner/group/mode → PASS
- [x] `file_permission`: wrong owner → FAIL with detail
- [x] `file_permission`: glob path expands to multiple files, all checked
- [x] `file_permission`: file not found → FAIL
- [x] `command`: exit code matches expected → PASS
- [x] `command`: exit code mismatch → FAIL
- [x] `command`: expected_stdout checked when present
- [x] `sysctl_value`: matching value → PASS
- [x] `sysctl_value`: mismatching value → FAIL with actual
- [x] `kernel_module_state`: blacklisted and not loaded → PASS
- [x] `kernel_module_state`: loaded when should be blacklisted → FAIL
- [x] `kernel_module_state`: not blacklisted → FAIL
- [x] `package_state`: present and installed → PASS
- [x] `package_state`: present but not installed → FAIL
- [x] `package_state`: absent and not installed → PASS
- [x] `file_exists`: file exists → PASS
- [x] `file_exists`: file missing → FAIL
- [x] Multi-condition check: all pass → PASS
- [x] Multi-condition check: first fails → FAIL (short-circuit)
- [x] Unknown check method → FAIL with detail

### test_engine_remediation.py (per handler)
- [x] `config_set`: dry_run returns description
- [x] `config_set`: replaces existing key in file
- [x] `config_set`: appends when key not found
- [x] `config_set`: calls reload service when specified
- [x] `config_set_dropin`: writes to correct path
- [x] `command_exec`: unless guard skips when true
- [x] `command_exec`: onlyif guard skips when false
- [x] `command_exec`: dry_run returns command description
- [x] `file_permissions`: sets owner, group, mode
- [x] `file_permissions`: glob path not quoted
- [x] `sysctl_set`: applies and persists
- [x] `package_present`: calls dnf install
- [x] `kernel_module_disable`: writes blacklist conf and unloads
- [x] `manual`: returns False with note
- [x] Multi-step remediation: executes sequentially, stops on failure
- [x] Unknown mechanism → failure with detail
- [x] `evaluate_rule()` + `remediate_rule()` full cycle: check → fail → remediate → re-check → pass

### test_engine_selection.py (implemented in test_engine_loading.py)
- [x] `evaluate_when(None, caps)` → True
- [x] `evaluate_when("cap_name", caps)` → True when present
- [x] `evaluate_when("cap_name", caps)` → False when absent
- [x] `evaluate_when({"all": [...]}, caps)` → True when all present
- [x] `evaluate_when({"all": [...]}, caps)` → False when any absent
- [x] `evaluate_when({"any": [...]}, caps)` → True when any present
- [x] `evaluate_when({"any": [...]}, caps)` → False when all absent
- [x] `select_implementation()` picks first matching gate
- [x] `select_implementation()` falls back to default when no gates match
- [x] `select_implementation()` returns None when no implementations

### test_cli.py
- [ ] `detect` subcommand runs and produces table output
- [x] `check` subcommand shows PASS/FAIL with rule counts
- [x] `remediate` subcommand with `--dry-run` shows DRY prefix
- [x] `--verbose` flag produces capability and implementation lines
- [x] Missing `--host` and `--inventory` exits with error
- [x] Missing `--rules` and `--rule` exits with error
- [x] `--severity`, `--tag`, `--category` filters applied

## Technical Approach

### Mock SSH Layer
Create a `MockSSHSession` that takes a dict mapping commands (or command patterns) to `Result` objects. Inject it in place of real SSH connections.

```python
class MockSSHSession:
    def __init__(self, responses: dict[str, Result]):
        self.responses = responses
        self.commands_run: list[str] = []

    def run(self, cmd, *, timeout=None):
        self.commands_run.append(cmd)
        for pattern, result in self.responses.items():
            if pattern in cmd:
                return result
        return Result(exit_code=1, stdout="", stderr="command not mocked")
```

### Test Runner
Use pytest. No external dependencies beyond what's already installed.

```bash
pip install pytest
pytest tests/ -v
```

### Fixtures (conftest.py)
- `mock_ssh`: MockSSHSession factory
- `sample_caps`: dict of capabilities with common RHEL 9 profile
- `sample_rule`: a minimal single-implementation rule dict
- `sample_rule_gated`: a rule with when gate + default
- `tmp_rule_file`: writes a rule to a temp file, returns path
- `tmp_rule_dir`: writes multiple rules to a temp directory
