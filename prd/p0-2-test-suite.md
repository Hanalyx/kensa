# P0-2: Test Suite

## Status: Not Started

## Goal
Comprehensive test coverage for the runner package. Tests must run without SSH access to real hosts — mock the SSH layer.

## Structure

```
tests/
  conftest.py               # Shared fixtures: mock SSHSession, sample rules, sample capabilities
  test_ssh.py               # SSHSession unit tests (connection args, sudo wrapping, result parsing)
  test_inventory.py          # Target resolution: all three formats + --limit filtering
  test_detect.py             # Capability probe structure validation + mock execution
  test_engine_loading.py     # Rule loading, filtering, implementation selection
  test_engine_checks.py      # Every check handler against mock SSH responses
  test_engine_remediation.py # Every remediation handler (dry-run + real), service reload
  test_cli.py                # CLI integration: Click test runner, output format verification
```

## Acceptance Criteria

### test_ssh.py
- [ ] `SSHSession.__init__` stores all parameters
- [ ] `run()` without sudo sends command verbatim
- [ ] `run()` with sudo wraps as `sudo -n sh -c '<cmd>'`
- [ ] Sudo wrapping handles commands with single quotes, double quotes, pipes, semicolons
- [ ] `Result.ok` returns True for exit_code=0, False otherwise
- [ ] Context manager calls `connect()` and `close()`

### test_inventory.py
- [ ] `--host` single host
- [ ] `--host` comma-separated multiple hosts
- [ ] `--host` with port (`host:2222`)
- [ ] Ansible INI: groups, host vars (ansible_host, ansible_user, ansible_port, ansible_ssh_private_key_file)
- [ ] Ansible INI: host in multiple groups
- [ ] Ansible YAML: all.children.{group}.hosts structure
- [ ] Ansible YAML: nested children
- [ ] Plain text host list (one per line, comments, blank lines)
- [ ] Auto-detection: .yml → YAML, [group] headers → INI, else plain text
- [ ] `--limit` by group name
- [ ] `--limit` by hostname glob
- [ ] `--limit` matching nothing raises ValueError
- [ ] CLI defaults applied when inventory doesn't set per-host values
- [ ] Inventory per-host vars override CLI defaults
- [ ] No hosts specified raises ValueError

### test_detect.py
- [ ] All 22 probes are defined in CAPABILITY_PROBES
- [ ] All probe names are valid identifiers (lowercase, underscores)
- [ ] `detect_capabilities()` returns dict with all probe names as keys
- [ ] Probe returning exit 0 → True, non-zero → False
- [ ] Verbose mode prints failed probes to stderr

### test_engine_loading.py
- [ ] Load single YAML file
- [ ] Load directory recursively (finds all .yml/.yaml)
- [ ] Skip non-rule YAML files (no `id` field)
- [ ] Skip malformed YAML (parse error)
- [ ] Filter by severity (single and multiple)
- [ ] Filter by tag (single and multiple, OR semantics)
- [ ] Filter by category
- [ ] Combined filters (AND across filter types)
- [ ] No path raises ValueError

### test_engine_checks.py (per handler)
- [ ] `config_value`: key found with correct value → PASS
- [ ] `config_value`: key found with wrong value → FAIL with actual vs expected
- [ ] `config_value`: key not found → FAIL
- [ ] `config_value`: directory mode with scan_pattern
- [ ] `config_value`: handles key=value and key value and key = value separators
- [ ] `file_permission`: correct owner/group/mode → PASS
- [ ] `file_permission`: wrong owner → FAIL with detail
- [ ] `file_permission`: glob path expands to multiple files, all checked
- [ ] `file_permission`: file not found → FAIL
- [ ] `command`: exit code matches expected → PASS
- [ ] `command`: exit code mismatch → FAIL
- [ ] `command`: expected_stdout checked when present
- [ ] `sysctl_value`: matching value → PASS
- [ ] `sysctl_value`: mismatching value → FAIL with actual
- [ ] `kernel_module_state`: blacklisted and not loaded → PASS
- [ ] `kernel_module_state`: loaded when should be blacklisted → FAIL
- [ ] `kernel_module_state`: not blacklisted → FAIL
- [ ] `package_state`: present and installed → PASS
- [ ] `package_state`: present but not installed → FAIL
- [ ] `package_state`: absent and not installed → PASS
- [ ] `file_exists`: file exists → PASS
- [ ] `file_exists`: file missing → FAIL
- [ ] Multi-condition check: all pass → PASS
- [ ] Multi-condition check: first fails → FAIL (short-circuit)
- [ ] Unknown check method → FAIL with detail

### test_engine_remediation.py (per handler)
- [ ] `config_set`: dry_run returns description
- [ ] `config_set`: replaces existing key in file
- [ ] `config_set`: appends when key not found
- [ ] `config_set`: calls reload service when specified
- [ ] `config_set_dropin`: writes to correct path
- [ ] `command_exec`: unless guard skips when true
- [ ] `command_exec`: onlyif guard skips when false
- [ ] `command_exec`: dry_run returns command description
- [ ] `file_permissions`: sets owner, group, mode
- [ ] `file_permissions`: glob path not quoted
- [ ] `sysctl_set`: applies and persists
- [ ] `package_present`: calls dnf install
- [ ] `kernel_module_disable`: writes blacklist conf and unloads
- [ ] `manual`: returns False with note
- [ ] Multi-step remediation: executes sequentially, stops on failure
- [ ] Unknown mechanism → failure with detail
- [ ] `evaluate_rule()` + `remediate_rule()` full cycle: check → fail → remediate → re-check → pass

### test_engine_selection.py
- [ ] `evaluate_when(None, caps)` → True
- [ ] `evaluate_when("cap_name", caps)` → True when present
- [ ] `evaluate_when("cap_name", caps)` → False when absent
- [ ] `evaluate_when({"all": [...]}, caps)` → True when all present
- [ ] `evaluate_when({"all": [...]}, caps)` → False when any absent
- [ ] `evaluate_when({"any": [...]}, caps)` → True when any present
- [ ] `evaluate_when({"any": [...]}, caps)` → False when all absent
- [ ] `select_implementation()` picks first matching gate
- [ ] `select_implementation()` falls back to default when no gates match
- [ ] `select_implementation()` returns None when no implementations

### test_cli.py
- [ ] `detect` subcommand runs and produces table output
- [ ] `check` subcommand shows PASS/FAIL with rule counts
- [ ] `remediate` subcommand with `--dry-run` shows DRY prefix
- [ ] `--verbose` flag produces capability and implementation lines
- [ ] Missing `--host` and `--inventory` exits with error
- [ ] Missing `--rules` and `--rule` exits with error
- [ ] `--severity`, `--tag`, `--category` filters applied

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
