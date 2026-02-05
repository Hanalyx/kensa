# Architecture

## Data Flow

```
CLI flags (--host, --inventory, --rules, --sudo, ...)
    │
    ▼
┌─────────────┐     ┌──────────────┐
│ inventory.py │────▶│ list[HostInfo]│
└─────────────┘     └──────┬───────┘
                           │
                    for each host:
                           │
                    ┌──────▼───────┐
                    │   ssh.py     │
                    │ SSHSession   │──── paramiko ────▶ remote host
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  detect.py   │
                    │ 22 probes    │──▶ dict[str, bool] (capabilities)
                    └──────┬───────┘
                           │
               ┌───────────▼────────────┐
               │      engine.py         │
               │                        │
               │  load_rules(path)      │◀── rules/*.yml
               │         │              │
               │  select_implementation │◀── capabilities
               │         │              │
               │  run_check / run_      │
               │  remediation           │──▶ SSHSession.run()
               │         │              │
               │  RuleResult            │
               └───────────┬────────────┘
                           │
                    ┌──────▼───────┐
                    │   cli.py     │
                    │ rich output  │──▶ terminal
                    └──────────────┘
```

## Component Responsibilities

### ssh.py — Transport Layer
- Single class: `SSHSession`
- One TCP connection per host, reused for all commands
- `run(cmd)` returns `Result(exit_code, stdout, stderr)`
- Transparent `sudo -n sh -c` wrapping when `--sudo` is set
- Context manager for clean connection lifecycle

### inventory.py — Target Resolution
- Three input sources: `--host` (comma-separated), Ansible inventory (INI/YAML), plain text host list
- Auto-detects format by file extension and content
- Outputs `list[HostInfo]` with per-host connection parameters
- `--limit` filters by group name or hostname glob
- CLI defaults (`--user`, `--key`, `--port`) are fallbacks; inventory per-host vars override them (Ansible precedence model)

### detect.py — Capability Detection
- Dictionary of probe name → shell command
- Each probe: exit 0 = capability present
- Runs all probes sequentially on each host
- Results feed into `select_implementation()` for rule evaluation
- Probes are read-only and side-effect free

### engine.py — Rule Engine (re-export facade + sub-modules)
`engine.py` is a thin re-export facade. All logic lives in underscore-prefixed sub-modules under `runner/`:
- **`_types.py`:** Result dataclasses — `CheckResult`, `PreState`, `StepResult`, `RollbackResult`, `RuleResult`
- **`_loading.py`:** YAML files from a single file or directory (recursive), with optional severity/tag/category/platform filters
- **`_selection.py`:** `evaluate_when()` and `select_implementation()` — capability gate evaluation, first match wins, falls back to `default: true`
- **`_checks.py`:** `run_check()` dispatches to typed handlers, supports multi-condition checks (AND semantics via `checks:` list)
- **`_remediation.py`:** `run_remediation()` dispatches to typed handlers, supports multi-step (sequential via `steps:` list), respects `dry_run`, handles `unless`/`onlyif` guards; also owns `_reload_service()`
- **`_capture.py`:** Pre-state capture handlers — snapshot host state before remediation for rollback support
- **`_rollback.py`:** Rollback handlers — restore host to pre-remediation state; `_execute_rollback()` processes steps in reverse
- **`_orchestration.py`:** `evaluate_rule()` and `remediate_rule()` — top-level rule evaluation and remediation with re-check and rollback-on-failure

All public imports go through `from runner.engine import ...` for backward compatibility.

### cli.py — User Interface
- Three subcommands: `detect`, `check`, `remediate`
- Shared option decorators for target and rule selection
- Sequential host iteration (parallel is P1)
- Rich console output with color-coded PASS/FAIL/FIXED/SKIP
- `--verbose` shows capability detection and implementation selection
- Per-host summaries and cross-host totals


## Design Decisions

### Why No SFTP
SSH commands are sufficient for all operations (grep, stat, echo, sed, sysctl, rpm, etc.). SFTP adds complexity (file handle management, partial transfer recovery) for no benefit. The rule format's remediation mechanisms are all expressible as shell commands.

### Why Capabilities Instead of OS Version Checks
The same RHEL 9 host might have authselect or not depending on how it was provisioned. Checking the actual host state (is the .d directory present? is authselect active?) is more reliable than assuming based on version. This also handles derivatives (CentOS, Rocky, Alma) without needing a version mapping table.

### Why Sequential Host Execution (V0)
Simplicity. Parallel execution requires connection pooling, output interleaving, error isolation, and progress reporting — all solvable but not needed to validate the core check/remediate loop. P1 will add `concurrent.futures.ThreadPoolExecutor`.

### Why One Connection Per Host
SSH connection setup is expensive (~1s with key exchange). Reusing one connection for all probes + checks + remediations on a host avoids repeated handshakes. The `SSHSession` context manager ensures cleanup.

### Why Per-Rule Error Handling
A single failing rule (bad command, unexpected output) shouldn't abort the entire scan. Each rule evaluation is wrapped in try/except, producing a `RuleResult` with error detail. The CLI prints all results and summaries regardless of individual failures.

### Why sudo Is a Global Flag
Compliance checks require reading sensitive files (`/etc/ssh/sshd_config`, `/etc/shadow`) and remediations require writing to them. It's impractical to determine which commands need sudo per-rule. A global `--sudo` flag matches Ansible's `become: yes` model: either you have privilege escalation or you don't.
