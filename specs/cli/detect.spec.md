# Spec: detect CLI Command

## Context
- **Module:** `runner/cli.py` → `detect()`
- **Click decorators:** `@main.command()`, `@target_options`
- **Option groups:** target_options (--host, --inventory, --limit, --user, --key, --password, --port, --verbose, --sudo, --strict-host-keys, --capability, --workers)
- **Dependencies:** `runner._host_runner` (connect, detect_platform, detect_capabilities, apply_capability_overrides), `runner.inventory` (resolve_targets)

## Objective
Probe capabilities on one or more remote hosts over SSH. Display platform info and a table of detected capabilities per host, with optional capability overrides.

### Input Contract

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--host / -h` | `str` | No* | `None` | Comma-separated host list |
| `--inventory / -i` | `str` | No* | `None` | Inventory file path |
| `--limit / -l` | `str` | No | `None` | Host glob pattern |
| `--user / -u` | `str` | No | `None` | SSH username |
| `--key / -k` | `str` | No | `None` | SSH private key path |
| `--password / -p` | `str` | No | `None` | SSH password |
| `--port / -P` | `int` | No | `22` | SSH port |
| `--verbose / -v` | `bool` | No | `False` | Show capability detection detail |
| `--sudo` | `bool` | No | `False` | Run commands via sudo |
| `--strict-host-keys / --no-strict-host-keys` | `bool` | No | `False` | Verify SSH host keys |
| `--capability / -C` | `str (multiple)` | No | `()` | Capability overrides `KEY=VALUE` |
| `--workers / -w` | `int (1-50)` | No | `1` | Parallel SSH connections |

\* At least one of `--host` or `--inventory` must resolve to targets (or auto-discovery must succeed).

### Behavior

1. Resolve target hosts via `_resolve_hosts(host, inventory, limit, user, key, port)`.
2. Parse capability overrides from `-C` flags via `_parse_capability_overrides()`.
3. If `workers == 1`: iterate hosts sequentially, printing directly to console.
4. If `workers > 1`: use `ThreadPoolExecutor` with buffered output, printing results under a lock.
5. For each host:
   a. Print host header rule.
   b. Open SSH connection via `connect()`.
   c. Detect platform via `detect_platform()`.
   d. Detect capabilities via `detect_capabilities()`.
   e. Apply overrides via `apply_capability_overrides()`.
   f. Print platform info.
   g. Print capability table sorted by name, marking overrides in magenta.
6. On connection failure: print error message, continue to next host.

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Always — even when connection failures occur |
| 1 | Only for target resolution errors (no hosts) or invalid `-C` format |

### Output Contract

**Terminal:** Per-host Rich-formatted output:
- Host header rule: `Host: <hostname>`
- Platform line: `Platform: <FAMILY> <version>` or `Platform: unknown`
- Capability table with columns: Capability, Available (yes/no, overrides in magenta)

**No `--json`, `--quiet`, or `-o` options.**

### Side Effects

None. No database writes, no file writes.

### Acceptance Criteria

- **AC-1:** Detect with a single reachable host exits 0 and prints platform + capability table.
- **AC-2:** Detect with an unreachable host exits 0 and prints "Connection failed:" error.
- **AC-3:** Detect with no target hosts (no --host, no --inventory, no auto-discovery) exits 1.
- **AC-4:** Capability override `-C key=true` appears as magenta "yes (override)" in output.
- **AC-5:** Capability override `-C key=false` appears as magenta "no (override)" in output.
- **AC-6:** Invalid `-C` format (no `=`) exits 1 with "Invalid capability format" error.
- **AC-7:** Invalid `-C` value (not true/false) exits 1 with "Invalid capability value" error.
- **AC-8:** Parallel execution (`--workers 2`) with two hosts prints both host outputs.

## Constraints

- MUST always exit 0 when target resolution succeeds, regardless of per-host failures.
- MUST print connection failures and continue to next host.
- MUST sort capabilities alphabetically in the table.
- MUST mark overridden capabilities distinctly (magenta) from detected ones.
