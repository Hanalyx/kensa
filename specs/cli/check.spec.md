# Spec: check CLI Command

## Context
- **Module:** `runner/cli.py` → `check()`
- **Click decorators:** `@main.command()`, `@target_options`, `@rule_options`, `@output_options`, `@click.option("--store")`
- **Option groups:** target_options, rule_options (--rules, --rule, --severity, --tag, --category, --framework, --var, --control, --config-dir), output_options (--output, --quiet)
- **Dependencies:** `runner._host_runner`, `runner._rule_selection`, `runner.engine`, `runner.inventory`, `runner.output`, `runner.storage`

## Objective
Run compliance checks on target hosts over SSH, evaluate YAML rules against host state, and report pass/fail/skip results. Optionally write output to files (CSV, JSON, PDF) and/or persist results to SQLite.

### Input Contract

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| (target_options) | | | | See detect spec |
| `--rules / -r` | `str` | No* | `None` | Rules directory path |
| `--rule` | `str` | No* | `None` | Single rule file path |
| `--severity / -s` | `str (multiple)` | No | `()` | Severity filter |
| `--tag / -t` | `str (multiple)` | No | `()` | Tag filter |
| `--category / -c` | `str` | No | `None` | Category filter |
| `--framework / -f` | `str` | No | `None` | Framework mapping filter |
| `--var / -V` | `str (multiple)` | No | `()` | Variable overrides `KEY=VALUE` |
| `--control` | `str` | No | `None` | Control filter (e.g., `cis-rhel9-v2.0.0:5.1.12`) |
| `--config-dir` | `str` | No | `None` | Config directory path |
| `--output / -o` | `str (multiple)` | No | `()` | Output format specs |
| `--quiet / -q` | `bool` | No | `False` | Suppress terminal output |
| `--store` | `bool` | No | `False` | Persist results to SQLite |

\* At least one of `--rules` or `--rule` must be provided (or auto-discovery must succeed).

### Behavior

1. Resolve target hosts via `_resolve_hosts()`.
2. Load and filter rules via `select_rules()`.
3. Parse capability overrides.
4. For each host (sequential or parallel based on `--workers`):
   a. Connect via SSH.
   b. Detect platform and capabilities.
   c. Apply `--framework auto` on first host if specified.
   d. Apply platform-aware control filtering.
   e. Resolve per-host variables from config hierarchy.
   f. Run checks via `run_checks()`.
   g. Collect results into `RunResult`.
5. Print per-host summary (rules | pass | fail | skip).
6. Print multi-host summary if >1 host.
7. Sort results by framework section if `--framework` is active.
8. Write output files via `_write_outputs()`.
9. Store results via `_store_results()` if `--store`.

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Normal completion — even when checks fail, hosts unreachable, or all checks skip |
| 1 | Target resolution error (no hosts), rule loading error (no rules, bad path), output format error |

### Output Contract

**Terminal (default):**
- Per-host: Host header, platform, capability detail (verbose), per-rule PASS/FAIL/SKIP, host summary line.
- Multi-host: Grand summary line with totals.

**`--quiet`:** Suppresses all terminal output. Useful with `-o`.

**`-o json`:** JSON to stdout with RunResult schema.
**`-o json:path`:** JSON written to file.
**`-o csv` / `-o csv:path`:** CSV format.
**`-o pdf:path`:** PDF report (requires filepath).

### Side Effects

- **SQLite** (only with `--store`): Creates session + results records in `.kensa/results.db`.
- **File writes** (only with `-o fmt:path`): Writes output files.

### Acceptance Criteria

- **AC-1:** Check with one host and one passing rule exits 0, output contains "PASS" and "1 pass".
- **AC-2:** Check with one host and one failing rule exits 0, output contains "FAIL" and "1 fail".
- **AC-3:** Check with no target hosts exits 1 with "No target hosts" error.
- **AC-4:** Check with no rules (no --rules, no --rule) exits 1 with "Specify --rules or --rule" error.
- **AC-5:** Check with bad rules path exits 1.
- **AC-6:** `--quiet` suppresses terminal output (result.output is empty or minimal).
- **AC-7:** `-o json` writes JSON to stdout containing host results.
- **AC-8:** `--store` creates a session in ResultStore.
- **AC-9:** Connection failure prints error and continues; exit code remains 0.
- **AC-10:** `--severity` filter reduces the rule set to matching severities only.
- **AC-11:** Multi-host run prints summary line with host count and totals.
- **AC-12:** `--framework auto` applies platform-based framework selection.
- **AC-13:** `--var KEY=VALUE` overrides rule variables.
- **AC-14:** `--control` filters to rules for a specific framework control.
- **AC-15:** Parallel execution (`--workers 2`) produces results for all hosts.
- **AC-16:** `-o csv:path` writes a CSV file to the specified path.
- **AC-17:** Invalid output format exits 1 with error.
- **AC-18:** `--framework` sorts results by framework section order.

## Constraints

- MUST exit 0 on normal completion, even with check failures or connection errors.
- MUST exit 1 only for argument validation / rule loading errors.
- MUST NOT store results unless `--store` is explicitly passed.
- MUST suppress terminal output when `--quiet` is set.
- MUST apply per-host variable resolution when config is available.
