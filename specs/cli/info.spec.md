# Spec: info CLI Command

## Context
- **Module:** `runner/cli.py` → `info()`
- **Click decorators:** `@main.command()`, `@click.argument("query", required=False)`, individual options
- **Dependencies:** `runner.mappings.FrameworkIndex`, `runner.mappings.load_all_mappings`, `runner.rule_info.build_rule_index`, `runner.rule_info.classify_query`, `runner.rule_info.search_rules_by_reference`, `runner.paths.get_rules_path`

## Objective
Show detailed information about rules and framework controls. Supports auto-detection of query type from positional argument, explicit framework flags (`--cis`, `--stig`, `--nist`), and control/rule/list-controls modes.

### Input Contract

| Argument/Flag | Type | Required | Default | Description |
|---------------|------|----------|---------|-------------|
| `QUERY` | `str` | No | `None` | Auto-detected: rule ID, CIS section, STIG ID, or NIST control |
| `--control / -c` | `str` | No | `None` | Find rules implementing a control |
| `--rule / -r` | `str` | No | `None` | Find framework references for a rule |
| `--list-controls / -l` | `bool` | No | `False` | List all controls with rule counts |
| `--framework / -f` | `str` | No | `None` | Filter by framework ID (for --list-controls) |
| `--prefix-match / -p` | `bool` | No | `False` | Match control as prefix |
| `--json` | `bool` | No | `False` | Output as JSON |
| `--cis` | `str` | No | `None` | CIS section number |
| `--stig` | `str` | No | `None` | STIG ID |
| `--nist` | `str` | No | `None` | NIST 800-53 control |
| `--rhel` | `Choice[8,9,10]` | No | `None` | Filter by RHEL version |
| `--all` | `bool` | No | `False` | Show all RHEL versions |

### Behavior

1. **Explicit reference flags** (`--cis`, `--stig`, `--nist`): Search rules by reference type. Exit 1 if rules/ not found.
2. **Mutual exclusion check:** At most one of `--control`, `--rule`, `--list-controls`. Exit 1 if >1.
3. **--control mode:** Query FrameworkIndex for rules implementing a control. Supports `--prefix-match`.
4. **--rule mode:** If rule ID in index, show full detail; otherwise show framework cross-references only.
5. **--list-controls mode:** List all controls with rule counts. Filter by `--framework` if specified.
6. **Positional QUERY:** Auto-detect type via `classify_query()`:
   - Rule ID → full rule detail. Exit 1 if not found.
   - V-NNNNNN → STIG lookup.
   - XX-N pattern → NIST 800-53.
   - N.N.N pattern → CIS section.
7. **No arguments:** Print usage error with examples, exit 1.

### Exit Code Contract

| Exit Code | Condition |
|-----------|-----------|
| 0 | Successful query (including empty results for --control, --rule, --list-controls) |
| 1 | No arguments, conflicting flags (>1 of --control/--rule/--list-controls), rule not found (positional), rules/ directory not found |

### Output Contract

**--control (terminal):** Header, optional prefix match note, control info, rule list with severity.
**--rule (terminal):** Full rule detail OR framework cross-references.
**--list-controls (terminal):** Controls grouped by mapping with rule counts.
**Positional rule ID (terminal):** Full detail: title, description, severity, category, tags, platforms, implementations, references, framework cross-refs.
**Positional reference (terminal):** Rules matching the reference, grouped by framework when showing all versions.
**--json:** JSON object with query context and results appropriate to the mode.

### Side Effects

- **None.** Read-only operation.

### Acceptance Criteria

- **AC-1:** Positional rule ID exits 0 with full rule detail.
- **AC-2:** Positional rule ID not found exits 1.
- **AC-3:** Positional CIS section auto-detected and exits 0.
- **AC-4:** Positional STIG ID auto-detected and exits 0.
- **AC-5:** Positional NIST control auto-detected and exits 0.
- **AC-6:** `--cis` explicit flag exits 0 with matching rules.
- **AC-7:** `--control` with valid control exits 0 with matching rules.
- **AC-8:** `--rule` with known rule exits 0 with framework refs.
- **AC-9:** `--list-controls` exits 0 with control listing.
- **AC-10:** `--json` outputs valid JSON for all modes.
- **AC-11:** Multiple conflicting flags (`--control` + `--rule`) exits 1.
- **AC-12:** No arguments exits 1 with usage examples.
- **AC-13:** `--prefix-match` matches control prefixes.
- **AC-14:** `--list-controls --framework` filters to specified framework.
- **AC-15:** Rules directory not found with explicit ref flag exits 1.

## Constraints

- MUST support auto-detection from positional QUERY.
- MUST enforce mutual exclusion of `--control`, `--rule`, `--list-controls`.
- MUST exit 1 for no arguments.
- MUST handle missing rules/ directory gracefully.
