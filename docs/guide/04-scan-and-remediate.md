# Scan And Remediate

**Stub.** The bulk of this chapter is forthcoming. Until it lands, the
authoritative source for the topics not yet covered below is:

- The relevant binary's `--help` output
- The `.spec.yaml` file(s) under `specs/` for the components
  involved
- The atomicity contract guarantees described in
  [`README.md`](../../README.md) and
  [`03-concepts.md`](03-concepts.md)

The one part that IS documented here is the live result-row stream.

---

## Live result rows (default text output)

`kensa check` and `kensa remediate` stream their results **live** in the
default text output: one aligned row per rule, printed **as each rule
completes**, in scan order, so you watch a long scan advance instead of
waiting for a buffered report at the end. There is no `--progress` flag
and no separate progress channel — the rows *are* the text result, and
they go to stdout.

### What you see

```
── Host: web01 ──
Platform: rhel 9.4

STATUS   SEVERITY  RULE-ID                      DESCRIPTION
PASS     high      xccdf_org...partition_tmp    Ensure /tmp is a separate partition
FAIL     medium    xccdf_org...sysctl_aslr      Enable randomized virtual memory
...
3 passed, 1 failed, 0 error   (4 rules)
```

- The columns are `STATUS  SEVERITY  RULE-ID  DESCRIPTION`, followed by a
  trailing detail on `FAIL`/`ERROR`/`SKIP` rows.
- `check` shows `PASS` / `FAIL` / `ERROR` / `SKIP`. `remediate` shows
  `PASS` (already compliant), `FIXED` (remediated this run), `FAIL`,
  `ERROR`, and `SKIP`.
- `SKIP` (since v0.3.0) means the rule **does not apply to this host** and
  was not evaluated: kensa reads the host's OS from `/etc/os-release` and
  compares it against the rule's `platforms:` block (family plus
  `min_version`/`max_version`). A `rhel >= 9` control scanned on a RHEL 8
  host renders `SKIP` with a detail like
  `not applicable: host RHEL 8.10, rule targets rhel >=9` — instead of a
  misleading pass/fail. On `remediate`, a skipped rule's remediation is
  **never applied**. Rules with no `platforms:` block run everywhere, and
  a host whose OS cannot be detected is never gated (every rule runs), so
  a detection blip cannot silently skip a scan. The tally appends
  `N skipped` when any rule was skipped.
- `STATUS` and `SEVERITY` are colored **only when stdout is a terminal**;
  redirected or piped output is plain text with no escape sequences.

### Machine output is never interleaved

The live rows apply to the **default human output only** (`--format
table`/`text`, or no format flag, with no `-o FILE`). Machine formats are
always buffered and structured, never streamed row-by-row:

```bash
# Rows stream to the terminal here:
kensa check web01 --sudo

# JSON is buffered and written whole — nothing interleaved on stdout:
kensa check web01 --sudo -o json:result.json
kensa check web01 --sudo --format json > result.json
```

Choosing a machine format or an `-o FILE` destination turns the row
stream off; the canonical `ScanResult` / `RemediationResult` is what gets
serialized. `--quiet` suppresses the default output entirely (errors
still go to stderr).

### The result is authoritative

The exit code and every `-o FORMAT[:PATH]` output are produced from the
canonical result struct, not reconstructed from the rendered rows. Read
the result document (or `-o json`/`oscal`/etc.) for the record of what
changed; the rows are the same data rendered for a human as it arrives.

### Inventory (multi-host)

`kensa check`/`detect` against an `--inventory` run per host; stdout
carries the concatenated per-host result documents. (`remediate` and
`rollback` are single-host; they require `--host`.)
