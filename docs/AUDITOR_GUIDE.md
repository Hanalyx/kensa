# Kensa Auditor Guide

How to interpret, verify, and report on Kensa compliance evidence.

This guide is for compliance reviewers, assessors, and auditors who receive Kensa output and need to evaluate it independently. For background on Kensa's design principles, see the [Compliance Philosophy](COMPLIANCE_PHILOSOPHY.md).

## What Kensa Produces

When a system administrator runs a Kensa scan, it evaluates compliance rules against one or more target hosts over SSH. Each rule produces a result with one of four statuses:

| Status | Meaning |
|--------|---------|
| **PASS** | The host meets the compliance requirement |
| **FAIL** | The host does not meet the requirement |
| **SKIP** | The rule does not apply to this host |
| **ERROR** | The check could not complete |

Kensa outputs results in four formats, each serving a different purpose:

| Format | Purpose | Contains Evidence? |
|--------|---------|-------------------|
| **Evidence** (JSON) | Auditor verification | Yes — raw commands, stdout, exit codes |
| **JSON** | Tool integration | Partial — results and capabilities, no raw command output |
| **CSV** | Spreadsheet analysis | No — summary data only |
| **PDF** | Executive reporting | No — summary tables |

The evidence export is the primary format for audit purposes.

## Evidence Export

The evidence export (`-o evidence:evidence.json`) contains everything needed to independently verify every finding.

### Structure

An evidence file contains four sections:

**Session** — when the scan ran and what command was used:

```json
{
  "id": "a1b2c3d4",
  "timestamp": "2026-02-28T14:32:01Z",
  "rules_path": "/opt/kensa/rules",
  "command": "check"
}
```

**Host** — what was scanned, including platform and detected capabilities:

```json
{
  "hostname": "web1.example.com",
  "platform": { "family": "rhel", "version": 9 },
  "capabilities": {
    "sshd_config_d": true,
    "authselect": true,
    "crypto_policies": true,
    "fips_mode": false
  }
}
```

The capability set determines which implementation variant Kensa selected for each rule. Two hosts with different capabilities may use different commands to verify the same control.

**Results** — per-rule findings with raw evidence:

```json
{
  "rule_id": "ssh-disable-root-login",
  "title": "Disable SSH root login",
  "severity": "high",
  "passed": true,
  "skipped": false,
  "detail": "PermitRootLogin=no",
  "timestamp": "2026-02-28T14:32:05Z",
  "evidence": {
    "method": "sshd_effective_config",
    "command": "sshd -T 2>/dev/null | grep -i permitrootlogin",
    "stdout": "permitrootlogin no\n",
    "stderr": "",
    "exit_code": 0,
    "expected": "no",
    "actual": "no"
  },
  "frameworks": {
    "cis-rhel9-v2.0.0": "5.1.20",
    "stig-rhel9-v2r7": "V-257947",
    "nist-800-53-r5": "AC-6(2)"
  }
}
```

**Summary** — aggregate counts:

```json
{
  "total": 508,
  "pass": 312,
  "fail": 142,
  "skip": 48,
  "fixed": 0
}
```

### Evidence Fields

The `evidence` object within each result is the core of auditor verification:

| Field | Description |
|-------|-------------|
| `method` | The check handler that evaluated this rule (e.g., `sshd_effective_config`, `file_permission`, `config_value`) |
| `command` | The exact shell command executed on the target host |
| `stdout` | Raw standard output from the command |
| `stderr` | Raw standard error output |
| `exit_code` | Command exit code (0 typically indicates success) |
| `expected` | The value Kensa expected to find |
| `actual` | The value Kensa actually found |

These fields provide machine-verifiable evidence. An auditor can confirm that the `actual` value matches (or does not match) the `expected` value by inspecting `stdout` directly.

## Verifying Evidence

### Step-by-Step Verification

For each finding an auditor wants to verify:

1. **Check the command.** Is it a reasonable way to test this control? For example, `sshd -T` queries the SSH daemon's effective configuration, resolving all drop-in files and overrides — more reliable than reading a static config file.

2. **Read stdout.** Does the raw output support the `actual` value? The `actual` field is extracted from `stdout` by the check handler. The raw output is preserved so you can confirm the extraction is correct.

3. **Compare expected vs. actual.** A `passed: true` result means `actual` matches `expected`. A `passed: false` result means they differ. Verify this yourself.

4. **Check the timestamp.** Evidence timestamps are ISO-8601 UTC. Confirm the scan was run within an acceptable window for your assessment.

5. **Review stderr.** Non-empty stderr may indicate warnings. An exit code of 0 with stderr content usually means the command succeeded but produced warnings.

### Common Check Methods

Different check methods produce different types of evidence:

**sshd_effective_config** — runs `sshd -T` to query the SSH daemon's compiled configuration. This resolves all `Include` directives, drop-in files, and `Match` blocks into a single effective configuration. More reliable than reading `/etc/ssh/sshd_config` directly.

**config_value** — reads a configuration file and searches for a specific key. The `command` field shows the exact grep or parse command used.

**file_permission** — runs `stat` to check file mode, ownership, or group. The `expected` field contains the required permission (e.g., `0600`).

**file_content** — reads a file and checks for the presence or absence of specific content. Used for banner text verification, configuration content checks, and similar controls.

**command** — runs an arbitrary shell command and checks the exit code or stdout content. Used for controls that require custom verification logic.

**service_state** — checks whether a systemd service is enabled, disabled, or masked.

**package_state** — checks whether an RPM package is installed or absent.

**audit_rule_exists** — runs `auditctl -l` and verifies that a specific audit rule is loaded in the kernel.

**sysctl_value** — runs `sysctl` to query a kernel parameter and compares it to the expected value.

**kernel_module_state** — checks whether a kernel module is loaded, disabled, or blacklisted.

## Understanding Framework Mappings

Each result includes a `frameworks` field that maps the rule to one or more compliance framework controls:

```json
"frameworks": {
  "cis-rhel9-v2.0.0": "5.1.20",
  "stig-rhel9-v2r7": "V-257947",
  "nist-800-53-r5": "AC-6(2)",
  "pci-dss-v4.0": "2.2.6"
}
```

This means the single rule `ssh-disable-root-login` satisfies control 5.1.20 in the CIS RHEL 9 benchmark, vulnerability V-257947 in the STIG, control AC-6(2) in NIST 800-53, and requirement 2.2.6 in PCI-DSS — all from the same evidence.

### Framework Coverage

Administrators can generate a coverage report showing which framework controls are implemented:

```bash
kensa coverage --framework cis-rhel9-v2.0.0
```

This shows the total number of controls in the framework, how many are mapped to rules, how many are explicitly marked unimplemented (with documented reasons), and how many are missing. When reviewing Kensa output, check the coverage report to understand which controls are and are not covered by the scan.

## Understanding Skip Results

A SKIP result means the rule was not evaluated — it does not indicate a pass or a fail. Skips occur for specific reasons:

| Skip Reason | Meaning | Audit Implication |
|-------------|---------|-------------------|
| Platform mismatch | Rule requires a different OS family or version | Not applicable to this host |
| Missing capability | Rule requires a capability the host does not have | Implementation variant unavailable |
| Dependency unmet | A prerequisite rule failed or was skipped | Control blocked by prerequisite |
| Not in framework | Rule is not mapped to the selected framework filter | Filtered out by scan configuration |

When a rule is skipped, no evidence is collected because no check was executed. The `skip_reason` field explains why.

An auditor should not count skipped rules as failures. Instead, document them as not applicable, and verify that the skip reason is legitimate for the host's platform and configuration.

## Remediation Evidence

When a scan is run with `kensa remediate` instead of `kensa check`, results may include remediation fields:

```json
{
  "rule_id": "ssh-disable-root-login",
  "passed": false,
  "remediated": true,
  "remediation_detail": "Written PermitRootLogin=no to /etc/ssh/sshd_config.d/00-kensa-permit-root-login.conf and reloaded sshd",
  "rolled_back": false,
  "evidence": {
    "method": "sshd_effective_config",
    "command": "sshd -T 2>/dev/null | grep -i permitrootlogin",
    "stdout": "permitrootlogin no\n",
    "exit_code": 0,
    "expected": "no",
    "actual": "no"
  }
}
```

| Field | Description |
|-------|-------------|
| `remediated` | `true` if a fix was applied |
| `remediation_detail` | What the fix did (file written, service reloaded, etc.) |
| `rolled_back` | `true` if the fix was automatically reversed due to a failure |

The `evidence` in a remediation result reflects the post-remediation state. The `passed` field indicates whether the initial check (before remediation) passed or failed. A result with `passed: false` and `remediated: true` means the host originally failed but was corrected.

## Working with JSON Output

The JSON output (`-o json:results.json`) provides structured results suitable for importing into security tools, dashboards, or SIEM systems.

Key differences from the evidence export:

- **No raw command output.** JSON results include the `detail` message and `implementation` variant but not the `evidence` block with `command`, `stdout`, and `exit_code`.
- **Multi-host aggregation.** JSON includes a top-level `hosts` array with per-host results and a global `summary`.
- **Skip reason breakdown.** The `summary.skip_reasons` field categorizes why rules were skipped.

JSON is useful for programmatic analysis but is not sufficient for independent evidence verification. For audit purposes, use the evidence export.

## Working with CSV Output

The CSV output (`-o csv:results.csv`) provides one row per host-rule combination:

```
host,platform,rule_id,framework_section,title,severity,passed,skipped,error,error_detail,detail
```

CSV is designed for spreadsheet tools. Typical use cases:

- Pivot tables by severity and status
- Filter to failures for remediation tracking
- Compare across hosts for consistency analysis
- Bulk import into GRC platforms

CSV does not contain evidence data. Use it for reporting summaries, not audit verification.

## Working with PDF Output

The PDF report (`-o pdf:report.pdf`) provides a visual compliance summary with color-coded status indicators. It includes a summary table and per-host result tables.

PDF is suitable for executive briefings and printed documentation. It does not contain raw evidence.

## Compliance Assessment Workflow

### Phase 1: Plan

Understand what was scanned and what frameworks apply.

```bash
# What platform and capabilities does the host have?
kensa detect -h 192.168.1.10 -u admin --sudo

# What frameworks are available?
kensa list-frameworks

# How complete is the framework coverage?
kensa coverage --framework cis-rhel9-v2.0.0
```

### Phase 2: Collect Evidence

Run the scan with evidence export and any additional formats needed:

```bash
kensa check -h 192.168.1.10 -u admin --sudo \
  -f cis-rhel9-v2.0.0 \
  -o evidence:evidence.json \
  -o json:results.json \
  -o csv:results.csv \
  -o pdf:report.pdf
```

### Phase 3: Review

1. **Open the evidence file.** Review the `host.platform` and `host.capabilities` sections to confirm the target system matches expectations.

2. **Review failures.** Filter results where `passed: false` and `skipped: false`. For each failure, examine the `evidence` block to confirm the finding.

3. **Review skips.** Check that skipped rules have legitimate reasons. Flag any skips that seem unexpected for the host's platform.

4. **Spot-check passes.** Select a sample of passing rules and verify that `stdout` supports the `actual` value and that `actual` matches `expected`.

5. **Cross-reference to framework.** Use the `frameworks` field to map findings back to the specific benchmark control numbers your assessment requires.

### Phase 4: Report

Use the CSV or JSON output to generate summary statistics. Use the evidence export to back specific findings with verifiable data. The PDF report serves as a printable executive summary.

## Verifying Without Re-Scanning

An auditor can verify a specific finding without access to Kensa by running the command shown in the evidence directly on the target host:

```bash
# Evidence shows this command was used:
ssh admin@web1.example.com "sudo sshd -T 2>/dev/null | grep -i permitrootlogin"
```

If the output matches the `stdout` in the evidence file, the finding is confirmed. If the output differs, either the system state changed since the scan or the scan was not run against the expected host.

## Key Concepts for Auditors

**One rule, multiple frameworks.** Kensa maintains one rule per security control, mapped to multiple frameworks. A single scan produces evidence that satisfies CIS, STIG, NIST, PCI-DSS, and FedRAMP assessors simultaneously.

**Capability-gated implementations.** The same rule may use different commands on different hosts depending on detected capabilities. This is by design — a host with `sshd_config_d` support uses `sshd -T` to resolve drop-in files, while a host without it reads the main config directly. The evidence shows which variant was used.

**Evidence is raw system output.** Kensa does not interpret or summarize. The `stdout` field contains exactly what the target system returned. The `expected` and `actual` fields are extracted from that output for comparison, but the raw output is always available for independent verification.

**Timestamps are per-check.** Each result has its own `timestamp` showing when that specific check was executed, not just when the scan session started.
