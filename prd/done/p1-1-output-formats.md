# P1-1: Output Formats

## Status: Complete

## Problem
V0 only outputs rich terminal text. CI/CD pipelines need machine-readable output (JSON). Compliance reporting needs CSV/PDF for non-technical stakeholders.

## Solution
Add `--output` / `-o` flag with format selection and optional file path.

## What Was Delivered

### runner/output/__init__.py
- `RunResult` and `HostResult` dataclasses for result aggregation
- `parse_output_spec()` function to parse format:filepath specifications
- `write_output()` dispatcher that routes to appropriate formatter
- Support for stdout or file output (PDF requires filepath)

### runner/output/json_fmt.py
- Full structured JSON output with ISO-8601 timestamps
- Per-host results with platform info and capabilities
- Summary statistics at host and run level
- Remediation details when running remediate command

### runner/output/csv_fmt.py
- Flat tabular format (one row per host+rule)
- Suitable for spreadsheet import and analysis
- Column definitions for check and remediate commands

### runner/output/pdf_fmt.py
- Formatted reports using reportlab library
- Color-coded status tables (PASS=green, FAIL=red, SKIP=grey)
- Executive summary and per-host sections
- Optional dependency (requires `pip install reportlab`)

## Formats

### JSON (`--output json`)
```json
{
  "timestamp": "2026-02-05T14:30:00Z",
  "hosts": [
    {
      "hostname": "192.168.1.211",
      "capabilities": {"sshd_config_d": true, "authselect": true, ...},
      "results": [
        {
          "rule_id": "ssh-disable-root-login",
          "title": "Disable SSH root login",
          "severity": "high",
          "passed": true,
          "skipped": false,
          "detail": "PermitRootLogin=no",
          "implementation": "sshd_config_d"
        }
      ],
      "summary": {"total": 35, "pass": 26, "fail": 9, "skip": 0}
    }
  ],
  "summary": {"hosts": 1, "total": 35, "pass": 26, "fail": 9, "skip": 0}
}
```

### CSV (`--output csv`)
Flat format for spreadsheet analysis:
```
host,platform,rule_id,title,severity,passed,skipped,detail
192.168.1.211,rhel 9,ssh-disable-root-login,Disable SSH root login,high,true,false,PermitRootLogin=no
```

### PDF (`--output pdf:report.pdf`)
Formatted report with:
- Title and timestamp
- Summary table (hosts, pass/fail/skip counts)
- Per-host sections with color-coded results tables

## Technical Approach

### Output Collection
Separate result collection from rendering. The check/remediate loop already produces `RuleResult` objects — collect them into a structured results dict, then pass to the appropriate formatter.

### File Output
- `--output json` prints to stdout
- `--output json:results.json` writes to file
- `--output pdf:report.pdf` writes PDF to file (requires filepath)
- Terminal (rich) output is always shown unless `--quiet` / `-q` is set

## Acceptance Criteria
- [x] `--output json` produces valid JSON to stdout
- [x] `--output json:file.json` writes to file
- [x] `--output csv` produces valid CSV with headers
- [x] `--output pdf:file.pdf` produces formatted PDF report
- [x] JSON includes capabilities, implementation used, and timestamps
- [x] CSV is flat (one row per host+rule combination)
- [x] PDF includes color-coded status and summary tables
- [x] All formats include remediation details when running remediate
- [x] Multiple `--output` flags can be combined
