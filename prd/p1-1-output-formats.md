# P1-1: Output Formats

## Status: Not Started

## Problem
V0 only outputs rich terminal text. CI/CD pipelines need machine-readable output (JSON, JUnit XML). Compliance reporting needs CSV/HTML for non-technical stakeholders.

## Solution
Add `--output` / `-o` flag with format selection and optional file path.

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
          "category": "access-control",
          "passed": true,
          "skipped": false,
          "detail": "PermitRootLogin=no",
          "implementation": "sshd_config_d",
          "remediated": false
        }
      ],
      "summary": {"total": 35, "pass": 26, "fail": 9, "skip": 0}
    }
  ],
  "summary": {"hosts": 1, "total": 35, "pass": 26, "fail": 9, "skip": 0}
}
```

### JUnit XML (`--output junit`)
For CI/CD integration (Jenkins, GitLab CI, GitHub Actions):
```xml
<testsuites>
  <testsuite name="192.168.1.211" tests="35" failures="9">
    <testcase name="ssh-disable-root-login" classname="access-control">
    </testcase>
    <testcase name="ssh-banner" classname="access-control">
      <failure message="Banner not found in /etc/ssh/sshd_config"/>
    </testcase>
  </testsuite>
</testsuites>
```

### CSV (`--output csv`)
Flat format for spreadsheet analysis:
```
host,rule_id,title,severity,category,passed,detail
192.168.1.211,ssh-disable-root-login,Disable SSH root login,high,access-control,true,PermitRootLogin=no
```

## Technical Approach

### Output Collection
Separate result collection from rendering. The check/remediate loop already produces `RuleResult` objects — collect them into a structured results dict, then pass to the appropriate formatter.

### File Output
- `--output json` prints to stdout
- `--output json:results.json` writes to file
- Terminal (rich) output is always shown unless `--quiet` / `-q` is set

### Implementation
```
runner/
  output/
    __init__.py
    json_fmt.py      # JSON formatter
    junit_fmt.py     # JUnit XML formatter
    csv_fmt.py       # CSV formatter
```

Each formatter takes the same results structure and produces a string or writes to a file.

## Acceptance Criteria
- [ ] `--output json` produces valid JSON to stdout
- [ ] `--output json:file.json` writes to file
- [ ] `--output junit` produces valid JUnit XML
- [ ] `--output csv` produces valid CSV with headers
- [ ] `--quiet` suppresses terminal output when combined with file output
- [ ] JSON includes capabilities, implementation used, and timestamps
- [ ] JUnit failure messages include check detail
- [ ] CSV is flat (one row per host+rule combination)
- [ ] All formats include remediation details when running remediate
- [ ] Multiple `--output` flags can be combined (e.g., `--output json:out.json --output junit:out.xml`)
