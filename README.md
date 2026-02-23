# Kensa

**Compliance scanning that auditors actually trust.**

`508 rules` · `7 frameworks` · `Evidence capture` · `No agent`

---

Compliance audits shouldn't mean weeks of manual checking, screenshots as evidence, and spreadsheets that go stale the moment they're created. But that's how most teams do it.

Kensa connects to your RHEL hosts over SSH, runs 508 compliance checks, captures machine-verifiable evidence for every one, and maps results directly to the frameworks your auditor cares about — CIS, STIG, NIST 800-53, PCI-DSS, and FedRAMP. No agent to install, no infrastructure to manage.

## Try It in 5 Minutes

```bash
pip install git+https://github.com/Hanalyx/kensa.git
```

```bash
# Check a single rule
kensa check --sudo --host 192.168.1.10 --user admin \
  --rule rules/access-control/ssh-disable-root-login.yml

# Check all rules, output as JSON with evidence
kensa check --sudo --host 192.168.1.10 --user admin \
  --rules rules/ -o evidence:results.json
```

## Why Kensa

- **Evidence-first** — Every check captures the exact command, stdout, exit code, and timestamp. Hand your auditor a JSON file, not a screenshot.
- **Multi-framework** — One scan maps results to CIS, STIG, NIST 800-53, PCI-DSS, and FedRAMP simultaneously. No duplicate work.
- **Capability-aware** — 22 probes detect what each host supports (authselect, sshd drop-ins, firewalld, SELinux) and auto-select the right check.
- **Remediate safely** — Dry-run first, pre-state snapshots by default, rollback any change from stored snapshots.
- **No agent required** — Pure SSH. No daemon, no client install, no open ports. Works with your existing key or password auth.

## Framework Coverage

| Framework | Mapping ID | Controls | Status |
|-----------|------------|----------|--------|
| CIS RHEL 9 v2.0.0 | `cis-rhel9-v2.0.0` | 271 | 95%+ |
| STIG RHEL 9 V2R7 | `stig-rhel9-v2r7` | 338 | 75%+ |
| NIST 800-53 R5 | `nist-800-53-r5` | 87 | Complete |
| PCI-DSS v4.0 | `pci-dss-v4.0` | 45 | Complete |
| FedRAMP Moderate | `fedramp-moderate` | 87 | Complete |
| CIS RHEL 8 v4.0.0 | `cis-rhel8-v4.0.0` | 120 | ~80% |
| STIG RHEL 8 V2R6 | `stig-rhel8-v2r6` | 116 | ~70% |

## Evidence Sample

Every check produces structured, machine-verifiable evidence:

```json
{
  "rule_id": "ssh-disable-root-login",
  "passed": true,
  "evidence": {
    "method": "config_value",
    "command": "grep -E '^\\s*PermitRootLogin' /etc/ssh/sshd_config",
    "stdout": "PermitRootLogin no\n",
    "exit_code": 0,
    "expected": "no",
    "actual": "no",
    "timestamp": "2024-02-09T12:00:00Z"
  },
  "frameworks": {
    "cis_rhel9_v2": "5.1.12",
    "stig_rhel9_v2r7": "V-257983",
    "nist_800_53": "AC-6, CM-6"
  }
}
```

## Output Formats

- **Terminal** — color-coded pass/fail with summary (default)
- **JSON** — structured results for automation
- **CSV** — for spreadsheet workflows
- **PDF** — formatted reports for stakeholders
- **Evidence** — full evidence export with raw command output and host context

## Installation

```bash
# From GitHub
pip install git+https://github.com/Hanalyx/kensa.git

# With PDF report support
pip install "git+https://github.com/Hanalyx/kensa.git#egg=kensa[pdf]"

# From source (development)
git clone https://github.com/Hanalyx/kensa.git
cd kensa
pip install -e ".[dev]"
```

Requires Python 3.10+ and SSH access to target hosts. Sudo checks require passwordless sudo (`NOPASSWD`) on targets.

## License

Kensa is source-available under the Business Source License 1.1. It is free for individuals and small businesses (under $5M annual revenue) and will convert to Apache 2.0 on January 1, 2029. See [LICENSE](https://github.com/Hanalyx/kensa/blob/main/LICENSE) for full terms.
