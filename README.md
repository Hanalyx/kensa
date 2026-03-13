# Kensa

**Compliance as Code — Scan, Remediate, Rollback.**

`630 rules` · `26 remediation mechanisms` · `7 frameworks` · `Automatic rollback` · `No agent`

---

Your auditor wants evidence that 300 RHEL servers meet STIG. Your team has two weeks.

The current playbook: SSH into each box, run commands by hand, copy stdout into spreadsheets, cross-reference against framework controls, and pray nothing drifts before the assessor arrives. It takes days per server. The evidence is stale before you finish. And when something fails, remediation is a Bash script that might break SSH access at 2 AM with no way to undo it.

Kensa replaces that entire workflow. It connects over SSH, evaluates 630 compliance rules with machine-verifiable evidence for every check, maps results to CIS, STIG, NIST 800-53, PCI-DSS, FedRAMP, ISO 27001, and SRG simultaneously, and remediates failures with 22 typed mechanisms that capture pre-state and automatically roll back on failure.

No agent. No XML. No Ansible. Just YAML rules, SSH, and structured evidence your auditor can independently verify.

## Try It in 5 Minutes

```bash
pip install git+https://github.com/Hanalyx/kensa.git
```

**Scan a host:**
```bash
kensa check --sudo -h 192.168.1.10 -u admin -r rules/
```

**Remediate failures (dry-run first):**
```bash
kensa remediate --sudo -h 192.168.1.10 -u admin -r rules/ --dry-run
```

**Remediate for real, with automatic rollback on failure:**
```bash
kensa remediate --sudo -h 192.168.1.10 -u admin -r rules/ --rollback-on-failure
```

## What Makes Kensa Different

### 1. Scan + Remediate + Rollback (No Other Agentless Tool Does This)

Most compliance tools stop at scanning. A few generate Bash scripts for remediation. Kensa does both — and does remediation safely.

Every remediation uses one of **22 typed, declarative mechanisms** (not scripts). Before any change, Kensa captures the current state. If a step fails, all completed steps are reversed automatically. Your system is never left half-remediated.

```yaml
# This is a Kensa rule — not a script. Kensa decides HOW to apply it safely.
remediation:
  mechanism: config_set
  path: "/etc/ssh/sshd_config"
  key: "PermitRootLogin"
  value: "no"
  reload: "sshd"
```

| Phase | What Happens |
|---|---|
| **Check** | Read-only evaluation. Evidence captured: exact command, stdout, expected vs. actual, timestamp. |
| **Remediate** | Pre-state snapshot taken. Typed mechanism applied. Service reloaded. Post-change verified. |
| **Rollback** | If any step fails, completed steps are reversed in order. System restored to pre-remediation state. |

### 2. One Rule, All Frameworks

A single `ssh-disable-root-login.yml` maps to:

- CIS RHEL 9 v2.0.0 — Section 5.1.20
- DISA STIG RHEL 9 — V-257947
- NIST 800-53 R5 — AC-6(2), AC-17(2)
- PCI-DSS v4.0 — 2.2.6, 8.6.1
- FedRAMP Moderate — AC-6(2)

Run one scan. Satisfy five assessors. No duplicate content, no framework-specific rule repos.

This is an architectural choice: Kensa separates rules from their implementations and treats framework identifiers as metadata labels attached to a canonical rule — not as reasons to duplicate the rule set. Adding a new framework means adding a new column of labels, not a new set of rules.

### 3. Evidence Auditors Actually Trust

Every check captures structured, machine-verifiable evidence — not screenshots, not log files:

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
    "timestamp": "2025-02-09T12:00:00Z"
  },
  "frameworks": {
    "cis_rhel9": "5.1.20",
    "stig_rhel9": "V-257947",
    "nist_800_53": "AC-6(2), AC-17(2)"
  }
}
```

Hand your auditor a JSON file. Every finding is independently verifiable: they can see exactly what command ran, what the system returned, and whether it matched the expected value.

### 4. YAML Rules, Not XML

Kensa rules are human-readable YAML — designed to be read, reviewed, and modified by the engineers who manage the systems:

```yaml
id: ssh-disable-root-login
title: Disable SSH root login
severity: high
category: access-control

implementations:
  - when: sshd_config_d
    check:
      method: sshd_effective_config
      key: "permitrootlogin"
      expected: "no"
    remediation:
      mechanism: config_set_dropin
      dir: "/etc/ssh/sshd_config.d"
      file: "00-kensa-permit-root-login.conf"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"

  - default: true
    check:
      method: sshd_effective_config
      key: "permitrootlogin"
      expected: "no"
    remediation:
      mechanism: config_set
      path: "/etc/ssh/sshd_config"
      key: "PermitRootLogin"
      value: "no"
      reload: "sshd"
```

Anyone can read a rule, understand what it checks, and verify the remediation is safe. Fully Git-friendly — diff, review, and version your compliance policy.

### 5. Adapts to Each Host Automatically

24 runtime probes detect what each host supports — sshd drop-in directories, authselect, crypto policies, FIPS mode, SELinux, firewalld backend, and more. Kensa selects the correct implementation variant for each host. One rule works across RHEL 8, 9, and 10 without version-specific content.

This is capability detection, not version-string matching. The question isn't "is this RHEL 9?" — it's "does this system support sshd_config.d drop-in files?" A capability-based model extends forward to new OS versions without modification.

### 6. No Agent Required

Pure SSH. No daemon running on targets, no client packages to install, no ports to open. Works with your existing SSH keys or password auth. Requires passwordless sudo on targets for privileged checks.

Up to 50 concurrent SSH sessions for fleet-scale scanning.

## How It Compares

Kensa takes a different architectural approach than most compliance tools. Where traditional tools organize content around benchmark documents (one artifact per OS per framework), Kensa separates rules from implementations, treats frameworks as metadata, and adds typed remediation with rollback as a first-class concern.

| | Kensa | Manual Checks | Ansible Lockdown | Point-in-Time Scanners |
|---|---|---|---|---|
| **Architecture** | Canonical rules, capability-gated | N/A | Per-OS per-framework repos | Per-benchmark content |
| **Remediation** | 22 typed mechanisms | Run commands by hand | Ansible tasks | Basic scripts or none |
| **Rollback** | Automatic | None | None | None |
| **Rule format** | YAML | N/A | Ansible YAML | Varies (XCCDF/OVAL, Ruby DSL, etc.) |
| **Frameworks per rule** | All simultaneously | Whatever you check | One repo per framework+OS | One profile per scan |
| **Evidence** | Structured JSON per check | Screenshots | Unstructured logs | Varies by tool |
| **Agent required** | No (SSH) | No | No (SSH + Ansible) | Varies |
| **OS adaptation** | 24 capability probes | N/A | Version-specific repos | Version-specific content |
| **License** | BSL 1.1 (free for <$5M) | N/A | MIT | Varies |

## Framework Coverage

| Framework | Mapping ID | Total Controls | Mapped | Coverage |
|---|---|---|---|---|
| CIS RHEL 9 v2.0.0 | `cis-rhel9` | 297 | 276 | 92.9% |
| STIG RHEL 9 V2R7 | `stig-rhel9` | 446 | 420 | 94.2% |
| CIS RHEL 8 v4.0.0 | `cis-rhel8` | 322 | 293 | 91.0% |
| STIG RHEL 8 V2R6 | `stig-rhel8` | 366 | 348 | 95.1% |
| NIST 800-53 R5 | `nist-800-53-r5` | 87 | 87 | Selective |
| PCI-DSS v4.0 | `pci-dss-v4.0` | 45 | 45 | Selective |
| FedRAMP Moderate | `fedramp-moderate` | 323 | 91 | 28.2% |

NIST and PCI-DSS use selective mapping — Kensa maps automatable controls, not every control in the framework. FedRAMP coverage reflects OS-level controls verifiable on RHEL; many FedRAMP controls are organizational or procedural.

## Supported Platforms

| Platform | Versions | Status |
|---|---|---|
| Red Hat Enterprise Linux | 8, 9 | Production |
| CentOS Stream | 8, 9 | Production |
| AlmaLinux / Rocky Linux | 8, 9 | Production |
| Oracle Linux | 8, 9 | Community-tested |
| Fedora | 38+ | Experimental |

**Frameworks:** CIS Benchmarks (RHEL 8 v4.0.0, RHEL 9 v2.0.0), DISA STIG (RHEL 8 V2R6, RHEL 9 V2R7), NIST 800-53 Rev 5, PCI-DSS v4.0, FedRAMP Moderate Rev 5.

**What "manual" controls mean:** Some compliance controls require human judgment, physical access, or organizational policy decisions that cannot be automated via SSH. These are mapped in framework files as `unimplemented` with a reason, and are surfaced in coverage reports so auditors know they must be verified separately.

## CLI Reference

```bash
# Detect host capabilities and platform
kensa detect --sudo -h 192.168.1.10 -u admin

# Check all rules against a single host
kensa check --sudo -h 192.168.1.10 -u admin -r rules/

# Check a specific framework
kensa check --sudo -h 192.168.1.10 -u admin -r rules/ -f cis-rhel9

# Check across an inventory (10 hosts in parallel)
kensa check --sudo -i inventory.yml -r rules/ -w 10

# Output as JSON with evidence
kensa check --sudo -h 192.168.1.10 -u admin -r rules/ -o evidence:evidence.json

# Dry-run remediation (preview changes, apply nothing)
kensa remediate --sudo -h 192.168.1.10 -u admin -r rules/ --dry-run

# Remediate with rollback safety
kensa remediate --sudo -h 192.168.1.10 -u admin -r rules/ --rollback-on-failure

# Look up a rule by CIS section, STIG ID, or NIST control
kensa info 5.1.20
kensa info V-257947
kensa info AC-6

# Show framework coverage
kensa coverage -f cis-rhel9

# Compare two scan sessions for drift
kensa diff 1 2
```

## Output Formats

| Format | Flag | Use Case |
|---|---|---|
| Terminal | (default) | Color-coded pass/fail with summary |
| JSON | `-o json:results.json` | Automation, SIEM integration |
| CSV | `-o csv:results.csv` | Spreadsheet workflows |
| PDF | `-o pdf:report.pdf` | Stakeholder reports |
| Evidence | `-o evidence:evidence.json` | Full evidence export with host context |

Multiple outputs can be generated in a single run:

```bash
kensa check --sudo -h host -u admin -r rules/ \
  -o json:results.json -o csv:results.csv -o evidence:evidence.json
```

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

Requires Python 3.10+ and SSH access to target hosts. Privileged checks require passwordless sudo (`NOPASSWD`) on targets.

## Part of the Hanalyx Compliance Platform

Kensa is the compliance engine. **[OpenWatch](https://github.com/Hanalyx/OpenWatch)** is the compliance operating system — a web platform that wraps Kensa with a dashboard, multi-host orchestration, temporal compliance queries, governance workflows, and audit reporting. If you need a GUI, scheduling, and team collaboration, start with OpenWatch.

If you need a fast, powerful CLI that integrates into scripts and pipelines, start here.

## Community

- **[GitHub Discussions](https://github.com/Hanalyx/kensa/discussions)** — Questions, ideas, show and tell
- **[Issue Tracker](https://github.com/Hanalyx/kensa/issues)** — Bug reports and feature requests
- **[Contributing Guide](CONTRIBUTING.md)** — How to contribute rules, handlers, and fixes

## License

Kensa is source-available under the **Business Source License 1.1**. It is free for individuals and organizations under $5M annual revenue, and will convert to Apache 2.0 on January 1, 2029. See [LICENSE](LICENSE) for full terms.

Commercial licensing: [legal@hanalyx.com](mailto:legal@hanalyx.com)
