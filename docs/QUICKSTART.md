# Kensa QuickStart Guide

Get from zero to your first compliance scan in 10 minutes.

## Prerequisites

- **Python 3.10+** on the machine running Kensa (the control host)
- **SSH access** to target hosts (key-based or password)
- **Sudo privileges** on target hosts for privileged checks (most compliance rules require root access)

Kensa runs entirely from the control host over SSH. Nothing is installed on target systems.

## Installation

### pip (any Linux/macOS)

```bash
pip install git+https://github.com/Hanalyx/kensa.git
```

For PDF report support:

```bash
pip install "git+https://github.com/Hanalyx/kensa.git#egg=kensa[pdf]"
```

### RPM (RHEL, Rocky Linux, AlmaLinux)

Download the RPM for your distribution from the [latest release](https://github.com/Hanalyx/kensa/releases/latest):

```bash
dnf install ./kensa-1.2.2-1.el9.noarch.rpm
```

RPM packages are available for EL8, EL9, EL10, and Fedora.

### From source (development)

```bash
git clone https://github.com/Hanalyx/kensa.git
cd kensa
pip install -e ".[dev]"
```

### Verify installation

```bash
kensa --version
```

## SSH Setup

Kensa needs SSH access to target hosts. The simplest setup:

**Key-based auth (recommended):**

```bash
# Ensure your SSH key can reach the target
ssh admin@192.168.1.10 "echo connected"
```

**Password auth:**

```bash
# Use -p to prompt securely for a password
kensa check -h 192.168.1.10 -u admin -p --sudo
```

The `-p` flag without a value prompts interactively with hidden input. You can also pass a password inline with `-p mypassword`, but interactive prompting is more secure.

**Sudo access:** Most compliance checks require root privileges. Configure passwordless sudo for the SSH user, or use `--password` to provide the sudo password:

```bash
# On the target host, grant passwordless sudo:
echo "admin ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/kensa
```

## Your First Scan

### Step 1: Detect host capabilities

```bash
kensa detect -h 192.168.1.10 -u admin --sudo
```

This probes the target and reports its platform (e.g., RHEL 9.3) and detected capabilities (authselect, crypto policies, sshd_config.d support, etc.). Use this to verify connectivity before running checks.

### Step 2: Run compliance checks

```bash
kensa check -h 192.168.1.10 -u admin --sudo
```

Kensa auto-discovers the rules directory and runs all applicable rules against the target. Each rule produces a result:

| Status | Meaning |
|--------|---------|
| **PASS** | Host meets the compliance requirement |
| **FAIL** | Host does not meet the requirement — remediation available |
| **SKIP** | Rule does not apply to this host (platform mismatch or missing capability) |
| **ERROR** | Check could not complete (SSH failure, timeout, unexpected output) |

The summary line at the end shows totals:

```
508 rules: 312 pass, 142 fail, 48 skip, 6 error (45.2s)
```

### Step 3: Generate structured output

For sharing results with your team or auditors:

```bash
# JSON output
kensa check -h 192.168.1.10 -u admin --sudo -o json:results.json

# CSV for spreadsheets
kensa check -h 192.168.1.10 -u admin --sudo -o csv:results.csv

# Multiple formats in one run
kensa check -h 192.168.1.10 -u admin --sudo \
  -o json:results.json -o csv:results.csv

# Evidence export (full command output for auditor verification)
kensa check -h 192.168.1.10 -u admin --sudo -o evidence:evidence.json
```

## Filtering Rules

You rarely need to run all 508 rules. Kensa provides several ways to focus your scan:

**By framework** — run only rules mapped to a specific benchmark:

```bash
kensa check -h 192.168.1.10 -u admin --sudo -f cis-rhel9-v2.0.0
```

**By specific control** — run the rules for a single framework section:

```bash
kensa check -h 192.168.1.10 -u admin --sudo --control cis-rhel9-v2.0.0:5.1.12
```

**By severity** — run only high and critical rules:

```bash
kensa check -h 192.168.1.10 -u admin --sudo -s high -s critical
```

**By category** — run only rules in a category (access-control, audit, kernel, etc.):

```bash
kensa check -h 192.168.1.10 -u admin --sudo -c access-control
```

## Scanning Multiple Hosts

Use an inventory file to scan multiple hosts in parallel:

```ini
# hosts.ini
[webservers]
web1.example.com
web2.example.com

[databases]
db1.example.com ansible_user=dbadmin
```

```bash
# Scan all hosts, 4 in parallel
kensa check -i hosts.ini --sudo -w 4

# Scan only the webservers group
kensa check -i hosts.ini --sudo -l webservers
```

## Available Frameworks

List all framework mappings installed with Kensa:

```bash
kensa list-frameworks
```

| Framework | Mapping ID | Description |
|-----------|-----------|-------------|
| CIS RHEL 9 v2.0.0 | `cis-rhel9-v2.0.0` | Center for Internet Security Benchmark |
| STIG RHEL 9 V2R7 | `stig-rhel9-v2r7` | DISA Security Technical Implementation Guide |
| NIST 800-53 R5 | `nist-800-53-r5` | NIST Security Controls |
| PCI-DSS v4.0 | `pci-dss-v4.0` | Payment Card Industry Data Security Standard |
| FedRAMP Moderate | `fedramp-moderate` | Federal Risk and Authorization Management Program |
| CIS RHEL 8 v4.0.0 | `cis-rhel8-v4.0.0` | CIS Benchmark for RHEL 8 |
| STIG RHEL 8 V2R6 | `stig-rhel8-v2r6` | STIG for RHEL 8 |

## Next Steps

- **Remediate failures:** Use `kensa remediate` with `--dry-run` first, then run for real with `--rollback-on-failure` for safety. See the Admin Guide.
- **Customize variables:** Override password policies, SSH settings, and banner text via `config/conf.d/`. See the Admin Guide.
- **Understand evidence output:** Learn how to interpret `evidence.json` for auditors. See the Auditor Guide.
- **Track compliance drift:** Use `kensa history` and `kensa diff` to compare scans over time.
- **Look up rules:** Use `kensa info 5.1.20` or `kensa info V-257947` to find rules by framework reference.
