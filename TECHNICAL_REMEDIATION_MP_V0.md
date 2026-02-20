# Technical Remediation Master Plan — Version 0

**Project:** Kensa
**Date:** 2026-02-04
**Status:** Draft — Philosophical Foundation

---

## 1. The Problem

### 1.1 How the Industry Builds Compliance Automation Today

Every major compliance automation effort follows the same pattern:

1. Pick a benchmark (e.g., CIS RHEL 9 v2.0.0).
2. Pick a tool (Ansible, Puppet, Bash, PowerShell).
3. Write one task/resource/function per recommendation.
4. Ship it as a role, module, or script bundle scoped to that benchmark and OS.

The result is a discrete artifact: `RHEL9-CIS`, `RHEL8-STIG`, `RHEL9-STIG`. Each is
self-contained. Each is maintained independently. Each is a full copy of the compliance
logic for that specific intersection of framework and operating system.

This is the model used by:

- **Ansible Lockdown** (MindPoint Group): Separate repositories per OS per benchmark.
  `RHEL8-CIS`, `RHEL9-CIS`, `RHEL8-STIG`, `RHEL9-STIG` — four repos that share
  70-80% of their logic but are maintained as independent codebases.

- **ComplianceAsCode** (OpenSCAP upstream): Uses Jinja2 templates with some shared
  content, but ultimately renders into per-OS SCAP datastreams. The output is
  `ssg-rhel8-ds.xml`, `ssg-rhel9-ds.xml` — separate artifacts with separate rule sets.

- **DISA STIG Ansible**: Ships as separate zip archives per OS version, as seen in this
  directory. `U_RHEL_8_V2R6_STIG_Ansible.zip` and `U_RHEL_9_V2R7_STIG_Ansible.zip`
  are independent playbooks with near-identical structure.

- **CIS Hardening scripts**: Per-OS, per-benchmark. Always.

- **Puppet modules** (e.g., `simp`, `hardening`): Same pattern.

### 1.2 The Combinatorial Problem

For a single OS family like RHEL, the matrix looks like this:

| Framework | RHEL 8 | RHEL 9 | RHEL 10 |
|-----------|--------|--------|---------|
| CIS       | Full playbook | Full playbook | Full playbook |
| STIG      | Full playbook | Full playbook | Full playbook |

That is six full codebases. Add Ubuntu, SUSE, Debian, Oracle Linux, and the matrix
becomes:

|           | RHEL 8 | RHEL 9 | RHEL 10 | Ubuntu 22.04 | Ubuntu 24.04 | SUSE 15 |
|-----------|--------|--------|---------|--------------|--------------|---------|
| CIS       | ✦      | ✦      | ✦       | ✦            | ✦            | ✦       |
| STIG      | ✦      | ✦      | ✦       | ✦            | ✦            | ✦       |

Each ✦ is a full, independently maintained automation artifact. Twelve codebases. For
two frameworks.  Add PCI-DSS hardening guides, NIST 800-171 overlays, or organization-
specific baselines, and the number keeps climbing.

### 1.3 The Consequences

**Drift.** When a bug is fixed in `RHEL9-CIS` task 5.2.4 (SSH MaxAuthTries), that same
fix must be manually ported to `RHEL8-CIS`, `RHEL9-STIG`, and every other artifact
that implements the same control. In practice, it isn't. The codebases drift. The same
logical control behaves differently depending on which artifact was applied. Compliance
results become inconsistent — not because the systems differ, but because the
automation does.

**Delayed coverage.** When RHEL 10 ships, every benchmark and every automation artifact
must be rebuilt from scratch. It takes DISA 6-18 months to publish a new STIG. CIS
follows a similar timeline. Ansible Lockdown creates a new repo and starts writing. The
organization running RHEL 10 in production has no automation until someone completes
the full rewrite — even though 85%+ of the controls are mechanically identical to
RHEL 9.

**False complexity.** Teams perceive compliance automation as inherently expensive because
every new OS or framework "requires" a full implementation effort. This is not inherent
complexity — it is accidental complexity created by the architecture. The actual
security controls are not that different. The automation model makes them appear so.

**Maintenance burden.** Maintaining N full codebases means N times the testing, N times
the review, N times the release cycle. Teams burn out. Playbooks go stale. Security
controls that should be enforced aren't, because the automation that enforces them
hasn't been updated in 18 months.

### 1.4 Root Cause

The root cause is a design decision made so consistently across the industry that it
feels like a law of nature:

> **Policy and mechanism are fused into a single artifact, organized by the structure
> of the benchmark document rather than the structure of the problem.**

CIS publishes a PDF per OS. DISA publishes a STIG per OS. So we build a playbook per
OS. The organizational structure of the *document* becomes the organizational structure
of the *code*. Conway's Law, applied to compliance content.

But the document structure serves auditors — humans who need to look up "what does
RHEL 9 require for SSH?" The automation structure should serve machines — which need
to answer "how do I ensure SSH root login is disabled on this system, right now?"

These are different questions. They demand different architectures.

---

## 2. Philosophy

### 2.1 A Rule is Not a Task

A compliance rule is a statement of desired state:

> *Root login over SSH must be disabled.*

It is not an Ansible task. It is not a Bash command. It is not a SCAP check. Those are
*implementations* of the rule — mechanisms that verify or enforce the desired state on
a specific platform using a specific tool.

The rule exists independent of any mechanism. It existed before Ansible. It will exist
after Ansible. It is true on RHEL 8 and RHEL 9 and RHEL 10 and every future version
of every Linux distribution that ships OpenSSH. The mechanism may vary. The rule does
not.

**Principle 1: Separate the rule from its implementation. The rule is the stable core.
Implementations are the variable shell.**

### 2.2 Operating Systems Have Capabilities, Not Just Version Numbers

The standard pattern in compliance automation is:

```yaml
when: ansible_distribution == "RedHat" and ansible_distribution_major_version == "9"
```

This is fragile and semantically wrong. The question is not "is this RHEL 9?" The
question is: "does this system support `sshd_config.d` drop-in files?" or "does this
system use `authselect` or `authconfig`?" or "does this system enforce crypto policies
via `update-crypto-policies`?"

Version numbers are a proxy for capabilities. They are an unreliable proxy — because
capabilities change within a major version (RHEL 8.6 introduced features absent in
8.0), because derivative distributions share capabilities across different version
numbers (CentOS Stream 9, Rocky 9, Alma 9, Oracle Linux 9 all share RHEL 9's
capabilities), and because future versions inherit most capabilities from their
predecessors.

**Principle 2: Target capabilities, not version strings. Detect what the system supports
and act on that. A capability-based model extends forward in time without modification.**

The practical differences between RHEL 8, 9, and 10 for compliance purposes are
concentrated in a small number of capability dimensions:

| Capability                  | RHEL 8       | RHEL 9       | RHEL 10      |
|-----------------------------|--------------|--------------|--------------|
| sshd_config.d drop-ins      | Supported¹   | Default      | Default      |
| authselect                   | Primary      | Primary      | Primary      |
| crypto-policies              | Yes          | Yes          | Yes          |
| crypto-policy modules        | Limited      | Extended     | Extended     |
| FIPS mode via crypto-policy  | Yes          | Yes          | Yes          |
| firewalld backend            | iptables²    | nftables     | nftables     |
| systemd-resolved             | Optional     | Default³     | Default      |
| System-wide TLS (MIN_TLS)    | 1.2          | 1.2          | 1.3⁴        |
| audit immutable rules        | Yes          | Yes          | Yes          |
| GRUB BLS                     | Optional     | Default      | Default      |
| rsyslog → journald default   | rsyslog      | journald     | journald     |
| GnuTLS / OpenSSL default     | OpenSSL      | OpenSSL      | OpenSSL      |
| PAM faillock (replaces pam_tally2) | Yes⁵   | Yes          | Yes          |

¹ Requires OpenSSH 8.2+, available in RHEL 8.3+
² nftables backend available but iptables is default
³ May vary by installation profile
⁴ Subject to final RHEL 10 GA configuration
⁵ pam_tally2 deprecated in RHEL 8, removed in RHEL 9

A remediation that detects "does sshd_config.d exist and is Include configured?"
rather than "is this RHEL >= 9?" will work correctly on RHEL 8 systems that have been
updated, on RHEL 9, on RHEL 10, and on any future version — without a single line of
change.

### 2.3 Model the Delta, Not the Whole

Between any two consecutive RHEL major versions, the overlap in security-relevant
configuration is approximately 85-90%. Between CIS and STIG for the same OS, the
overlap in actual system changes (not documentation, but what you would configure) is
approximately 70-80%.

The current approach models 100% of each combination. The correct approach models:

- **The common core** — controls that are mechanically identical across all supported
  platforms and frameworks. This is the majority of the work, and it is written once.

- **The delta** — controls where the mechanism genuinely differs by platform capability.
  These are thin overlays, not full playbooks. They are the exception, and they look
  like exceptions in the codebase.

**Principle 3: One canonical rule set. Thin overlays for genuine differences. The overlay
is the thing you maintain when a new OS ships — not a clone of the world.**

### 2.4 Frameworks Are Metadata, Not Structure

"Disable SSH root login" maps to:

| Framework       | Identifier            |
|-----------------|-----------------------|
| CIS RHEL 8      | 5.2.10                |
| CIS RHEL 9      | 5.2.3                 |
| CIS RHEL 10     | 5.1.4                 |
| STIG RHEL 8     | V-230296 (SV-230296r1) |
| STIG RHEL 9     | V-257947              |
| NIST 800-53     | AC-6(2), AC-17(2)     |
| PCI-DSS 4.0     | 2.2.6, 8.6.1          |
| ISO 27001:2022  | A.8.9                 |
| CMMC L2         | AC.L2-3.1.12          |
| HIPAA           | §164.312(a)(1)        |

These are not ten different rules. They are ten different *labels* for the same rule.
The CIS number for RHEL 8 is different from the CIS number for RHEL 9 because CIS
reorganized their benchmark. The underlying control did not change. The SSH
configuration did not change. The desired state did not change.

**Principle 4: Framework identifiers are cross-references attached to rules as metadata.
They do not define the structure of the rule set. Adding a new framework means adding
a new column of labels, not a new set of rules.**

### 2.5 Compliance Is a Continuous Spectrum, Not a Binary

Traditional automation treats each control as pass/fail and each benchmark as a
checklist. But real compliance has nuance:

- A system may have the correct setting but lack the mechanism to survive reboot.
- A control may be implemented in a way that technically passes but is operationally
  fragile (e.g., hardcoded in the main config file instead of a managed drop-in).
- A system may be compliant with the letter of a control but violate its intent.
- A remediation may fix the immediate finding but create a regression in another
  control.

**Principle 5: Prefer remediations that are durable, idempotent, and minimally
invasive. Favor the mechanism that survives the most change — package updates, config
management runs, reboots, upgrades — without breaking or requiring re-application.**

### 2.6 Forward Compatibility Is a Design Requirement

The most expensive moment in a compliance program is when a new OS version ships.
If the automation requires a full rebuild for each new version, the program is
permanently reactive — always 6-18 months behind the OS lifecycle.

**Principle 6: A new OS version should require only the addition of its genuinely new
exceptions. If 90% of the automation works without modification on RHEL N+1, then 90%
of the automation must work without modification on RHEL N+1. The architecture must
guarantee this, not rely on manual porting.**

---

## 3. The Approach

### 3.1 Architecture: Three Layers

```
┌──────────────────────────────────────────────────────────────────┐
│                        FRAMEWORK MAPPINGS                        │
│   CIS 8/9/10  ·  STIG 8/9  ·  NIST 800-53  ·  PCI-DSS  · ... │
│                     (metadata layer — labels)                    │
└──────────────────────────┬───────────────────────────────────────┘
                           │ references
┌──────────────────────────▼───────────────────────────────────────┐
│                        CANONICAL RULES                           │
│                                                                  │
│   rule: ssh-disable-root-login                                   │
│   rule: ssh-max-auth-tries                                       │
│   rule: sshd-crypto-policy                                       │
│   rule: audit-privileged-commands                                │
│   rule: pam-faillock-deny                                        │
│   ...                                                            │
│                                                                  │
│   Each rule declares: desired state, severity, rationale,        │
│   and one or more platform implementations.                      │
└──────────────────────────┬───────────────────────────────────────┘
                           │ implements
┌──────────────────────────▼───────────────────────────────────────┐
│                    PLATFORM IMPLEMENTATIONS                      │
│                                                                  │
│   ssh-disable-root-login:                                        │
│     ├── default:    set PermitRootLogin no in sshd_config        │
│     └── capability(sshd_config_d):                               │
│                     set PermitRootLogin no in drop-in file       │
│                                                                  │
│   pam-faillock-deny:                                             │
│     ├── capability(authselect): authselect + faillock config     │
│     └── fallback:   direct PAM stack modification                │
│                                                                  │
│   Implementations are selected at runtime by capability          │
│   detection, not by OS version conditionals.                     │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 The Canonical Rule

A canonical rule is the atomic unit. It represents one security control, independent
of any framework or OS version.

```
Rule: ssh-disable-root-login
├── id:          ssh-disable-root-login
├── title:       Disable SSH Root Login
├── description: The SSH daemon must not allow direct login as root. Root access
│                over SSH provides a high-value target for attackers and bypasses
│                accountability mechanisms that tie actions to individual users.
├── severity:    high
├── rationale:   Direct root login cannot be attributed to an individual user,
│                violating the principle of individual accountability. It also
│                exposes the highest-privilege account to brute-force attacks
│                on a network-accessible service.
│
├── frameworks:
│   ├── cis_rhel8:       ["5.2.10"]
│   ├── cis_rhel9:       ["5.2.3"]
│   ├── cis_rhel10:      ["5.1.4"]
│   ├── stig_rhel8:      ["V-230296"]
│   ├── stig_rhel9:      ["V-257947"]
│   ├── nist_800_53:     ["AC-6(2)", "AC-17(2)", "IA-2(5)"]
│   ├── pci_dss_4:       ["2.2.6", "8.6.1"]
│   ├── iso27001_2022:   ["A.8.9"]
│   ├── cmmc_l2:         ["AC.L2-3.1.12"]
│   └── hipaa:           ["164.312(a)(1)"]
│
├── check:
│   ├── method:  config_value
│   ├── target:  sshd                          # logical service
│   ├── key:     PermitRootLogin
│   └── expected: "no"
│
├── remediation:
│   ├── default:
│   │   ├── mechanism:   config_set
│   │   ├── service:     sshd
│   │   ├── key:         PermitRootLogin
│   │   ├── value:       "no"
│   │   └── restart:     sshd
│   │
│   └── when(sshd_config_d):                   # capability gate
│       ├── mechanism:   config_set_dropin
│       ├── service:     sshd
│       ├── dropin_dir:  /etc/ssh/sshd_config.d
│       ├── dropin_file: 99-kensa-root-login.conf
│       ├── key:         PermitRootLogin
│       ├── value:       "no"
│       └── restart:     sshd
│
└── tags:
    ├── category:  access-control
    ├── service:   ssh
    └── impact:    authentication
```

Key properties:

- **One rule, one control.** There is exactly one `ssh-disable-root-login` rule, not one
  per OS, not one per framework.

- **Frameworks are metadata.** The rule carries its framework mappings as a flat
  dictionary. Adding CIS RHEL 11 support means adding one line to this map. Not a new
  rule. Not a new playbook.

- **Implementations are capability-gated.** The `when(sshd_config_d)` block is selected
  when the target system has the `sshd_config_d` capability. This is detected at
  runtime by probing the system, not by checking a version string.

- **The default is the common case.** Most implementations have a `default` path that
  works on the broadest set of systems. Capability-specific paths exist only where the
  mechanism genuinely differs.

### 3.3 Capability Detection

Capabilities are facts about the target system that determine which implementation
path to use. They are detected at the start of a remediation run and cached for the
session.

Capabilities are boolean or valued properties. Examples:

| Capability              | Detection Method                                      |
|-------------------------|-------------------------------------------------------|
| `sshd_config_d`         | Directory `/etc/ssh/sshd_config.d` exists AND main    |
|                         | `sshd_config` contains `Include` directive            |
| `authselect`            | `authselect current` exits 0                          |
| `crypto_policies`       | `update-crypto-policies --show` exits 0               |
| `crypto_policy_modules` | Directory `/etc/crypto-policies/policies/modules`     |
|                         | exists (RHEL 9+)                                      |
| `firewalld_nftables`    | `firewall-cmd --get-backend` returns `nftables`       |
| `systemd_resolved`      | `systemctl is-active systemd-resolved` exits 0        |
| `pam_faillock`          | `/etc/security/faillock.conf` exists                  |
| `grub_bls`              | `grub2-editenv list` succeeds and GRUB BLS entries    |
|                         | exist in `/boot/loader/entries/`                      |
| `journald_primary`      | `systemctl is-active rsyslog` fails OR journald       |
|                         | configured as primary                                 |
| `fapolicyd`             | `rpm -q fapolicyd` exits 0                            |
| `selinux`               | `getenforce` returns `Enforcing` or `Permissive`      |
| `audit_immutable`       | Supported on all target versions (always true)         |
| `aide`                  | `rpm -q aide` exits 0                                 |
| `tpm2`                  | `/sys/class/tpm/tpm0` exists                          |
| `dnf_automatic`         | `rpm -q dnf-automatic` exits 0                        |
| `usbguard`              | `rpm -q usbguard` exits 0                             |
| `package_manager`       | `dnf` (RHEL 8+). Value: `dnf`                         |

Detection runs once per host at the beginning of a session. It is fast (under 2
seconds for all capabilities) because each detection is a single command or file
existence check. The resulting capability set is a flat key-value map that
implementations reference.

This model has a critical forward-compatibility property: **when a new OS version ships,
the capability detection runs against it and produces a capability set.** If RHEL 11
supports `sshd_config_d` (it will), the detection returns true, and the `sshd_config_d`
implementation path is selected — without any change to the rules, the detection logic,
or the implementation code.

The only time new work is required is when a genuinely new capability appears (e.g., a
new authentication mechanism, a new firewall backend). That is a real change — it
deserves new code. Everything else is covered by existing detection.

### 3.4 Implementation Mechanisms

Remediation implementations use a small set of composable mechanisms rather than
arbitrary scripts. This keeps the rule set declarative and auditable.

| Mechanism              | Description                                             |
|------------------------|---------------------------------------------------------|
| `config_set`           | Set key=value in a configuration file                   |
| `config_set_dropin`    | Set key=value in a drop-in file in a `.d` directory     |
| `config_remove`        | Remove or comment out a key from a config file          |
| `config_ensure_block`  | Ensure a multiline block exists in a file               |
| `file_permissions`     | Set owner, group, mode on a file or directory           |
| `file_absent`          | Ensure a file does not exist                            |
| `service_enabled`      | Ensure a systemd service is enabled and started         |
| `service_disabled`     | Ensure a systemd service is disabled and stopped        |
| `service_masked`       | Ensure a systemd service is masked                      |
| `package_present`      | Ensure a package is installed                           |
| `package_absent`       | Ensure a package is not installed                       |
| `sysctl_set`           | Set a kernel parameter via sysctl (persisted)           |
| `kernel_module_disabled` | Blacklist a kernel module                             |
| `grub_parameter`       | Set or remove a kernel boot parameter                   |
| `mount_option`         | Ensure a mount point has specific options in fstab      |
| `pam_module`           | Configure a PAM module (via authselect when available)  |
| `audit_rule`           | Ensure an audit rule exists in audit.rules              |
| `cron_job`             | Ensure a cron job or systemd timer exists               |
| `selinux_boolean`      | Set an SELinux boolean                                  |
| `command_exec`         | Run an arbitrary command (escape hatch — audited)       |

Each mechanism is idempotent by design. Running it twice produces the same result as
running it once. Each mechanism is also reversible — the prior state is captured before
modification for rollback support.

The `command_exec` mechanism is an explicit escape hatch for controls that do not fit
the declarative model. Its use is audited and flagged. Over time, patterns that
repeatedly use `command_exec` should be promoted to first-class mechanisms.

### 3.5 Rule Categories and the Real Differences

To quantify the "copy-paste" problem, the controls from CIS RHEL 8, CIS RHEL 9,
CIS RHEL 10, STIG RHEL 8, and STIG RHEL 9 can be classified into three categories
based on how their remediation differs across OS versions:

**Category A — Identical Across All Versions (~70-75%)**

These controls use the exact same mechanism on every supported OS. The configuration
file, key, value, service, and package are identical.

Examples:
- Set `PermitRootLogin no` in sshd_config
- Set `net.ipv4.conf.all.send_redirects = 0` via sysctl
- Ensure `auditd` service is enabled
- Set file permissions on `/etc/passwd` to 0644
- Disable `cramfs`, `freevxfs`, `hfs` kernel modules
- Set `PASS_MAX_DAYS 365` in `/etc/login.defs`
- Ensure `nodev`, `nosuid`, `noexec` on `/tmp`
- Ensure `aide` package is installed

These rules require zero platform-specific logic. One implementation. Universal.

**Category B — Capability-Gated Variation (~15-20%)**

These controls have the same desired state but use a different mechanism depending on
a detected capability. The variations are thin and systematic.

Examples:
- SSH configuration → `sshd_config` (direct) vs `sshd_config.d/` (drop-in)
- PAM configuration → `authselect` vs direct PAM modification
- Cryptographic policy → `update-crypto-policies` with or without subpolicy modules
- Firewall backend → `iptables` rules vs `nftables` rules
- Logging → `rsyslog` configuration vs `journald` configuration
- GRUB configuration → `grub2-mkconfig` vs BLS entry modification

Each of these has exactly two or three implementation paths, selected by capability
detection. The capability gate is the only branching logic.

**Category C — Genuinely OS-Specific (~5-10%)**

A small number of controls exist only in certain benchmarks or require fundamentally
different approaches on different platforms. These are the true exceptions.

Examples:
- Controls for services that exist only on certain versions (e.g., `rsh`, `telnet`
  removed entirely in newer versions — control becomes N/A)
- Controls referencing default values that changed between versions (e.g., a default
  that was insecure in RHEL 8 but secure in RHEL 9 — the check logic differs)
- Controls for features introduced in a specific version (e.g., `fapolicyd`
  application whitelisting, more prominent in RHEL 9+ STIGs)

Category C is genuinely different. It deserves version-specific or capability-specific
treatment. But it is 5-10% of the total — not 100%.

**The current industry approach treats all three categories as Category C.** Every rule
is rewritten for every OS. That is the core inefficiency.

### 3.6 Framework Mapping Layer

Framework mappings are a separate data structure that references canonical rules by ID.
They express relationships like:

```
CIS RHEL 9 v2.0.0:
  Section 5.2.3 → ssh-disable-root-login
  Section 5.2.4 → ssh-max-auth-tries
  Section 5.2.5 → ssh-log-level
  ...

STIG RHEL 9 V2R7:
  V-257947 → ssh-disable-root-login
  V-257948 → ssh-max-auth-tries
  ...

NIST 800-53 Rev 5:
  AC-6(2)  → [ssh-disable-root-login, sudo-require-auth, ...]
  AC-17(2) → [ssh-disable-root-login, ssh-crypto-policy, ...]
  ...
```

This structure enables:

- **Generate a CIS RHEL 9 report** by filtering the canonical rules through the
  CIS RHEL 9 mapping and producing results in CIS numbering order.

- **Generate a STIG RHEL 8 checklist** by filtering through the STIG RHEL 8 mapping
  and outputting STIG Finding IDs.

- **Cross-reference frameworks** by noting that CIS 5.2.3 and STIG V-257947 are the
  same underlying control, because they both map to `ssh-disable-root-login`.

- **Add a new framework** by adding a new mapping file. No rules change. No
  implementations change.

- **Add a new OS version's benchmark** by adding a new mapping file that references
  the same canonical rules with the new benchmark's numbering. If the CIS RHEL 11
  benchmark renumbers SSH root login from 5.2.3 to 6.1.4, the mapping says
  `6.1.4 → ssh-disable-root-login`. The rule and its implementation are untouched.

### 3.7 Execution Model

A remediation run proceeds in four phases:

```
Phase 1: DETECT
   Connect to target host
   Run capability detection
   Produce capability set: {sshd_config_d: true, authselect: true, ...}

Phase 2: RESOLVE
   Take the set of requested rules (from a framework mapping, custom selection, etc.)
   For each rule, select the implementation path matching the detected capabilities
   Produce an execution plan: ordered list of concrete actions

Phase 3: EXECUTE
   For each action in the plan:
     Record pre-state (for rollback)
     Apply the change (idempotently)
     Verify the change took effect
     Record result (pass/fail/error)

Phase 4: REPORT
   Produce results mapped to the requested framework(s)
   Flag any rules that could not be resolved (no matching implementation for
   detected capabilities — indicates a gap requiring new implementation)
   Summarize: applied, already-compliant, failed, not-applicable
```

Phase 2 is where the capability-based selection happens. It replaces the cascade of
`when:` conditionals in traditional Ansible roles with a single lookup: "given these
capabilities, which implementation variant applies?" This is a table lookup, not a
conditional tree.

Phase 3 is intentionally conservative. Each action verifies its own result. If a
`config_set` for `PermitRootLogin no` is applied but a subsequent check shows the
value is still `yes` (perhaps overridden by a later Include), the action reports
failure. The system does not assume success because the write succeeded.

### 3.8 What Changes When a New OS Ships

Scenario: RHEL 11 is released. CIS publishes the CIS RHEL 11 Benchmark. DISA
publishes the RHEL 11 STIG.

**Under the current approach:** New repos are created. ~250 Ansible tasks are written
from scratch. Testing begins. Coverage is months away.

**Under this approach:**

1. Run capability detection against a RHEL 11 system. Review the capability set.
   Likely result: identical to RHEL 10 for 95%+ of capabilities.

2. Identify genuinely new capabilities or changed behaviors. Example: perhaps RHEL 11
   introduces a new authentication mechanism or changes a default crypto policy.
   Write implementations for the 3-5 affected rules. Add new capability detections
   if needed.

3. Create new framework mapping files:
   - `cis_rhel11_v1.0.0.yaml` — maps CIS RHEL 11 section numbers to canonical rule IDs
   - `stig_rhel11_v1r1.yaml` — maps STIG RHEL 11 Finding IDs to canonical rule IDs

4. Done. The 95% of rules that are mechanically identical work immediately. The 5%
   that genuinely changed have new implementation variants. The framework mappings
   produce correctly numbered reports for auditors.

Time to coverage: days, not months.

---

## 4. Scope and Boundaries

### 4.1 In Scope for V0

- **RHEL family**: RHEL 8, 9, 10 (and binary-compatible derivatives: CentOS Stream,
  Rocky Linux, AlmaLinux, Oracle Linux)
- **Frameworks**: CIS Benchmarks, DISA STIGs
- **Framework cross-references**: NIST 800-53, PCI-DSS (as metadata labels, not
  separate rule sets)
- **Remediation mechanisms**: The mechanism table in 3.4
- **Execution**: Remote via SSH, local execution
- **Rule format**: YAML-based canonical rule definitions

### 4.2 Out of Scope for V0 (Future Phases)

- **Non-RHEL Linux**: Ubuntu, SUSE, Debian. The architecture supports them (they are
  just different capability sets and framework mappings), but V0 focuses on RHEL to
  prove the model with the deepest benchmark coverage.
- **Windows**: Fundamentally different mechanism layer. Same philosophical approach
  applies, but the implementation substrate is entirely different.
- **Cloud/Container benchmarks**: CIS Kubernetes, CIS Docker, cloud provider
  benchmarks. Same architectural principles, different capability domain.
- **GUI-based remediations**: Controls requiring graphical environment (GNOME/KDE
  settings). These can be addressed but are lower priority for server workloads.

### 4.3 Success Criteria

The architecture is validated when:

1. A single canonical rule set covers CIS RHEL 8, CIS RHEL 9, CIS RHEL 10, STIG
   RHEL 8, and STIG RHEL 9 — the five benchmarks represented by the reference
   materials in this directory.

2. Adding coverage for a new RHEL version requires modifying fewer than 10% of the
   canonical rules.

3. Adding coverage for a new framework (e.g., PCI-DSS hardening guide) requires zero
   changes to canonical rules — only a new mapping file.

4. The same rule applied to RHEL 8 and RHEL 9 produces correct, idempotent
   remediation on both — automatically selecting the appropriate mechanism based on
   detected capabilities.

5. An auditor can generate a report in CIS format or STIG format from the same scan
   results, with correct framework-specific numbering.

---

## 5. Risks and Mitigations

| Risk | Description | Mitigation |
|------|-------------|------------|
| **Abstraction leakage** | Some controls may not fit cleanly into the declarative mechanism model, requiring excessive use of `command_exec`. | Track `command_exec` usage. If a pattern emerges, promote it to a first-class mechanism. The mechanism table is extensible. |
| **Capability detection inaccuracy** | A capability probe could return a false positive or negative (e.g., `sshd_config.d` exists but the Include directive was removed). | Each detection is a precise, multi-condition check. Test capability detection against known system states. Allow manual capability overrides. |
| **Framework mapping maintenance** | Mapping files must be updated when new benchmark versions publish, even though rules don't change. | Mapping creation is mechanical — it maps section/finding numbers to canonical IDs. This can be partially automated by diffing consecutive benchmark versions. |
| **Edge cases between RHEL derivatives** | Rocky Linux, AlmaLinux, or Oracle Linux may diverge from RHEL in security-relevant ways. | Capability detection is agnostic to distribution name. If a derivative diverges, the capability probe will reflect that, and the correct implementation path will be selected. |
| **Complexity of PAM stack** | PAM configuration is one of the most fragile areas of Linux system administration. `authselect` helps but does not cover all cases. | Isolate PAM into a dedicated mechanism with conservative change semantics. Always verify PAM state after modification. Provide rollback. |
| **Rule conflicts** | Two rules in the same run could set contradictory values (e.g., one requires `MaxAuthTries 4`, another requires `MaxAuthTries 3`). | Detect conflicts in the RESOLVE phase before execution. Flag them as errors. Defer resolution to the operator. |

---

## 6. What We Are Not Building

Clarity on non-goals prevents scope creep and architectural contamination:

- **Not a configuration management tool.** Kensa does not replace Puppet or Ansible for
  general system configuration. It is concerned exclusively with security compliance
  controls.

- **Not a scanning-only tool.** Kensa is not an alternative to OpenSCAP for assessment.
  It is the remediation and enforcement counterpart. It can verify its own remediations,
  but it is not a general-purpose vulnerability scanner.

- **Not a policy-as-code language.** We are not inventing a new DSL for compliance. The
  rule format is YAML. The mechanisms are composable primitives. The execution is
  straightforward. Expressiveness is intentionally limited to keep rules auditable by
  compliance engineers who are not software developers.

- **Not a replacement for reading the benchmarks.** Auditors and compliance engineers
  must still understand the controls. Kensa automates the remediation. It does not
  replace the human judgment that determines which controls apply and how to handle
  exceptions.

---

## 7. Guiding Principles Summary

1. **Separate the rule from its implementation.** The rule is the stable core.
   Implementations are the variable shell.

2. **Target capabilities, not version strings.** Detect what the system supports and
   act on that.

3. **Model the delta, not the whole.** One canonical rule set. Thin overlays for
   genuine differences.

4. **Frameworks are metadata, not structure.** Framework identifiers are cross-
   references, not reasons to duplicate rules.

5. **Prefer durable, idempotent, minimally invasive remediations.** Favor the mechanism
   that survives the most change.

6. **Forward compatibility is a design requirement.** A new OS version should require
   only its genuinely new exceptions.

---

*This document defines the philosophical and architectural foundation for Kensa. It is
version 0 — a statement of intent and direction. Implementation details, file formats,
and tooling choices will be developed in subsequent documents as the canonical rule set
takes shape against the reference benchmarks in this directory.*
