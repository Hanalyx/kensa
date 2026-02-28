# Kensa Compliance Philosophy

## The Problem with Compliance Automation

Every major compliance automation effort follows the same pattern: pick a benchmark, pick an OS, write a full set of tasks scoped to that intersection. The result is a discrete artifact — `RHEL9-CIS`, `RHEL8-STIG` — maintained independently.

This is the model used by Ansible Lockdown, ComplianceAsCode, DISA STIG Ansible, CIS hardening scripts, and Puppet modules. Each publishes separate codebases per OS per benchmark.

For two frameworks across three RHEL versions, that is six full codebases. Add Ubuntu, SUSE, and a few more frameworks, and the matrix grows multiplicatively. Each cell is an independently maintained artifact that shares 70-85% of its logic with its neighbors.

The consequences are predictable:

- **Drift.** A bug fixed in one artifact is rarely ported to all others. The same logical control behaves differently depending on which artifact was applied.
- **Delayed coverage.** When a new OS ships, every artifact must be rebuilt from scratch. Coverage arrives months later, even though 90% of the controls are mechanically identical to the previous version.
- **False complexity.** Teams perceive compliance automation as inherently expensive because every new OS or framework requires a full implementation effort. This is accidental complexity, not inherent complexity.

The root cause is a design decision so consistent across the industry it feels like a law of nature: policy and mechanism are fused into a single artifact, organized by the structure of the benchmark document rather than the structure of the problem.

## How Kensa Thinks About Compliance

Kensa is built on six principles that address this structural problem.

### 1. Separate the Rule from Its Implementation

A compliance rule is a statement of desired state: "Root login over SSH must be disabled." It is not an Ansible task, a Bash command, or a SCAP check. Those are implementations — mechanisms that verify or enforce the desired state on a specific platform.

Kensa keeps one canonical rule per security control. Implementations are attached to the rule as capability-gated variants, not as separate codebases.

### 2. Target Capabilities, Not Version Strings

The question is not "is this RHEL 9?" The question is "does this system support sshd_config.d drop-in files?" or "does this system use authselect?"

Version numbers are an unreliable proxy for capabilities — capabilities change within a major version, and derivative distributions share capabilities across different version numbers. Kensa detects 22 capabilities at runtime and selects the correct implementation variant for each host. A rule written today works on future OS versions without modification, as long as the capability still exists.

### 3. Model the Delta, Not the Whole

Between consecutive RHEL major versions, 85-90% of security-relevant configuration is identical. Between CIS and STIG for the same OS, 70-80% overlap. The industry models 100% of each combination. Kensa models the common core once and maintains thin overlays only where the mechanism genuinely differs.

When a new OS version ships, the work is limited to the 5-10% of controls where something actually changed — not a clone of the world.

### 4. Frameworks Are Metadata, Not Structure

"Disable SSH root login" maps to CIS RHEL 9 Section 5.1.20, STIG V-257947, NIST 800-53 AC-6(2), PCI-DSS 2.2.6, and FedRAMP AC-6(2). These are not five different rules. They are five labels for the same rule.

Kensa stores framework identifiers as cross-references attached to canonical rules. Adding a new framework means adding a column of labels, not a new set of rules. Run one scan, satisfy multiple assessors from the same results.

### 5. Prefer Durable, Idempotent Remediations

Not all fixes are equal. A setting written to a drop-in file in a `.d/` directory survives package updates. The same setting written directly to the main config file gets overwritten on the next `dnf update`.

Kensa uses 23 typed, declarative mechanisms instead of arbitrary scripts. Each mechanism is idempotent by design — running it twice produces the same result as running it once. When a more durable option exists (drop-in files, authselect features, dedicated config files), Kensa uses it.

### 6. Forward Compatibility Is a Design Requirement

The most expensive moment in a compliance program is when a new OS version ships. If the automation requires a full rebuild, the program is permanently reactive.

Kensa's architecture guarantees that the majority of rules work on new OS versions without modification. Capability detection runs against the new system, produces a capability set, and existing implementation paths are selected automatically. New work is required only for genuinely new capabilities or changed behaviors.

## Architecture: Three Layers

Kensa separates compliance content into three distinct layers:

**Framework Mappings** sit at the top. They are pure metadata — tables that map framework-specific identifiers (CIS section numbers, STIG Finding IDs, NIST control numbers) to canonical rule IDs. Adding a new benchmark version means adding a new mapping file. No rules change.

**Canonical Rules** form the stable core. Each rule declares a desired state, severity, category, framework references, and one or more implementations. There is exactly one rule per security control, regardless of how many frameworks reference it.

**Platform Implementations** are the variable shell. Each implementation is gated by a detected capability, not a version string. A rule for SSH root login has a `sshd_config_d` variant (writes a drop-in file) and a `default` variant (edits the main config). The runtime selects the right one.

## Evidence-First Design

Kensa captures raw, machine-verifiable evidence for every check — the exact command that ran, the raw stdout, the exit code, the expected value, the actual value, and a timestamp. This is not an interpreted summary. It is the system's own output, preserved for independent verification.

An auditor receiving Kensa evidence can see exactly what was measured and confirm the result without re-running the scan. This shifts compliance from "trust the tool" to "verify the evidence."

## Safe Remediation

Compliance tools that stop at scanning leave remediation to ad-hoc scripts. Tools that include remediation typically use arbitrary shell commands with no safety net.

Kensa takes a different approach:

- **Typed mechanisms.** Every remediation uses a declared mechanism type (config_set, file_permissions, service_enabled, etc.), not arbitrary commands. The mechanism constrains what can happen.
- **Pre-state capture.** Before any change, Kensa captures the current state. This creates a snapshot that enables rollback.
- **Automatic rollback.** If a remediation step fails or the post-change verification shows the fix didn't take effect, completed steps are reversed in order. The system is never left half-remediated.
- **Risk classification.** Each remediation mechanism and target path is classified by risk level (high, medium, low). Operators can configure snapshot behavior based on risk tolerance.

The result: remediation is a first-class operation with the same rigor as scanning, not an afterthought.

## What Kensa Is Not

- **Not a configuration management tool.** Kensa does not replace Puppet or Ansible for general system configuration. It handles security compliance controls exclusively.
- **Not a policy language.** Rules are YAML with constrained mechanisms. Expressiveness is intentionally limited to keep rules auditable by compliance engineers who are not developers.
- **Not a replacement for reading the benchmarks.** Kensa automates measurement and remediation. It does not replace the human judgment that determines which controls apply and how to handle exceptions.
