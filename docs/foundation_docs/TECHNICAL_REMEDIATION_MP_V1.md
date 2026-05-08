# Technical Remediation Master Plan — Version 1

**Project:** Kensa
**Date:** 2026-04-13
**Status:** Draft — Philosophical Foundation
**Supersedes:** `TECHNICAL_REMEDIATION_MP_V0.md` (retained for historical reference)
**Companion:** `CANONICAL_RULE_SCHEMA_V1.md`, `RULE_REVIEW_GUIDE_V1.md`, `TRANSACTION_CONTRACT_V1.md`

---

## 0. What Changed from V0

V0 established the three-layer architecture (framework mappings → canonical rules → platform
implementations), the six principles (rule separation, capability targeting, delta modeling,
framework metadata, durable mechanisms, forward compatibility), and a four-phase execution
model (DETECT → RESOLVE → EXECUTE → REPORT).

V1 retains all of that. It adds one principle and names one sub-structure:

- **New Principle 7: Atomicity.** Every mutation is a transaction. A rule either lands
  completely or leaves the system in the exact state it was in before the rule began. There
  is no third outcome.
- **The Transaction.** The EXECUTE phase is no longer a loop over actions with optional
  rollback. It is a four-phase transaction (capture → apply → validate → commit-or-rollback)
  that wraps every rule's mutation.

V0 said rollback was an engine-level capability. V1 says rollback is a required phase of
every production-mutating rule. That is the load-bearing change. Everything else is
formalization.

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

This produces the combinatorial explosion V0 described in detail — twelve codebases to
cover two frameworks across six OS/version pairs — and the drift, delay, false complexity,
and maintenance burden that follow.

### 1.2 The Second Problem V0 Did Not Name

Every tool in that list shares a deeper flaw, one V0 mentioned only in passing: **when a
remediation fails mid-way through, none of them restore the system to its pre-change state.**

Ansible applies tasks. If task 3 of 5 fails, tasks 1 and 2 are already applied. The
playbook reports failure and walks away. The operator now has a system in a partially-
configured state that was never intended to exist in any design document, and the only way
out is manual reconstruction from memory or backups.

Chef, Puppet, SaltStack, and Bash scripts all exhibit this same pattern. They are *change
appliers*. None of them are *change guarantors*.

The consequence: compliance automation is avoided in production precisely where it would
be most valuable — on the systems where a broken remediation at 3 AM is an incident, not
an inconvenience. Teams scan in production and remediate in lower environments, then hope
the remediation behaves the same when it runs again in prod. The automation does not get
trusted with the production mutation it was built for.

Kensa exists to fix both problems — the combinatorial one V0 named, and the atomicity one
V0 did not.

### 1.3 Root Cause

Two design decisions, made so consistently across the industry that they feel like laws of
nature:

> **Policy and mechanism are fused into a single artifact, organized by the structure of
> the benchmark document rather than the structure of the problem.**

> **Change application is treated as a sequence of independent operations rather than as a
> transaction with a commit-or-rollback boundary.**

The first produces the combinatorial explosion. The second produces the "broke prod at
3 AM" failure mode. Both are architectural choices, not constraints. Kensa rejects both.

---

## 2. Philosophy

### 2.1 A Rule is Not a Task

A compliance rule is a statement of desired state:

> *Root login over SSH must be disabled.*

It is not an Ansible task. It is not a Bash command. It is not a SCAP check. Those are
*implementations* of the rule — mechanisms that verify or enforce the desired state on a
specific platform using a specific tool.

The rule exists independent of any mechanism. It existed before Ansible. It will exist
after Ansible. It is true on RHEL 8 and RHEL 9 and RHEL 10 and every future version of
every Linux distribution that ships OpenSSH. The mechanism may vary. The rule does not.

**Principle 1: Separate the rule from its implementation. The rule is the stable core.
Implementations are the variable shell.**

### 2.2 Operating Systems Have Capabilities, Not Just Version Numbers

Version numbers are a proxy for capabilities. They are an unreliable proxy — because
capabilities change within a major version, because derivative distributions share
capabilities across different version numbers, and because future versions inherit most
capabilities from their predecessors.

**Principle 2: Target capabilities, not version strings. Detect what the system supports
and act on that. A capability-based model extends forward in time without modification.**

The capability model, its detection mechanism, and its forward-compatibility properties
are described in V0 Section 2.2 and Section 3.3. That content carries forward unchanged.

### 2.3 Model the Delta, Not the Whole

Between any two consecutive RHEL major versions, the overlap in security-relevant
configuration is approximately 85-90%. Between CIS and STIG for the same OS, the overlap
in actual system changes is approximately 70-80%.

**Principle 3: One canonical rule set. Thin overlays for genuine differences. The overlay
is the thing you maintain when a new OS ships — not a clone of the world.**

### 2.4 Frameworks Are Metadata, Not Structure

A single rule ("disable SSH root login") maps to many framework identifiers (CIS section
numbers, STIG V-IDs, NIST controls, PCI-DSS requirements). These are not ten different
rules. They are ten different *labels* for the same rule.

**Principle 4: Framework identifiers are cross-references attached to rules as metadata.
They do not define the structure of the rule set.**

### 2.5 Prefer Durable, Idempotent, Minimally Invasive Remediations

Traditional automation treats each control as pass/fail and each benchmark as a checklist.
Real compliance has nuance: a system may have the correct setting but lack the mechanism
to survive reboot; a control may pass technically but be operationally fragile; a
remediation may fix one finding and regress another.

**Principle 5: Prefer remediations that are durable, idempotent, and minimally invasive.
Favor the mechanism that survives the most change — package updates, config management
runs, reboots, upgrades — without breaking or requiring re-application.**

### 2.6 Forward Compatibility Is a Design Requirement

The most expensive moment in a compliance program is when a new OS version ships. If the
automation requires a full rebuild for each new version, the program is permanently
reactive.

**Principle 6: A new OS version should require only the addition of its genuinely new
exceptions. If 90% of the automation works without modification on RHEL N+1, then 90% of
the automation must work without modification on RHEL N+1. The architecture must guarantee
this, not rely on manual porting.**

### 2.7 Atomicity — The New Principle

Every mutation Kensa applies must end in one of two states: the target state, or the exact
pre-change state. There is no third outcome.

This is the guarantee a database transaction makes. `BEGIN TRANSACTION` → `UPDATE …` →
constraint check → `COMMIT` or `ROLLBACK`. Either the whole change lands, or the system
ends exactly where it started. There is no "half-applied" state. No partial write. No
"task 3 of 5 failed and tasks 1 and 2 are stranded."

Kensa provides this guarantee for Linux configuration changes. Every rule's mutation is
wrapped in a transaction. If any part of the mutation fails — the change itself, the
validation of the change, the restart of a dependent service — the engine rolls back every
change that was made within the transaction, using captured pre-state, and records the
operation as rolled back.

**Principle 7: Every mutation is a transaction. A rule either lands completely or leaves
the system in the exact state it was in before the rule began. There is no third outcome.**

Two consequences of this principle:

1. **Multi-step remediations are atomic across all their steps.** V0 said "if any step
   fails, execution stops and the rule is marked failed; earlier steps are not rolled back
   automatically." V1 says: if any step fails, every earlier step is rolled back using its
   captured pre-state, and the rule is marked rolled-back. Cross-step atomicity is now the
   contract.

2. **Mechanisms that cannot capture pre-state cannot participate in atomic transactions.**
   `command_exec`, `manual`, and `grub_parameter` mutations have no reliable pre-state
   capture — they are explicit escape hatches. A rule that contains one of these steps
   cannot offer the atomicity guarantee and must declare this explicitly in its metadata.
   Section 3.5 describes the boundary.

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
│   Each rule declares: desired state, severity, rationale,        │
│   atomicity declaration, and one or more implementations.        │
└──────────────────────────┬───────────────────────────────────────┘
                           │ implements
┌──────────────────────────▼───────────────────────────────────────┐
│                    PLATFORM IMPLEMENTATIONS                      │
│   Capability-gated check + remediation pairs.                    │
│   The engine wraps every remediation in a transaction.           │
└──────────────────────────────────────────────────────────────────┘
```

The three-layer architecture from V0 is preserved. What changes in V1 is the contract
between the canonical rule and the engine: the rule declares desired state and
remediation steps; the engine guarantees atomicity.

### 3.2 The Canonical Rule

A canonical rule is the atomic unit. It represents one security control, independent of
any framework or OS version.

The rule structure (fields, framework references, platform scope, capability-gated
implementations) carries forward from V0 unchanged, with one addition: an optional
top-level `transactional` field that declares whether the rule can satisfy the atomicity
guarantee. Details are in `CANONICAL_RULE_SCHEMA_V1.md`.

### 3.3 Capability Detection

Capabilities are facts about the target system that determine which implementation path
to use. They are detected at the start of a remediation run and cached for the session.
The capability model is described in V0 Section 3.3 and carries forward unchanged.

### 3.4 Implementation Mechanisms

Remediation implementations use a small set of composable mechanisms rather than
arbitrary scripts. V1 adds one structural distinction to the V0 mechanism table: every
mechanism is now classified as either **capturable** or **non-capturable**.

A capturable mechanism has a defined, reliable procedure for recording the system's
pre-change state and a corresponding procedure for restoring it. A non-capturable
mechanism does not — either because the pre-state is ambiguous, because the operation is
inherently irreversible, or because the operation requires human judgment.

**Capturable mechanisms** (participate in atomic transactions):

| Mechanism                | Capture mechanism                                       |
|--------------------------|---------------------------------------------------------|
| `config_set`             | Read and store prior key=value (or "absent")            |
| `config_set_dropin`      | Record drop-in file content (or "absent")               |
| `config_remove`          | Read and store prior key=value                          |
| `config_block`           | Read block marker region                                |
| `file_permissions`       | Read owner, group, mode                                 |
| `file_absent`            | Read file content, permissions, SELinux context         |
| `file_content`           | Read prior file content, permissions, context           |
| `service_enabled`        | Read enabled/active state                               |
| `service_disabled`       | Read enabled/active state                               |
| `service_masked`         | Read masked/enabled state                               |
| `package_present`        | Record package absent/present, version                  |
| `package_absent`         | Record package present, version                         |
| `sysctl_set`             | Read runtime value and persist-file content             |
| `kernel_module_disable`  | Read blacklist file content, module loaded/unloaded     |
| `mount_option_set`       | Read fstab entry and current mount options              |
| `pam_module_configure`   | Read authselect profile + feature state, or PAM stack   |
| `audit_rule_set`         | Read rule file content and loaded ruleset               |
| `selinux_boolean_set`    | Read current boolean value                              |
| `cron_job`               | Read prior crontab or timer unit content                |

**Non-capturable mechanisms** (explicit transaction escape hatches):

| Mechanism                | Reason                                                  |
|--------------------------|---------------------------------------------------------|
| `command_exec`           | Arbitrary command; pre-state cannot be inferred         |
| `manual`                 | Human intervention required; no machine pre-state       |
| `grub_parameter_set`     | Bootloader state is not reliably reversible mid-boot    |
| `grub_parameter_remove`  | Bootloader state is not reliably reversible mid-boot    |

Each mechanism is idempotent by design. Running it twice produces the same result as
running it once. For capturable mechanisms, the pre-state is captured before modification
and the rollback procedure is defined.

The `command_exec` mechanism is an explicit escape hatch for controls that do not fit the
declarative model. A rule that contains a `command_exec` step forfeits its atomicity
guarantee. This is a deliberate trade-off: the rule can still execute, but the operator
must accept that a mid-rule failure may leave earlier successful steps in place. The rule
must declare this by setting `transactional: false` in its metadata.

Over time, patterns that repeatedly use `command_exec` should be promoted to first-class
capturable mechanisms. The table above is extensible.

### 3.5 The Transaction Model

Every rule's remediation, regardless of how many steps it contains, runs as a single
transaction with four phases:

```
┌─────────────────────────────────────────────────────────────────┐
│                        TRANSACTION                              │
│                                                                 │
│  1. CAPTURE   ← record pre-state for every capturable mechanism │
│       │         in the remediation plan, in order               │
│       ▼                                                         │
│  2. APPLY     ← execute every remediation step in order         │
│       │         (halt on first failure)                         │
│       ▼                                                         │
│  3. VALIDATE  ← verify the rule's check now passes AND any      │
│       │         dependent validators (service health, config    │
│       ▼         syntax, etc.) pass                              │
│  4. COMMIT    ← if APPLY and VALIDATE succeeded, leave the      │
│       OR        change in place and record evidence             │
│    ROLLBACK   ← if APPLY failed mid-stream OR VALIDATE failed,  │
│                 restore every captured pre-state in reverse     │
│                 order using the corresponding rollback handler  │
└─────────────────────────────────────────────────────────────────┘
```

The guarantee is that the transaction always terminates in one of two states:

1. **Committed** — the change is in place, the check passes, all validators pass, and an
   evidence record is written. The system is in the target state.
2. **Rolled back** — every successful APPLY step has been reversed using its captured
   pre-state, and the transaction is recorded as rolled back. The system is in the exact
   state it was in before CAPTURE began.

There is no third outcome. There is no "halfway." There is no "task 3 of 5 failed, tasks
1 and 2 are stranded, good luck."

#### 3.5.1 Capture

For every step in the remediation plan, the engine invokes the step's capture handler and
records the result in a pre-state bundle. The bundle is serialized and persisted to
durable storage (SQLite by default) before any APPLY step runs. This ensures that if
Kensa itself crashes mid-transaction, the pre-state is still recoverable for an
out-of-band rollback.

Capture is non-mutating. It reads system state; it does not change it. Capture failures
(e.g., a file cannot be read due to permissions) abort the transaction before APPLY
begins — it is better to fail safely than to apply changes we cannot reverse.

#### 3.5.2 Apply

Remediation steps execute in order. Each step is idempotent; each step verifies its own
immediate result. If a step reports failure, the transaction halts and proceeds to
ROLLBACK. There is no "continue past the failing step" mode.

#### 3.5.3 Validate

After all APPLY steps succeed, the engine runs the rule's check to confirm round-trip
consistency (the post-remediation state satisfies the rule's check). It also runs any
declared dependent validators — these are validators that ensure the change did not break
adjacent system health. Examples:

- **Service health validators.** After a config change that requires a service restart,
  verify the service is active and accepting connections.
- **Config syntax validators.** After modifying sshd_config, run `sshd -t`. After
  modifying sysctl, confirm the runtime value matches the persisted value.
- **Control channel validators.** After modifying SSH, networking, or PAM, verify the
  control channel is still functional. A failure here triggers the deadman-timer rollback
  path described in `TRANSACTION_CONTRACT_V1.md`.

If any validator fails, the transaction proceeds to ROLLBACK.

#### 3.5.4 Commit or Rollback

On success, the transaction is marked committed and the evidence envelope is written. On
failure at any phase, the engine invokes each captured step's rollback handler in reverse
order, restoring the system to its pre-CAPTURE state. The rollback path is recorded in
the transaction log alongside the original apply attempt — both attempts are evidence.

### 3.6 The Atomicity Boundary

Atomicity applies only to rules composed entirely of capturable mechanisms. Rules that
use `command_exec`, `manual`, or bootloader mechanisms must declare `transactional: false`
in their metadata. For these rules:

- CAPTURE runs for any capturable steps in the rule.
- APPLY runs all steps in order.
- VALIDATE runs normally.
- On failure, ROLLBACK runs for the capturable steps only — the non-capturable steps
  are not reversed.

The operator sees this boundary explicitly. Every scan report, evidence bundle, and
transaction log entry flags non-transactional rules so that the atomicity expectation is
never silently violated. A customer running `kensa remediate` sees which rules are
guaranteed atomic and which are not, before the run begins.

This is the honest version of the atomicity claim. Some Linux operations are not
reversible; Kensa does not pretend they are. The alternative — claiming atomicity and
silently failing to deliver it — would be worse than being explicit about the boundary.

### 3.7 Framework Mapping Layer

Framework mappings are a separate data structure that references canonical rules by ID.
The mapping structure carries forward from V0 unchanged — mappings are metadata layered
over rules, and the transaction model does not touch them.

### 3.8 Execution Model

A remediation run proceeds in four phases at the run level, with a nested transaction
at the per-rule mutation level:

```
Phase 1: DETECT
   Connect to target host
   Run capability detection
   Produce capability set

Phase 2: RESOLVE
   For each requested rule, select the implementation matching detected capabilities
   Produce execution plan: ordered list of concrete rules with their remediation steps
   Pre-flight: flag rules with transactional: false so the operator sees atomicity scope

Phase 3: EXECUTE
   For each rule in the plan:
     BEGIN TRANSACTION
       CAPTURE   — record pre-state for every capturable step
       APPLY     — execute remediation steps in order
       VALIDATE  — round-trip check + dependent validators
     COMMIT or ROLLBACK
     Record transaction outcome in the transaction log
   Continue to the next rule regardless of whether the current rule committed
   or rolled back (each rule is an independent transaction boundary)

Phase 4: REPORT
   Produce results mapped to the requested framework(s)
   For each rule, report: committed, rolled-back, skipped, or errored
   Summarize transaction outcomes across the run
```

**Why the nesting is correct.** The run-level four phases (DETECT/RESOLVE/EXECUTE/REPORT)
operate at fleet scale — they describe what happens when an operator initiates a scan
against a set of hosts. The transaction-level four phases (CAPTURE/APPLY/VALIDATE/
COMMIT-OR-ROLLBACK) operate at rule scale — they describe what happens when a single
rule mutates a single host. Both are load-bearing. They are not in competition.

**Why rules are independent transactions, not one big transaction per run.** A single
run may remediate 200 rules. If rule 37 fails and rolls back, rules 1-36 should stay
committed — they were successful, independent changes. Rolling back the whole run would
lose the 36 legitimate improvements because of one unrelated failure. Each rule is its
own transaction boundary.

An operator who wants all-or-nothing at the run level can use `--atomic-run`, which wraps
the entire run in a meta-transaction. This is an explicit opt-in, not the default,
because most operators want per-rule transactionality.

### 3.9 What Changes When a New OS Ships

Scenario: RHEL 11 is released. CIS publishes the CIS RHEL 11 Benchmark. DISA publishes
the RHEL 11 STIG.

The V0 answer carries forward unchanged: run capability detection, identify genuinely new
capabilities, add implementation variants for the 3-5 affected rules, add new framework
mapping files. 95%+ of the rules work immediately without modification.

V1 adds one consideration: the capture and rollback handlers for each capturable
mechanism must be tested on the new OS. A new OS may change how the engine reads or
writes the state of a mechanism (e.g., a new config file location, a new service
management primitive). The handler itself is the same; its validation against the new
OS is part of the "new OS capability matrix" work.

---

## 4. Scope and Boundaries

### 4.1 In Scope for V1

- **RHEL family**: RHEL 8, 9, 10 (and binary-compatible derivatives: CentOS Stream,
  Rocky Linux, AlmaLinux, Oracle Linux)
- **Frameworks**: CIS Benchmarks, DISA STIGs
- **Framework cross-references**: NIST 800-53, PCI-DSS, FedRAMP Moderate
- **Remediation mechanisms**: The mechanism table in 3.4, with capture/rollback pairs
  for every capturable mechanism
- **Execution**: Remote via SSH, local execution
- **Rule format**: YAML-based canonical rule definitions (see
  `CANONICAL_RULE_SCHEMA_V1.md`)
- **Transactional guarantee**: Atomic per-rule for rules composed of capturable
  mechanisms; explicit boundary declaration for rules that include escape hatches

### 4.2 Out of Scope for V1 (Future Phases)

- **Non-RHEL Linux**: Ubuntu, SUSE, Debian. The architecture supports them; V1 focuses
  on RHEL to prove the model with the deepest benchmark coverage.
- **Windows**: Fundamentally different mechanism layer.
- **Cloud/Container benchmarks**: Same architectural principles, different capability
  domain.
- **GUI-based remediations**: Controls requiring graphical environment.
- **Multi-run transactions**: Atomicity across multiple invocations of `kensa remediate`
  is not supported. Within a single invocation, each rule is a transaction; across
  invocations, state is whatever the previous run left it in.

### 4.3 Success Criteria

The architecture is validated when:

1. A single canonical rule set covers CIS RHEL 8, CIS RHEL 9, CIS RHEL 10, STIG RHEL 8,
   and STIG RHEL 9.
2. Adding coverage for a new RHEL version requires modifying fewer than 10% of the
   canonical rules.
3. Adding coverage for a new framework requires zero changes to canonical rules.
4. The same rule applied to RHEL 8 and RHEL 9 produces correct, idempotent remediation
   on both.
5. An auditor can generate a report in CIS format or STIG format from the same scan
   results with correct framework-specific numbering.
6. **New in V1:** Every rule composed of capturable mechanisms satisfies the atomicity
   guarantee — either commits fully or rolls back every applied step using captured
   pre-state. This is verified by an integration test suite that deliberately induces
   failures at each transaction phase and confirms the rollback path restores the
   original state.

---

## 5. Risks and Mitigations

| Risk | Description | Mitigation |
|------|-------------|------------|
| **Abstraction leakage** | Some controls may not fit cleanly into the declarative mechanism model, requiring excessive use of `command_exec`. | Track `command_exec` usage. If a pattern emerges, promote it to a first-class mechanism. Rules using `command_exec` declare `transactional: false`, so the atomicity boundary is explicit. |
| **Capture incompleteness** | The pre-state captured for a mechanism may not be sufficient to fully restore the system if an adjacent subsystem also changed. | Each capture handler is reviewed against a "what state might we be missing" checklist before it ships. Rollback is tested against real failure cases, not just happy-path unit tests. See `RULE_REVIEW_GUIDE_V1.md` Section 4. |
| **Rollback handler bugs** | A rollback handler could fail to restore pre-state correctly, leaving the system in a worse state than before the transaction. | Every rollback handler requires a two-human review and a spec-derived integration test that exercises the full capture→apply-fail→rollback cycle on a real system before the handler can ship. This is a non-negotiable commitment. |
| **Control channel collapse** | A change to SSH, networking, or PAM may disable the SSH connection Kensa is using, leaving the engine unable to complete ROLLBACK. | For control-channel-affecting mechanisms, the engine uploads a rollback script and arms a deadman timer (via `at` or `systemd-run`) before applying the change. If the control channel survives, the timer is cancelled. If it does not, the timer fires and the rollback script runs out of band. See `TRANSACTION_CONTRACT_V1.md` Section 3. |
| **Capability detection inaccuracy** | A capability probe could return a false positive or negative. | Each detection is a precise, multi-condition check. Test capability detection against known system states. Allow manual capability overrides. |
| **Framework mapping maintenance** | Mapping files must be updated when new benchmark versions publish. | Mapping creation is mechanical. Partially automatable via diffing consecutive benchmark versions. |
| **Edge cases between RHEL derivatives** | Rocky, Alma, Oracle Linux may diverge from RHEL. | Capability detection is distribution-agnostic; divergences surface as capability differences. |
| **Complexity of PAM stack** | PAM configuration is one of the most fragile areas of Linux administration. | Isolate PAM into a dedicated mechanism with conservative change semantics. Always verify PAM state after modification. PAM changes are control-channel-adjacent and use the deadman timer path. |
| **Rule conflicts** | Two rules in the same run could set contradictory values. | Detect conflicts in RESOLVE before execution. Flag them as errors. Defer resolution to the operator. |
| **Non-capturable rule surprises** | An operator may expect atomicity on a rule that cannot provide it. | The RESOLVE phase surfaces `transactional: false` rules before the run begins. Every evidence record flags whether the rule ran atomically. Operators see the boundary explicitly. |

---

## 6. What We Are Not Building

Clarity on non-goals prevents scope creep and architectural contamination:

- **Not a configuration management tool.** Kensa does not replace Puppet or Ansible for
  general system configuration. It is concerned with security compliance controls and
  with providing the transactional primitive other tools can eventually run on top of.

- **Not a scanning-only tool.** Kensa is not an alternative to OpenSCAP for assessment.
  It is the remediation and enforcement counterpart.

- **Not a policy-as-code language.** The rule format is YAML. The mechanisms are
  composable primitives. Expressiveness is intentionally limited.

- **Not a replacement for reading the benchmarks.** Auditors and compliance engineers
  must still understand the controls.

- **Not a driver of production change decisions.** Kensa is the safety rail, not the
  operator. Every rollback path is written by a human who personally reasoned about the
  failure modes. Kensa provides atomicity; the human provides judgment about whether
  the change should run at all.

- **Not a tool that claims guarantees it cannot honor.** Where atomicity is not
  achievable (non-capturable mechanisms, SSH control channel collapse without the
  deadman-timer path), the rule, the evidence, and the report say so explicitly. We
  sell what we can deliver. We document what we cannot.

---

## 7. Guiding Principles Summary

1. **Separate the rule from its implementation.** The rule is the stable core.
   Implementations are the variable shell.

2. **Target capabilities, not version strings.** Detect what the system supports and
   act on that.

3. **Model the delta, not the whole.** One canonical rule set. Thin overlays for
   genuine differences.

4. **Frameworks are metadata, not structure.** Framework identifiers are
   cross-references, not reasons to duplicate rules.

5. **Prefer durable, idempotent, minimally invasive remediations.** Favor the mechanism
   that survives the most change.

6. **Forward compatibility is a design requirement.** A new OS version should require
   only its genuinely new exceptions.

7. **Every mutation is a transaction.** A rule either lands completely or leaves the
   system in the exact state it was in before the rule began. There is no third
   outcome. Where this guarantee cannot be honored (non-capturable mechanisms, control
   channel collapse without the deadman-timer path), the rule declares the boundary
   explicitly.

---

*This document defines the philosophical and architectural foundation for Kensa. V1
formalizes the transaction model that was implicit in V0, adds the atomicity principle,
and names the boundary where atomicity cannot be honored. The companion documents —
`CANONICAL_RULE_SCHEMA_V1.md`, `RULE_REVIEW_GUIDE_V1.md`, and `TRANSACTION_CONTRACT_V1.md`
— operationalize these commitments at the schema, review, and customer-commitment layers.*
