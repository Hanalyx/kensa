# Rule Review Guide — Version 1

**Project:** Kensa
**Date:** 2026-04-13
**Status:** Draft
**Supersedes:** `RULE_REVIEW_GUIDE_V0.md` (retained for historical reference)
**Companion:** `CANONICAL_RULE_SCHEMA_V1.md`, `TECHNICAL_REMEDIATION_MP_V1.md`, `TRANSACTION_CONTRACT_V1.md`

---

## 0. What Changed from V0

V0 defined five review dimensions (Check Accuracy, Remediation Effectiveness, Schema
Compliance, Framework References, Forward Compatibility) and established "effective vs.
static configuration" and "round-trip consistency" as the most important review
criteria. V1 preserves all of that.

V1 adds three things:

1. **The five dimensions are remapped onto the four transaction phases** (capture, apply,
   validate, commit-or-rollback). Each dimension now points to the phase it governs, and
   the review criteria are expressed as phase-level quality gates.

2. **A sixth dimension: Rollback Safety.** Every rule with `transactional: true` must be
   reviewed against whether its captured pre-state is sufficient to fully restore the
   system if the transaction fails. This is the review-time version of the failure-mode
   analysis commitment from `HANALYX_MISSION_AND_ROADMAP.md`.

3. **Review of the `transactional` declaration.** A rule that declares `transactional:
   true` but would break atomicity (because of a non-capturable step, because capture is
   incomplete, or because rollback is untested) fails review. A rule that declares
   `transactional: false` is reviewed against whether the escape hatch is genuinely
   necessary or whether the rule could be rewritten to use capturable mechanisms.

The existing domain guidance from V0 (effective vs. static, override precedence,
durability hierarchy, idempotency, reboot awareness) carries forward unchanged. The V1
changes reframe how these criteria are organized, not what they contain.

---

## 1. Purpose

This document defines the criteria for reviewing Kensa canonical rules. Every rule in
`rules/` should be evaluated against these criteria to ensure correctness, completeness,
and alignment with the project's design philosophy and its atomicity commitments.

A rule review is not a checkbox exercise. It requires understanding the control's
security intent, the system behavior it targets, the difference between what a static
configuration file says and what the system actually enforces, and — new in V1 —
whether the rule's transaction can be rolled back safely if any phase fails.

### When to Use This Guide

- **New rule creation.** Before a rule enters the canonical set.
- **Periodic rule audit.** Systematic review of existing rules for accuracy.
- **Post-incident review.** When a rule produces a false positive, false negative, or
  a failed rollback in production.
- **Framework update.** When a new benchmark version publishes.
- **V0 → V1 migration.** When reviewing the `transactional` declaration added during
  the schema migration.

---

## 2. The Six Review Dimensions

A rule review covers six dimensions, organized around the four transaction phases:

| # | Dimension                  | Transaction Phase         | Priority | Question                                               |
|---|----------------------------|---------------------------|----------|--------------------------------------------------------|
| 1 | Check Accuracy             | Validate (pre & post)     | Critical | Does the check measure what it claims to measure?      |
| 2 | Remediation Effectiveness  | Apply + Validate          | Critical | Does the remediation produce the desired state, and does the post-check confirm it? |
| 3 | **Rollback Safety**        | Capture + Rollback        | Critical | If the transaction fails, can every applied step be reversed to the exact pre-state? |
| 4 | Schema Compliance          | Cross-cutting             | High     | Does the rule conform to the canonical schema, including the `transactional` declaration? |
| 5 | Framework References       | Cross-cutting             | Medium   | Are all applicable framework mappings present and correct? |
| 6 | Forward Compatibility      | Capture + Apply           | Medium   | Will this rule work on future OS versions, and will its capture/rollback handlers? |

Check Accuracy is listed first because an incorrect check undermines everything
downstream — the remediation, the validation, the evidence, and the auditor's trust.
Rollback Safety is new in V1 and is listed third because an unsafe rollback path is
worse than a broken remediation — it can leave a system in a state neither the operator
nor the rule author anticipated.

---

## 3. Dimension 1: Check Accuracy (Validate Phase)

The check runs twice in every transaction: once before capture (pre-check, to determine
whether the rule needs to remediate at all) and once after apply (post-check, to confirm
the remediation produced the desired state). Both invocations rely on the same check
definition, so the check must be accurate enough for both purposes.

### 3.1 Effective vs. Static Configuration

**This is the single most important review criterion.**

Many system settings have two truths: the static configuration (what the file says) and
the effective configuration (what the system enforces). A check that reads only the
static file can produce false positives and false negatives.

**Review question:** Does this check verify what the system actually enforces, or only
what a file contains?

| Domain | Static Source | Effective Source | How to Check Effective |
|--------|-------------|-----------------|----------------------|
| SSH | `/etc/ssh/sshd_config` | Resolved config after all includes | `sshd -T` |
| SSH (user-specific) | `sshd_config` + `Match` blocks | Per-user resolved config | `sshd -T -C user=<user>,host=<host>` |
| Sysctl | `/etc/sysctl.conf`, `/etc/sysctl.d/*.conf` | Runtime kernel parameters | `sysctl -n <key>` |
| PAM | `/etc/pam.d/*` files | Authselect-managed stack | `authselect current`, then verify stack |
| Audit rules | `/etc/audit/rules.d/*.rules` | Loaded audit rules | `auditctl -l` |
| Firewall | Zone XML files | Active firewall state | `firewall-cmd --list-all` |
| Crypto policy | `/etc/crypto-policies/config` | Active policy + submodules | `update-crypto-policies --show` |
| GRUB parameters | `/etc/default/grub`, BLS entries | Running kernel cmdline | `cat /proc/cmdline` |
| Mount options | `/etc/fstab` | Currently mounted options | `findmnt -n -o OPTIONS <mount>` |
| Systemd units | Unit files in `/etc/systemd/` | Effective unit config | `systemctl show <unit>` |
| SELinux | `/etc/selinux/config` | Runtime enforcement | `getenforce` |
| Limits | `/etc/security/limits.conf`, `limits.d/*.conf` | Effective limits | `ulimit` or `/proc/<pid>/limits` |

The V0 guidance on ideal check patterns, acceptable patterns, and unacceptable patterns
carries forward unchanged. See `RULE_REVIEW_GUIDE_V0.md` §3.1 for the full examples;
the substance is preserved and is not repeated here to keep V1 focused on the new
atomicity-related criteria.

### 3.2 Override Precedence Rules

SSH, sysctl, PAM, audit, and systemd all have override precedence rules that the check
must respect. The V0 precedence guidance carries forward unchanged.

### 3.3 Check Method Selection

The `command` method is an escape hatch. Before accepting a `command` check, verify that
no typed method covers the case. The V0 mapping of "if the check does X, use method Y
instead of `command`" carries forward unchanged.

### 3.4 Evidence Quality

Good evidence is unambiguous, complete, and unforgeable. The V0 guidance carries
forward. V1 adds one criterion: the check's evidence must be suitable for inclusion in
the transaction log's evidence envelope, which means it must be deterministic and
replayable by an auditor reading the log weeks later.

### 3.5 Multi-Condition Completeness

Some controls have compound requirements. Use `checks:` (list with AND semantics) when
multiple conditions must all be true. Pre- and post-check must both run the full
condition set — a rule that passes one condition but not others has not been correctly
remediated.

---

## 4. Dimension 2: Remediation Effectiveness (Apply + Validate Phases)

### 4.1 Round-Trip Consistency

**Review question:** After remediation runs, will the check pass?

This is the validate-phase contract. If the remediation sets `PermitRootLogin no` in
`sshd_config` but the check reads from `sshd -T` (effective config), they must agree.
If the remediation writes to the wrong file, uses the wrong separator, or targets the
wrong path, the post-check will fail and the transaction will roll back — correctly
flagging a broken rule.

A rule where the remediation cannot produce a state that satisfies the check is
architecturally broken. The transaction will roll back every time, and the rule will
never commit. Review must catch this before the rule ships.

Verify:
- The `path`/`key`/`value` in remediation matches what the check reads.
- The `separator` matches the config file's format.
- After remediation, `reload`/`restart` triggers so the effective state reflects the
  change before the post-check runs.

### 4.2 Mechanism Durability

From V0 Principle 5: "Prefer remediations that are durable, idempotent, and minimally
invasive."

Durability hierarchy (most durable first):

| Mechanism | Durability | Use When |
|-----------|-----------|----------|
| Drop-in file in `.d/` directory | Survives package updates | System supports `.d/` includes |
| Authselect feature | Survives authselect profile switches | PAM on authselect systems |
| Dedicated config file (`/etc/sysctl.d/99-kensa.conf`) | Survives package updates | Sysctl, modprobe, audit rules |
| Direct edit to main config file | Overwritten by package updates | No `.d/` alternative exists |
| Runtime-only command | Lost on reboot | Never (unless paired with persistent change) |

### 4.3 Idempotency

Every mechanism must be idempotent — running it N times produces the same result as
running it once.

For declarative mechanisms (`config_set`, `file_permissions`, `service_enabled`),
idempotency is built in. For `command_exec`, idempotency must be explicit via `unless`
or `onlyif` guards. A rule containing `command_exec` without a guard fails review.

### 4.4 Reboot Awareness

Some changes are not fully effective until reboot. The V0 reboot-awareness table
carries forward unchanged. V1 adds one transaction-phase consideration: if a change
requires reboot to fully take effect, the validate phase cannot confirm the fully-
effective state within the transaction. The rule must document this explicitly (via a
comment in the rule YAML or in the rule description) so that the post-check's partial
success is not misinterpreted as a false positive.

### 4.5 Multi-Step Ordering

Steps execute sequentially. Under V1's atomic semantics, if step N fails, every earlier
capturable step is rolled back. This means the author must reason about ordering not
just for apply success but for rollback correctness:

- Package install before configuration (can't configure what isn't installed).
- Configuration before service enable (don't start with bad config).
- Service reload/restart after configuration change.

For rollback ordering: if step 3 fails and we roll back, step 2 is reversed before
step 1. The author must verify this reverse order is safe — reversing step 2 should not
depend on step 1 still being applied.

### 4.6 Conflict and Dependency Awareness

`depends_on`, `conflicts_with`, and `supersedes` work the same way in V1 as V0. The
execution engine uses these to order transactions across rules.

---

## 5. Dimension 3: Rollback Safety (Capture + Rollback Phases) — NEW IN V1

This is the dimension V0 did not have. Rollback Safety is the review-time version of
the commitment in `HANALYX_MISSION_AND_ROADMAP.md`: *every rollback path is written by
a human who personally reasoned about the failure modes.*

### 5.1 Capture Sufficiency

**Review question:** If the apply or validate phase fails, is the captured pre-state
sufficient to restore the system to its exact pre-change state?

Every capturable mechanism has a defined capture handler. The review must confirm that
for this specific rule, the capture handler records everything necessary:

| Mechanism              | What the capture handler records           | Review question                                    |
|------------------------|--------------------------------------------|----------------------------------------------------|
| `config_set`           | Prior key=value (or "absent")              | Is the key read from the correct file? Multiple files? |
| `config_set_dropin`    | Drop-in file content (or "absent")         | Does capture record the whole file, not just the key? |
| `file_permissions`     | Owner, group, mode                         | Does capture include SELinux context? ACLs?        |
| `file_content`         | Prior file content                          | Is the file small enough to capture? Is it binary? |
| `service_enabled`      | enabled/active state                        | Does capture record the `wanted-by` target?        |
| `package_present`      | Package present/absent, version             | Does capture handle held packages? Module streams? |
| `sysctl_set`           | Runtime value + persist-file content        | Does capture record both? Multiple persist files?  |
| `pam_module_configure` | Authselect profile + feature state, or PAM stack | Does capture handle the authselect case correctly? |
| `audit_rule_set`       | Rule file content + loaded ruleset          | Does capture handle the immutable flag?            |

For every rule, the reviewer walks through the capture handler's behavior against the
specific mechanism parameters in the rule. Generic capture is not sufficient if the
rule uses the mechanism in an unusual way.

### 5.2 Rollback Completeness

**Review question:** Does the rollback path restore every piece of state the apply path
modified?

An apply step may have side effects beyond the primary mutation. Examples:

- A `config_set` that triggers a service reload must, on rollback, restore the prior
  config AND reload the service so the effective state is also restored.
- A `package_present` that installs a package may create files, users, or directories
  as a side effect. Rollback must `package_absent` the package AND verify side-effect
  files are removed (or documented as accepted residue).
- A `selinux_boolean_set` may affect multiple services. Rollback must restore the
  boolean AND note any services whose behavior may have shifted while the boolean was
  inverted.

For complex mechanisms, the reviewer should trace the apply path step by step and
confirm that the rollback path reverses each step in the correct order.

### 5.3 Rollback Testing

**Review question:** Has the rollback path been tested with an actual induced failure
on a real system?

Per the `HANALYX_MISSION_AND_ROADMAP.md` commitment, every rollback handler requires a
spec-derived integration test that:

1. Captures pre-state.
2. Applies the change.
3. Deliberately induces a validate-phase failure.
4. Executes the rollback.
5. Confirms the system is in the exact pre-change state (using the capture handler
   against the current state and comparing to the original capture).

A rule's review includes confirming this test exists for the mechanisms it uses, and
that the test covers the specific parameters the rule passes to the mechanism (not
just a generic happy-path test).

### 5.4 The `transactional` Declaration

**Review question:** Is the rule's `transactional` declaration correct?

For `transactional: true` rules:
- Every step in every implementation uses a capturable mechanism.
- Capture is complete for each step's parameters.
- Rollback is tested for each step's parameters.

For `transactional: false` rules:
- At least one step uses a non-capturable mechanism (`command_exec`, `manual`,
  `grub_parameter_*`).
- The non-capturable step is genuinely necessary — there is no capturable mechanism
  that could replace it.
- If the non-capturable step is a `command_exec`, it has an `unless` or `onlyif` guard
  for idempotency.
- The rule's description or a YAML comment explains why the escape hatch is necessary.

A rule declaring `transactional: true` that the validator accepts but a human reviewer
finds has an incomplete capture (e.g., a `config_set` that should also capture a
companion drop-in file) must be fixed before the rule ships. The validator catches
structural mismatches; the human catches semantic ones.

### 5.5 Control Channel Impact

**Review question:** Does this rule modify SSH, networking, or PAM in a way that could
disable the control channel Kensa is using?

Rules affecting SSH configuration, networking parameters, firewall rules, or PAM
authentication are control-channel-sensitive. If the change breaks the SSH connection
Kensa is using, the engine cannot execute rollback over that connection. These rules
require the deadman-timer path described in `TRANSACTION_CONTRACT_V1.md` §3.

The reviewer confirms:
- The rule is tagged as control-channel-sensitive so the engine arms the deadman
  timer before applying.
- The rollback script that the deadman timer would execute is tested.
- The validate phase includes a control-channel health check.

---

## 6. Dimension 4: Schema Compliance

### 6.1 Required Fields

Every rule must have all required fields per `CANONICAL_RULE_SCHEMA_V1.md`:

| Field | Type | Requirement |
|-------|------|-------------|
| `id` | string | Globally unique, kebab-case, matches filename |
| `title` | string | Imperative voice, under 100 characters |
| `description` | string | 2-4 sentences: what the rule enforces and security context |
| `rationale` | string | Security justification |
| `severity` | enum | `critical`, `high`, `medium`, `low` — Kensa's own assessment |
| `category` | string | Must match parent directory name |
| `tags` | list | Free-form labels |
| `references` | object | Framework cross-references |
| `platforms` | list | OS family and version scope |
| `implementations` | list | At least one, exactly one with `default: true` |
| **`transactional`** | **bool** | **Optional, default `true`. Must be `false` if any step uses a non-capturable mechanism.** |

### 6.2 Severity Assessment

Kensa severity is independent of CIS Level (L1/L2) and STIG Category (CAT I/II/III).
The V0 severity criteria carry forward unchanged.

### 6.3 Naming Conventions

Unchanged from V0.

### 6.4 Description and Rationale Quality

Unchanged from V0.

### 6.5 The `transactional` Field (NEW IN V1)

Every rule must be consciously evaluated for transactionality:

- **If all steps are capturable** → the field may be omitted (defaults to `true`) or
  explicitly set to `true`.
- **If any step is non-capturable** → the field must be set to `false`, and the
  description should acknowledge the escape hatch.

A rule's review asks not just "is the field correct?" but "was the atomicity boundary
consciously considered?" A rule that uses `command_exec` without realizing it is
forfeiting atomicity is a review failure even if the `transactional: false`
declaration happens to be present.

---

## 7. Dimension 5: Framework References

The V0 guidance on completeness, accuracy, and consistency with mapping files carries
forward unchanged. No V1 changes in this dimension.

---

## 8. Dimension 6: Forward Compatibility

### 8.1 Platform Scope

Prefer `min_version: 8` with no `max_version`. Set `max_version` only when a feature is
genuinely removed.

### 8.2 Implementation Gating

Gate by capabilities, not version numbers.

### 8.3 RHEL Derivative Coverage

Rules targeting `family: rhel` automatically include derivatives.

### 8.4 Capture/Rollback Forward Compatibility (NEW IN V1)

A capability gate may select a capable mechanism, but the capture handler for that
mechanism must also work on the target OS. When a new OS version ships:

- Run the capability detection — most capabilities carry forward.
- Run the capture handler integration tests against the new OS. If a capture handler
  reads a file that moved, a command whose output format changed, or a service that was
  renamed, the capture will fail and the transaction cannot proceed safely.
- Verify rollback handlers work against the new OS's mechanisms.

A rule that passes on RHEL 9 but whose capture/rollback has not been validated on
RHEL 10 is not forward-compatible even if its check and remediation logic is. The
reviewer confirms the capture/rollback test matrix covers the rule's declared platforms.

---

## 9. Common Defects

Patterns frequently found during rule review, ordered by frequency. V1 adds three new
defect types related to atomicity.

### 9.1 Static-Only SSH Checks

**Defect:** Check reads `/etc/ssh/sshd_config` without accounting for `sshd_config.d/`
drop-in overrides.

**Impact:** False negatives and positives.

**Fix:** Use `sshd -T` for effective config verification.

### 9.2 Missing Idempotency Guards

**Defect:** `command_exec` remediation without `unless` or `onlyif`.

**Impact:** Remediation runs every time, potentially causing side effects.

**Fix:** Add appropriate guard condition.

### 9.3 Incomplete Multi-Condition Checks

**Defect:** A control requires multiple conditions but the check verifies only one.

**Impact:** Partial compliance reported as full compliance.

**Fix:** Add `checks:` list with all required conditions.

### 9.4 Wrong Separator in Config Set

**Defect:** Remediation uses wrong separator for the target config file.

**Impact:** Syntactically incorrect config, potentially breaking the service.

**Fix:** Verify the separator matches the target file format.

### 9.5 Missing Service Reload After Config Change

**Defect:** Config modified without `reload` or `restart`.

**Impact:** Change persisted but not effective until next service restart. The
post-check validates against effective state and will fail, triggering an unnecessary
rollback.

**Fix:** Add `reload` (preferred) or `restart`.

### 9.6 Severity Copied from Framework

**Defect:** Kensa `severity` matches CIS Level or STIG Category rather than Kensa's own
assessment.

**Fix:** Assess severity independently using the criteria in Section 6.2.

### 9.7 Missing Framework References

**Defect:** Rule maps to CIS but not STIG, NIST, or PCI-DSS even though the control
exists in those frameworks.

**Fix:** Cross-reference all mapping files and add missing references.

### 9.8 Overly Narrow Platform Scope

**Defect:** Rule sets `max_version: 9` without justification.

**Fix:** Remove `max_version` unless the controlled feature was genuinely removed.

### 9.9 Incorrect `transactional` Declaration (NEW IN V1)

**Defect:** A rule declares `transactional: true` but contains a `command_exec`,
`manual`, or `grub_parameter_*` step. Or a rule declares `transactional: false` but all
its steps are capturable (the `false` was added defensively rather than correctly).

**Impact:** Operators running the rule have the wrong expectation. A `true` declaration
on a non-atomic rule falsely promises atomicity and will produce surprise partial
applications. A `false` declaration on an atomic rule hides a guarantee the engine
could have provided.

**Fix:** For the first case, either remove the non-capturable step (preferred) or
change the declaration to `false`. For the second case, verify every step is capturable
and remove the `false` declaration.

### 9.10 Unreviewed Rollback Path (NEW IN V1)

**Defect:** A rule with `transactional: true` uses a mechanism whose rollback handler
has not been tested against the specific parameters the rule passes.

**Impact:** The atomicity guarantee is theoretical. A real failure in production may
reveal that the rollback cannot actually restore the system.

**Fix:** Write the spec-derived rollback integration test for the specific parameter
combination before the rule ships.

### 9.11 Missing Control-Channel Safety (NEW IN V1)

**Defect:** A rule modifies SSH, networking, firewall, or PAM state but does not
activate the deadman-timer path.

**Impact:** A remediation that bricks the SSH connection leaves the engine unable to
roll back, and the system stays in the broken state until manual intervention.

**Fix:** Tag the rule as control-channel-sensitive so the engine arms the deadman
timer before applying. Verify the rollback script is tested.

---

## 10. Review Workflow

### 10.1 Per-Rule Review

For each rule file, work through the six dimensions in order:

1. **Check accuracy.** Read the check(s). Does this verify the effective system state?
2. **Remediation effectiveness.** Trace remediation to check. After remediation runs,
   will the check pass? Is the mechanism durable? Idempotent? Reboot-aware?
3. **Rollback safety.** For each step, is the capture sufficient? Is rollback
   complete? Is the `transactional` declaration correct? Is the rule
   control-channel-sensitive?
4. **Schema compliance.** Required fields, naming, severity, `transactional`
   declaration.
5. **Framework references.** Cross-check mapping files.
6. **Forward compatibility.** Platform scope, capability gates, capture/rollback
   compatibility with new OS versions.

### 10.2 Category-Level Review

When reviewing a full category:

- Check for missing `depends_on` relationships.
- Check for missing `conflicts_with` between mutually exclusive approaches.
- Verify consistent use of capabilities across similar rules.
- **New in V1:** Verify consistent use of `transactional` across rules in the category.
  If most rules in a category are atomic but one is not, that rule warrants extra
  scrutiny — is the escape hatch genuinely necessary, or is the rule written
  differently from its peers for no good reason?
- Look for rules that should exist but don't (coverage gaps).

### 10.3 Tracking Review Status

A rule has been reviewed when all six dimensions have been evaluated and any defects
have been fixed or documented.

| Category | Rules | Reviewed | V1 Atomicity Review | Defects Fixed |
|----------|-------|----------|---------------------|---------------|
| access-control | 114 | 114 | pending V1 pass | 78 (PRs #13-#20) |
| audit | 92 | 92 | pending V1 pass | ~146 (PRs #21-#28) |
| services | 92 | 92 | pending V1 pass | ~139 (PRs #29-#36) |
| system | 56 | 56 | pending V1 pass | ~30 (PRs #37-#42) |
| filesystem | 51 | 51 | pending V1 pass | ~68 (PRs #43-#48) |
| network | 42 | 42 | pending V1 pass | ~64 (PRs #49-#54) |
| kernel | 19 | 19 | pending V1 pass | ~18 (PRs #55-#56) |
| logging | 18 | 18 | pending V1 pass | ~28 (PRs #57-#59) |

The V0 review passes (which covered dimensions 1-5) are preserved. V1 adds a single
new pass: confirm every rule's `transactional` declaration, verify rollback safety for
every `transactional: true` rule, and tag control-channel-sensitive rules. This pass
is mechanical for ~80% of rules (they are single-step, capturable, and unambiguous) and
requires careful per-rule reasoning for the remaining 20%.

---

## 11. References

- **CANONICAL_RULE_SCHEMA_V1.md** — Rule schema specification with `transactional`
  field and mechanism capturability classification.
- **TECHNICAL_REMEDIATION_MP_V1.md** — Design philosophy with the atomicity principle
  and the four transaction phases.
- **TRANSACTION_CONTRACT_V1.md** — The customer-facing commitment document that these
  review criteria enforce.
- **schema/rule.schema.json** — Machine-validatable JSON Schema for rule files.
- **scripts/migrate_schema_v0_to_v1.py** — V0 → V1 migration script that adds
  `transactional: false` to rules containing non-capturable mechanisms.

---

*This document defines the review criteria for Kensa canonical rules. V1 formalizes
rollback safety as a first-class review dimension and remaps the V0 dimensions onto
the four transaction phases. Every rule in the canonical set must meet these criteria
before being considered production-ready.*
