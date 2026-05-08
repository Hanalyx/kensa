# Transaction Contract — Version 1

**Project:** Kensa
**Date:** 2026-04-13
**Status:** Draft — Corollary to `TECHNICAL_REMEDIATION_MP_V1.md`
**Audience:** Customers, auditors, insurers, FedRAMP reviewers, and Kensa engineers
**Companion:** `TECHNICAL_REMEDIATION_MP_V1.md`, `CANONICAL_RULE_SCHEMA_V1.md`, `RULE_REVIEW_GUIDE_V1.md`

---

## Why This Document Exists

`TECHNICAL_REMEDIATION_MP_V1.md` is an internal design document. `CANONICAL_RULE_SCHEMA_V1.md`
is an author-facing contract. `RULE_REVIEW_GUIDE_V1.md` is a reviewer-facing checklist.

This document is the **external-facing commitment.** It states, in operator-legible
terms, what Kensa guarantees when it modifies production systems, where those guarantees
end, and what the operator must do to receive them. It is the document that should be
referenced by:

- Customer Master Service Agreements (MSAs) that incorporate production-mutation
  indemnification.
- Errors & Omissions (E&O) insurance applications where the underwriter needs to
  understand what safety claims the tool actually makes.
- FedRAMP System Security Plan (SSP) documentation that describes control implementation
  for CM-3 (Configuration Change Control), CM-5 (Access Restrictions for Change),
  SI-10 (Information Input Validation), and CP-10 (System Recovery and Reconstitution).
- Auditor briefings that evaluate whether Kensa evidence supports the compliance
  claims the customer intends to make.
- Third-party integrators who call Kensa programmatically and need to understand the
  failure semantics.

The surrounding documents describe how atomicity is achieved. This document describes
what atomicity *means* and what it does not.

---

## Current Implementation Status (as of 2026-05-07)

This contract describes the **target** behavior of Kensa Go. The atomicity,
auditability, and reversibility commitments below are honored today for the
shipped, integration-tested mechanisms; some specific elements remain in
flight per the M7 punch list in `CLAUDE.md` and the migration roadmap in
`docs/roadmap/`. Where the code does not yet literally deliver a commitment,
this section names it explicitly.

- **Signing.** The Ed25519 signer (task #12) is not yet implemented;
  envelopes are produced with the canonical schema but the `Signature`
  field is empty bytes until task #12 ships. The envelope shape is final.
- **Kernel-primitive atomicity.** File-handler atomicity is delivered today
  through shell-level write-and-rename via the SSH transport, with rollback
  via captured pre-state. Literal kernel-primitive atomicity (`renameat2`,
  `O_TMPFILE`+`linkat`, `fsync` barriers) is the Phase 2 deliverable in
  `docs/roadmap/LOW_LEVEL_MIGRATION_V1.md`.
- **Deadman timer.** Today's deadman uses `at(1)` / `systemd-run` schedulers.
  The `timerfd(CLOCK_BOOTTIME) + pidfd_open + epoll` rebuild that survives
  suspend, clock jumps, and parent SIGSTOP is Phase 3 of the same roadmap.
- **Integration-test coverage.** 19 of the 29 shipped handlers have full
  integration tests under deliberate failure injection (`cmd/kensa-fuzz`).
  6 capturable handlers (`authselectfeatureenable`, `configappend`,
  `cryptopolicyset`, `cryptopolicysubpolicy`, `dconfset`, `pammodulearg`)
  need first-principles integration tests to clear the M7 ship gate.

External citations of this document (SSP, MSA, E&O insurance application,
FedRAMP review) should reference this preamble alongside the commitments
below — the contract is what we commit to deliver, scoped explicitly to the
current implementation status.

---

## 1. The Three Commitments

Kensa makes three commitments to every customer installing it. Each commitment is a
product property — something the engine provides by construction, not something an
operator must configure.

### 1.1 Atomicity

**Every rule's remediation either lands completely or leaves the system in the exact
state it was in before the rule began.**

Every canonical rule in Kensa is classified as either `transactional: true` or
`transactional: false`. For `transactional: true` rules — the default and the majority
of the rule set — the engine guarantees one of two outcomes:

- **Committed.** The change is in place, the rule's check passes, all dependent
  validators pass, and a signed evidence record is written to the transaction log. The
  system is in the target state.
- **Rolled back.** Every applied step has been reversed using its captured pre-state.
  The system is in the exact state it was in before the rule began. The transaction log
  records the attempted change, the failure point, and the rollback outcome.

There is no third outcome. There is no "partially applied." There is no "task 3 failed
and tasks 1 and 2 are stranded." There is no "Kensa exited and we are not sure what
state the system is in."

For `transactional: false` rules — a minority that use escape-hatch mechanisms like
`command_exec`, `manual`, or bootloader parameter changes — the atomicity commitment
applies only to the capturable steps. The non-capturable steps are explicitly surfaced
to the operator before the run begins, and any non-capturable step that runs
successfully is not reversed on failure. The operator sees this scope in the pre-run
summary and accepts it by proceeding.

### 1.2 Auditability

**Every Kensa transaction produces a structured evidence record that can be reviewed,
exported, and trusted by auditors, compliance officers, and future incident responders.**

Every transaction, whether committed or rolled back, produces an evidence envelope
containing:

- **Timestamp and duration** of the transaction.
- **Host and fleet context** — which system, which scan, which operator or scheduled job.
- **Pre-state snapshot** — the exact state of every capturable element before the
  change, captured before any mutation runs.
- **Change attempted** — the specific remediation mechanisms and parameters.
- **Validation results** — the pre-check, post-check, and any dependent validators,
  with their command output and comparisons.
- **Commit or rollback decision** — which outcome occurred and why.
- **Post-state snapshot** — either the target state (on commit) or the restored
  pre-state (on rollback).
- **Framework mappings** — which compliance controls this transaction satisfies.
- **Signature** — a cryptographic signature over the envelope, using a key managed per
  deployment. (See "Current Implementation Status" preamble above: the Ed25519 signer
  is task #12; envelopes today carry the canonical shape with empty signature bytes
  until that task lands.)

Evidence is stored alongside the change, not in a separate silo that can drift out of
sync. An auditor reviewing a compliance finding six months later can load the evidence
envelope and verify the finding without access to the original host.

Evidence can be exported in OSCAL format for regulatory submissions or machine
consumption, or in human-readable PDF/JSON for operator review.

### 1.3 Reversibility

**Every Kensa change can be rolled back — either automatically on validation failure or
manually on human decision — using the captured pre-state.**

Rollback is not a best-effort cleanup path. It is a first-class engine phase, tested
against real failure conditions as part of every mechanism's qualification. The target
state is that every capturable mechanism ships with a rollback handler that has been
integration-tested by deliberately inducing a mid-transaction failure on a real system
and verifying that the rollback restores the exact pre-state. (See "Current
Implementation Status" preamble: 19 of the 29 shipped handlers meet this bar today;
6 capturable handlers need first-principles integration tests to clear the M7 ship
gate.)

Manual rollback is available via `kensa rollback --start N` for any past transaction
within the retention window. Snapshots are retained for 7 days in active-rollback mode
(full reversal available), and for an additional 83 days in info-only mode (snapshot
readable but not executable), after which they are pruned.

Rollback is unavailable only for non-capturable mechanisms — `command_exec`, `manual`,
`grub_parameter_set`, `grub_parameter_remove` — which are explicitly surfaced in the
transaction log and excluded from the atomicity guarantee.

---

## 2. The Boundaries

Kensa does not claim guarantees it cannot honor. The boundaries below are explicit
product boundaries, not hidden caveats. Every customer, auditor, and underwriter should
understand them before relying on the atomicity commitment.

### 2.1 Non-Capturable Mechanisms

Certain Linux operations cannot be reliably reversed:

- **`command_exec`** — arbitrary shell commands. Pre-state cannot be inferred because
  the command's side effects are not known to the engine.
- **`manual`** — controls that require human intervention. No machine pre-state exists.
- **`grub_parameter_set` / `grub_parameter_remove`** — bootloader configuration changes
  that only take effect on the next boot. The runtime state cannot be modified
  mid-transaction, so mid-transaction rollback is not meaningful.

Rules that use any of these mechanisms are declared `transactional: false` in the rule
YAML and surface this declaration to the operator before execution. A rule that partially
applies due to a non-capturable step failure is recorded in the transaction log with
explicit partial-application flags. The operator sees the boundary — it is not hidden.

Over time, Kensa works to reduce reliance on non-capturable mechanisms by promoting
repeated `command_exec` patterns to first-class capturable mechanisms.

### 2.2 SSH Control Channel

Kensa connects to target hosts over SSH. The SSH connection is Kensa's control channel.
A small number of changes — to SSH configuration, networking, firewall rules, or PAM
authentication — can disable the SSH connection itself, leaving the engine unable to
complete rollback over that connection.

For these changes, Kensa uses a **deadman-timer rollback path**:

1. Before applying the change, Kensa uploads a self-contained rollback script to the
   host and schedules it to run in a short window (default: 120 seconds) via `at` or
   `systemd-run`.
2. Kensa applies the change.
3. If the control channel survives, Kensa cancels the scheduled rollback script and
   removes it from the host.
4. If the control channel does not survive, the scheduled script fires on schedule and
   restores the pre-change state out of band.

The deadman timer makes the atomicity commitment honorable even for control-channel-
affecting changes. It requires that the target host have `at` or `systemd-run` available
(both are present on every supported RHEL release) and that the operator has sudo
privilege to schedule jobs.

If the deadman-timer path cannot be used (for example, because the target host has no
scheduler available), rules that affect the control channel are declared
`transactional: false` and the operator must accept the risk or exclude them from the
run. The boundary is surfaced before execution, not discovered after.

### 2.3 Multi-Run Boundaries

Atomicity applies within a single invocation of `kensa remediate`. It does not apply
across multiple invocations. If an operator runs `kensa remediate` on Monday and again
on Tuesday, the state between runs is whatever Monday's run left in place. Tuesday's
run does not retroactively roll back Monday's changes if Tuesday's run fails.

Operators who need run-level atomicity across a batch of rules can use `--atomic-run`,
which wraps the entire invocation's rules in a meta-transaction. All rules commit
together, or all roll back together. This is an explicit opt-in. The default is
per-rule atomicity.

### 2.4 Events Outside Kensa's Control

Atomicity covers changes Kensa initiates. It does not cover:

- Changes made by other tools (Ansible, Puppet, manual operator actions) between Kensa
  runs.
- Kernel panics, hardware failures, power loss, or other events that interrupt a
  transaction beyond Kensa's ability to recover. In these cases, the transaction log's
  pre-state snapshot is preserved to durable storage and can be used for out-of-band
  recovery via `kensa rollback --start N`, but the recovery itself requires the host to
  be accessible again.
- Application-level state (database content, customer data, in-memory caches). Kensa
  modifies configuration; it does not manage the data the configured systems operate on.

### 2.5 Scope: Linux Hosts

Kensa operates on Linux hosts. It does not modify Windows, macOS, container images as
artifacts (it does manage containers as hosts where the containers run systemd-managed
services), cloud control planes, or network appliances. Atomicity is a Linux-host
commitment.

---

## 3. The Operator's Obligations

The atomicity commitment is the engine's. For the commitment to deliver real value, the
operator has a small set of obligations:

### 3.1 Before Running `kensa remediate` in Production

- **Install Kensa's agentless SSH access with sudo.** Kensa requires privileged access
  to apply changes and capture pre-state. Install using the standard deployment
  procedure.
- **Review the pre-run summary.** Kensa displays, before any change runs, the list of
  rules that will execute, each tagged with its `transactional` status. Operators are
  responsible for reviewing this list and excluding rules they do not want to apply.
- **Accept non-atomic rules explicitly.** If any rule in the run is `transactional:
  false`, the pre-run summary surfaces this. The operator must acknowledge by continuing.
  Kensa does not execute non-atomic rules without an acknowledgment.
- **Ensure durable storage for the transaction log.** By default, Kensa writes to
  `.kensa/results.db` on the operator's workstation or a configured location. Operators
  should ensure this path is on durable storage with backup, because the transaction
  log is the rollback authority for past runs.

### 3.2 During Execution

- **Do not interrupt the engine.** `Ctrl-C` during a transaction is handled safely —
  Kensa will attempt rollback — but it is better to let transactions complete. If Kensa
  is killed during APPLY, the deadman timer (for control-channel-sensitive changes) or
  the post-crash recovery path (for all other changes) will restore pre-state, but the
  recovery is more complex than a clean rollback.
- **Do not modify the host from another channel.** If an operator SSHs into the host
  and makes manual changes while Kensa is mid-transaction, the capture snapshot no
  longer reflects the system's current state, and rollback may restore an unexpected
  prior configuration. Operator discipline is required.

### 3.3 After Execution

- **Review the transaction log.** Every run produces a transaction log that should be
  reviewed as part of the operator's change management process.
- **Retain the evidence envelopes** for the retention period required by the
  operator's compliance program (typically 1-7 years for federal compliance).
- **Report anomalies.** If a transaction outcome does not match the log (e.g., the log
  says committed but the system is not in the target state), report to Kensa support.
  This is the failure mode Kensa is built to prevent, and any real-world instance is a
  bug we will investigate and fix.

---

## 4. What the Commitment Enables

The three commitments are not abstract. They enable specific customer outcomes that
competing tools cannot match:

### 4.1 Production Remediation Confidence

Operators can run `kensa remediate` in production without the "what if it breaks prod
at 3 AM" fear that characterizes Ansible, Chef, and Puppet runs. The engine's
atomicity commitment means the worst outcome of a failed remediation is a rolled-back
transaction — not a broken system.

### 4.2 Auditable Change Control

Every change Kensa makes is captured, signed, and retained. An auditor asking "who
changed this, when, why, and with what evidence" gets a transaction log entry with
pre-state, change, validation, commit decision, and post-state. This is the chain of
custody federal auditors and regulated-industry auditors require, and Kensa produces
it automatically for every change.

### 4.3 AI Agent Safety Layer

AI agents modifying production infrastructure have the same problem human operators
have: how do I know the change I made did not break something, and how do I undo it if
it did? Kensa's atomicity commitment is the primitive an AI agent needs to operate
safely in production. An agent wraps its change in a Kensa transaction; the engine
captures, applies, validates, and decides. The human reviewer sees a complete
transaction log of every attempted change, committed or rolled back, with evidence.

As AI-driven infrastructure automation grows, this safety layer becomes increasingly
load-bearing. The commitment Kensa makes today is the foundation the AI-agent future
runs on top of.

### 4.4 Insurance and Contractual Backing

Because the atomicity commitment is verifiable (via the transaction log and the signed
evidence envelopes), Hanalyx is able to offer contractual indemnification for rollback
failures. This is a commitment no general-purpose automation tool makes and no
AI-generated knockoff can credibly make, because indemnification requires a company
with insurance, contracts, and a phone number — not a tool with a README.

---

## 5. Verifying the Commitment

The commitment is not a marketing claim. It is verifiable:

### 5.1 By Reading the Code

Kensa is open source under BSL 1.1 (transitioning to Apache 2.0 in 2029). Every capture
handler, every rollback handler, and every transaction boundary is readable in the
public repository. No black box.

### 5.2 By Reading the Tests

Every mechanism's rollback handler ships with a spec-derived integration test that
induces a real failure on a real system and confirms the rollback restores pre-state.
These tests are part of the public repository and run on every commit.

### 5.3 By Running Your Own Failure Injection

Customers can run Kensa's failure-injection harness against their own test
environments. The harness is part of the repository. It deliberately induces apply and
validate failures and confirms that the engine behaves as this document specifies.

### 5.4 By Reading the Transaction Log

Every customer's transaction log is a factual record of what Kensa did and what
happened. A commitment that is honored in the log is a commitment that is honored.
Kensa does not publish self-reported reliability metrics; it publishes the mechanism by
which operators verify the commitment themselves.

---

## 6. The One-Sentence Version

**Every change Kensa applies to your production Linux systems is wrapped in a
transaction that either lands completely or leaves the system exactly as it was, with
signed evidence for every outcome — and where that guarantee cannot be honored, Kensa
tells you before it runs.**

---

## 7. Change Log

**V1 (2026-04-13)** — Initial version. Corollary to `TECHNICAL_REMEDIATION_MP_V1.md`.
Establishes the three commitments (Atomicity, Auditability, Reversibility), the five
boundaries (non-capturable mechanisms, SSH control channel, multi-run, events outside
Kensa's control, scope), and the verification paths (code, tests, failure injection,
transaction log).

Future revisions will track:

- Changes to the scope of atomicity as new mechanisms are promoted from non-capturable
  to capturable.
- Changes to the deadman-timer path as new platforms are supported.
- Extensions to multi-run atomicity if customer demand justifies it.
- Updates to the verification paths as additional third-party validation becomes
  available.

---

*This document is the customer-facing commitment that `TECHNICAL_REMEDIATION_MP_V1.md`,
`CANONICAL_RULE_SCHEMA_V1.md`, and `RULE_REVIEW_GUIDE_V1.md` together make possible.
It is the contract between Hanalyx and every operator, auditor, insurer, and integrator
who relies on Kensa's atomicity guarantee. Every claim in this document is verifiable
in the public repository.*
