# Kensa Vision

**Status:** Founding document, draft v1
**Companion documents:**
- `HANALYX_MISSION_AND_ROADMAP.md` — company mission and 18-month trust roadmap
- `AI_DEFENSIBILITY.md` — why Hanalyx becomes more valuable as AI improves
- `HANALYX_18_MONTH_STRATEGY.md` — tactical strategy and 90-day plan

---

## What Kensa Is

**Kensa is transactional configuration management for Linux.**

Every change is captured, applied, validated, and either committed or automatically rolled back. No half-applied state. No 3 AM recovery. Auditable evidence for every change — whether a human or an AI made it.

---

## The Category

Every developer already knows what a transaction is. Databases have had transactions for 50 years: `BEGIN` → write → check → `COMMIT` or `ROLLBACK`. The guarantee a database transaction makes is that **either the whole change lands successfully, or the system ends up exactly where it started.** There is no "half-applied" state.

Kensa gives you that same guarantee for Linux configuration changes.

| Database | Kensa |
|---|---|
| `BEGIN TRANSACTION` | Capture pre-state |
| `UPDATE ...` | Apply the change (sshd config, kernel param, package install, etc.) |
| Constraint check | Validate the change (did the service restart? does the config parse?) |
| `COMMIT` | Leave the change in place |
| `ROLLBACK` | Restore pre-state automatically |

This framing is not a metaphor. It is an architectural claim. Kensa provides atomicity for Linux configuration changes in a way no general-purpose automation tool does today. Ansible does not give you this. Chef does not give you this. Puppet does not give you this. SaltStack does not give you this. Terraform gives you an analog for cloud resources but not for in-host configuration. **Kensa is the first production-grade transactional configuration management system for Linux.**

## The Four Phases

Every Kensa operation runs through four phases. Each phase has its own failure handling. The guarantee is that regardless of which phase fails, the system ends in a known-good state — either the target state or the exact pre-change state.

1. **Capture** — record the precise pre-state of whatever is about to be touched. Kensa currently ships 35+ capture handlers covering packages, services, files, kernel parameters, SELinux policy, mounts, users, sshd configuration, firewalld rules, systemd units, crypto policies, audit rules, PAM configuration, bootloader parameters, and more. The captured state is typed per mechanism, not a generic diff.
2. **Apply** — make the change using the corresponding remediation handler. Handlers are declarative and idempotent.
3. **Validate** — verify that the change produced the intended effect and did not break anything else. Services must restart. Configs must parse. Dependent state must remain consistent.
4. **Commit or Rollback** — if validation passed, the change is kept and evidence is written to the audit log. If validation failed, the corresponding rollback handler restores the captured pre-state automatically and the operation is recorded as rolled back.

The product promise is that phase 4 always terminates. Either the target state is achieved or the original state is restored. There is no third outcome where the system is stuck halfway.

## Why This Matters

### For humans

Linux automation is scary because the failure mode is "I broke prod at 3 AM and now I have to manually reconstruct what was there before I ran the playbook." Ansible does not remember what sshd_config looked like before you edited it. Chef does not remember what sysctl values were set before you converged. **Kensa does.** Every change is reversible by construction, not by hope.

This is the difference between a tool that *applies* changes and a tool that *guarantees* them. Ansible applies changes. Kensa guarantees them.

### For auditors

Every Kensa transaction produces a structured evidence record containing: the pre-state (what the system looked like before), the change attempted, the validation result, the commit/rollback decision, and the post-state (what the system looks like after). This is the full chain of custody an auditor needs to trust the system.

Traditional compliance scanners produce "we found 4,000 issues" reports and hand the remediation work to humans, leaving a gap in the audit trail between *finding* and *fix*. Kensa closes that gap. Every finding that Kensa remediates is a transaction with verifiable before-state, after-state, and evidence of safe application.

### For AI agents

This is the deepest reason Kensa will matter beyond compliance.

As AI agents increasingly modify production infrastructure — coding assistants editing configs in CI, autonomous SRE agents applying patches, remediation bots responding to alerts — every one of these agents faces the same problem: **how do I know the change I just made did not break something, and how do I undo it if it did?**

An AI agent cannot safely mutate production without a primitive that captures state, applies changes transactionally, validates the outcome, and rolls back on failure. That primitive is Kensa. The rollback-safe state engine is not just a compliance tool. It is the missing safety layer that AI-driven infrastructure automation has been waiting for.

When an AI agent in 2027 or 2028 needs to apply a configuration change to a production Linux host, the question "is this safe?" will be answered by wrapping the change in a Kensa transaction. The agent describes what it wants. Kensa captures, applies, validates, and decides. The human in the loop gets to see a full transaction log of every attempted change, committed or rolled back, with evidence.

**Kensa is the transaction layer for human and AI Linux automation.** Compliance is the first market. It is not the final market.

## Positioning Against Adjacent Categories

Kensa does not compete head-on with any of these tools. It occupies a space next to them that none of them currently fill.

| Category | Representative tools | What they do | What they don't do |
|---|---|---|---|
| **Configuration management** | Ansible, Chef, Puppet, Salt | Apply declarative state to fleets | No pre-state capture, no automatic rollback, no transactional guarantee |
| **Compliance scanners** | Tenable, Qualys, Rapid7, Wiz, OpenSCAP | Detect misconfigurations | Do not remediate; leave the fix to humans |
| **Compliance platforms** | Drata, Vanta, Secureframe | Track evidence and controls | Do not touch infrastructure directly |
| **IaC / cloud provisioning** | Terraform, Pulumi, Crossplane | Manage cloud resource lifecycle | Do not handle in-host Linux configuration |
| **Observability** | Datadog, Grafana, Prometheus | See what is happening | Do not change anything |
| **Kensa** | — | Transactional in-host Linux changes with automatic rollback | — |

The positioning sentence that distinguishes Kensa from the closest peer: *"Ansible applies changes. Kensa guarantees them."*

## The Product Promise

Every customer installing Kensa is making one bet: that their production Linux infrastructure is safer with Kensa in the loop than without it. The product promise that justifies that bet has three parts, and each part is a commitment we must earn daily:

1. **Atomicity.** Every Kensa change either lands completely or leaves the system exactly as it was. No half-applied state. No partial remediation. No drift caused by Kensa itself.
2. **Auditability.** Every Kensa change produces a structured evidence record that can be reviewed, exported, and trusted by auditors, compliance officers, and future incident responders. The evidence is stored alongside the change, not in a separate silo that can drift out of sync.
3. **Reversibility.** Every Kensa change can be rolled back either automatically (on validation failure) or manually (on human decision) using the captured pre-state. The rollback path is tested under real failure conditions, not just in the happy path.

These three properties — atomicity, auditability, reversibility — are the entire product. Everything else is a feature. The moment we ship a change that violates any of them, we are no longer selling what customers thought they bought.

## The Boundary: What Kensa Is Not

Naming what Kensa is not is as important as naming what it is, because the category is narrow on purpose.

- **Kensa is not a scanner.** Scanning is the weakest, most replicable part of the product. We do it because remediation requires detection, not because detection is the point.
- **Kensa is not a configuration management replacement.** Customers should still use Ansible (or equivalent) for their day-to-day infrastructure provisioning. Kensa is the layer that runs underneath when a change needs transactional guarantees.
- **Kensa is not a compliance platform.** We do not track controls, manage evidence collection across non-Linux systems, or produce organization-wide compliance dashboards. OpenWatch exists for the adjacent problem.
- **Kensa is not a Windows, macOS, or container-as-target tool.** The scope is Linux hosts. Containers are in scope when they are hosts (CIS Docker, CIS Kubernetes Node); they are out of scope as immutable artifacts.
- **Kensa is not an observability tool.** We capture what changes, not what is happening in real time.
- **Kensa does not replace human judgment about risk.** Every rollback path is written by a human who personally reasoned about the failure modes. Kensa is the safety rail, not the driver.

## The Vision, Extended

The original mission statement: **No Linux change should ever be unsafe, unauditable, or unreversible — whether a human or an AI made it.**

Kensa is how that mission is delivered. If the mission says *what must be true*, Kensa says *how*. Every change is a transaction. Every transaction has atomicity, auditability, and reversibility. Every transaction terminates in a known state. Every transaction produces evidence a human can trust.

In five years:

- When a federal contractor needs to pass a STIG audit, they run Kensa.
- When an SRE at a commercial company needs to change a kernel parameter across 5,000 hosts without risking a 3 AM incident, they run Kensa.
- When an autonomous AI agent needs to modify a production configuration and prove to a human reviewer that the change is reversible, it runs Kensa underneath.
- When an auditor asks "who changed this, when, how, and could it be safely undone," the answer is the Kensa transaction log.

Kensa is the transaction layer for human and AI Linux automation. The category is transactional configuration management. The guarantee is atomic, auditable, reversible change. The buyers are everyone who runs Linux in production and cannot afford a half-applied change.

---

## The One-Line Version

**Kensa is transactional configuration management for Linux. Ansible applies changes. Kensa guarantees them.**

---

## The Kensa Landing Page Hero

> ### Kensa is transactional configuration management for Linux.
>
> Every change is captured, applied, validated, and either committed or automatically rolled back. No half-applied state. No 3 AM recovery. Auditable evidence for every change — whether a human or an AI made it.
>
> *Ansible applies changes. Kensa guarantees them.*

---

*End of document.*
