# Concepts

_Applies to: Kensa v0.6.0 — last updated 2026-06-22._

Kensa is a compliance engine, but its core is not the rules. It's the
*transaction*: the four-phase Kensa operation (capture, apply, validate,
commit or roll back). Every change Kensa makes to a host runs as a
transaction, and that atomicity is the product. The compliance rules are
the first application of it. This chapter is the mental model behind the
commands in [02-quickstart](02-quickstart.md); the per-mechanism specifics
live in [10-mechanisms](10-mechanisms.md).

## The four-phase transaction

When `remediate` applies a rule, the engine runs four phases in order:

1. **Capture.** Before touching anything, the engine records the host's
   exact prior state for everything the change is about to modify (file
   bytes and attributes, a service's enablement, a sysctl value, whatever
   the mechanism touches). This snapshot is written to durable storage
   *before* any mutation, so it survives a crash.
2. **Apply.** The change is made.
3. **Validate.** The engine re-checks the host to confirm the change landed
   and that no dependent validator broke.
4. **Commit or Rollback.** If validation passes, the transaction commits and
   a signed evidence record is written. If anything fails, the engine
   reverses every applied step from the captured pre-state, returning the
   host to exactly where it began.

There is no third outcome. A rule either lands completely or leaves the host
in the state it was in before the rule began: no "partially applied," no
"step 3 failed and steps 1–2 are stranded." That guarantee is the contract
in `docs/TRANSACTION_CONTRACT_V1.md`, and it's what distinguishes Kensa from
a remediation script.

## The per-rule transaction boundary

The transaction boundary is **one rule**. Each rule captures, applies,
validates, and commits or rolls back on its own before the engine moves to
the next rule. A failure in rule 7 rolls back rule 7; it doesn't unwind
rules 1 through 6, which already committed and are individually recorded.
This keeps the blast radius of any single failure to a single rule and makes
the transaction log a per-rule ledger you can query and selectively reverse.

## Agent mode vs shell fallback

Kensa changes a host through one of two paths, chosen automatically:

- **Agent mode** is the default on `remediate`. Kensa spawns a small agent on
  the target that drives kernel primitives directly: atomic file replace via
  `renameat2`, `/proc/sys` writes, `delete_module(2)`, systemd over D-Bus,
  audit over netlink. This is where the strongest atomicity guarantees live:
  a crash mid-apply leaves either the old bytes intact or the new bytes
  complete, never a torn file.
- **Shell fallback** runs the equivalent change over the plain SSH shell
  transport. It's used when agent bootstrap isn't viable, and it's selected
  per-mechanism when a kernel primitive or privilege isn't available. Both
  paths write byte-identical files and record an identical pre-state, so
  capture and rollback behave the same either way; the shell path's
  mid-apply crash semantics are best-effort rather than kernel-atomic.

Set `KENSA_NO_AGENT=1` to force the shell path everywhere, which helps when
the agent can't be bootstrapped. You lose the kernel-atomic guarantee on the
file mechanisms but keep the four-phase transaction and rollback.

`check` is read-only and doesn't need agent mode for its guarantees; the
agent matters where Kensa *writes*.

## Reversible vs non-reversible rules

A rule is `transactional: true` (the default and the majority of the corpus)
or `transactional: false`.

- **Transactional rules** are backed by a mechanism that can both capture the
  prior state and restore it. These are covered by the atomicity guarantee:
  apply-time failure rolls back automatically, and you can deliberately roll
  them back later with `kensa rollback`.
- **Non-transactional rules** use escape-hatch mechanisms (`command_exec`,
  `manual`, bootloader parameter changes) that Kensa can't manufacture an
  inverse for. Kensa runs them and records them in the transaction log for
  audit, but they are **not** under the rollback guarantee. A non-capturable
  step that ran successfully is not reversed on a later failure, and rollback
  reports it as skipped rather than pretending to restore it.

The reversal level of each shipped mechanism (Atomic, Reversible,
Best-effort, Staged, or None) is tabulated in
[10-mechanisms](10-mechanisms.md). Boot-parameter changes are a special
"Staged" case: Kensa never edits the saved boot default directly but stages
the change through a one-shot trial boot, so a host that fails to boot
reverts on its own.

## Platform gating

The shipped corpus is large and not every rule applies to every host. Before
running a rule, Kensa compares the rule's `platforms:` block against the
host's detected OS. A rule that doesn't apply to this host renders **`SKIP`**:
it is neither checked for a pass/fail nor, on `remediate`, ever applied.
This is deliberately lenient: a rule with no `platforms:` block runs
everywhere, and an undetectable host OS gates nothing.

Gating is the standalone-CLI safety net. It's why a `SKIP` is meaningful in
the output: it tells you the rule was *intentionally not applicable here*,
not that it errored. (In a fleet, an orchestrator typically pre-filters by
platform upstream; the in-engine gate protects the CLI user who has no such
upstream.)

## Signed evidence envelopes

Every transaction, committed or rolled back, produces a structured
evidence envelope: a signed record carrying the timestamp and duration,
host context, the pre-state snapshot, the change attempted, the validation
results, the commit-or-rollback decision, the post-state, and the
framework-control mappings. The envelope is signed with an Ed25519 key so an
auditor can verify a finding months later without access to the original
host; `kensa verify` checks that signature on an envelope file.

Evidence is stored alongside the change in the transaction log, not in a
separate silo that can drift out of sync, and it can be exported in Open
Security Controls Assessment Language (OSCAL) 1.0.6 for regulatory
submission. For a stable signer identity across runs,
point `KENSA_SIGNING_KEY` at your private key (see [01-install](01-install.md));
without it Kensa uses an ephemeral per-process key.

## Rollback completeness

The whole guarantee rests on one thing: **Capture must record every piece of
state that Apply touches.** If Apply changes something Capture didn't record,
rollback can't restore it; the reversal would be incomplete. So
capture-completeness is treated as a first-class property of every
capturable handler, not an afterthought.

This is enforced by a *footprint* pre-commit gate: in agent mode the kernel-IO
layer records each filesystem resource a handler actually touches, and the
engine refuses to commit (rolling back first) if a handler touched anything
it didn't capture (`observed ⊆ captured`). A pre-apply restorability probe also
refuses to mutate a captured resource that is immutable (`chattr +i`), because a
rollback that can't rewrite it is impossible. The gate is opt-in per handler and
covers the kernel-atomic (fsatomic-funnelled) filesystem writes on the agent
path; for the direct-SSH shell fallback and for non-opted handlers, the
mandatory human review every capture/rollback handler goes through
(`CONTRIBUTING.md`) remains the backstop. Either way, the operator-facing
promise is the same: a rule that can't be fully restored does not get to claim a
clean commit.

## Where this leads

- [02-quickstart](02-quickstart.md): these concepts as four commands.
- [10-mechanisms](10-mechanisms.md): every mechanism, where it runs, and its
  reversal level.
- `docs/TRANSACTION_CONTRACT_V1.md`: the external-facing atomicity
  commitment in full.
