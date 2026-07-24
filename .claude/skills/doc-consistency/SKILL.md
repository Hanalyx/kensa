---
name: doc-consistency
description: Conventions for Kensa's front-door docs (README, CONTRIBUTING, CHANGELOG, SECURITY) and how to keep them consistent. Use when editing any of these files, adding a user-visible change, or preparing a release. The `make docs-check` gate enforces the mechanical parts.
---

# Front-door documentation consistency

Kensa's front-door docs are `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and
`SECURITY.md`. `make docs-check` (CI job **Docs consistency**,
`scripts/docs_check.sh`) enforces the mechanical invariants; this skill covers the
judgment the gate can't.

Run `make docs-check` after touching any of these files or `VERSION`.

## CHANGELOG.md — Keep a Changelog

- **Every user-visible change gets an entry under `## Unreleased`** as part of the
  same PR — a new flag, a changed default, a fixed verdict, a security bump. Pure
  internal refactors and corpus-count churn don't need one; a changed *verdict* or
  *behaviour* does.
- Use the six categories: **Added / Changed / Deprecated / Removed / Fixed /
  Security**. Write for a human reading the release, not a commit log.
- **Never delete the `## Unreleased` heading.** At release time, rename it to
  `## vX.Y.Z — YYYY-MM-DD` (ISO date) and add a fresh empty `## Unreleased` above.
- Call out anything that **changes a shipped verdict** or needs a **consumer
  action** (e.g. "OpenWatch must map the new `staged` status"). Flag breaking or
  `api/` changes explicitly — they drive the SemVer bump.
- Keep the file scannable; archive old per-release detail to
  `docs/archive/RELEASE_HISTORY.md`. Don't restructure the `## vX.Y.Z` headings —
  release tooling greps them.

## Release stamping (VERSION ↔ CHANGELOG)

- `VERSION` tracks the newest **stamped** CHANGELOG version — `make docs-check`
  fails if they diverge. Bump both together in the `release: prepare vX.Y.Z` PR.
- SemVer, pre-1.0: additive `api/` changes or a new capability → MINOR; fixes →
  PATCH. `api/` is frozen under v1 — additions only, and note the consumer impact.
- Tagging `vX.Y.Z` (founder-gated) triggers the signed release pipeline. Refresh
  the README **Status** version in the same release PR — a stale Status is the
  drift `docs-check` catches.

## README.md

- Keep the badges (CI, latest release, license, security policy) at the top and
  the **Status** section's version current — it must mention the `VERSION` string.
- It's the entry point, not the manual: lead with what Kensa does + copy-paste
  commands; link into `docs/guide/` for depth.
- Keep the **Security** section pointing to `SECURITY.md` (never tell people to
  file vulnerabilities as public issues).

## CONTRIBUTING.md

- Preserve the review discipline (spec-before-code, failure-mode analysis for
  engine/capture/rollback, two-reviewer for rollback handlers, capture
  sufficiency, the comment/planning-label rules).
- Bug reports go to GitHub issues with version + OS + command + expected/actual;
  **security reports go to `SECURITY.md`**, never a public issue.
- Commit messages: imperative present tense; the body explains the mechanism (same
  standard as code comments — no planning labels/chronology); AI-authored commits
  carry a `Co-Authored-By:` trailer.

## SECURITY.md

- It exists — don't duplicate it. Keep README + CONTRIBUTING linking to it
  (`docs-check` verifies both links). If the disclosure channel, GPG key
  fingerprint, or safe-harbor terms change, update `SECURITY.md` and `KEYS`.
