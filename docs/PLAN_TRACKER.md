# Plan Tracker

**Last updated:** 2026-03-14

Consolidated status tracker for four active planning documents. Updated after each PR.

---

## Summary

| Plan | Status | Progress |
|------|--------|----------|
| Framework Simplification | **~95% done** | Phases 1-4 complete, Phase 5 partial |
| CIS Baseline Alignment | **~95% done** | Parts A + B PRs 1-2 complete, optional PR 3 not done |
| Typed Mechanism Migration | **~45% done** | Phases 1-2 done, 3-5 partial, 6 not started |
| Gap Closure | **~75% done** | Phase 1 complete, Phase 2 complete (7/7 WS), Phase 3 partial |

---

## 1. Framework Simplification Plan

**Source:** `docs/FRAMEWORK_SIMPLIFICATION_PLAN.md`
**Goal:** Drop benchmark version numbers from CIS/STIG mapping IDs, establish "one living mapping per framework+platform."
**Merged in:** PR #151

| Phase | Description | Status | PR |
|-------|-------------|--------|-----|
| 1 | Schema + mapping infrastructure | Done | #151 |
| 2 | Rule reference key migration (~500 rules) | Done | #151 |
| 3 | Scripts and validation tooling | Done | #151 |
| 4 | Tests | Done | #151 |
| 5 | Documentation | Partial | #151 |

### Phase 5 remaining work

Customer-facing docs (README, QUICKSTART, ADMIN_GUIDE, AUDITOR_GUIDE) updated. Historical/internal docs still reference old versioned IDs in some places — low priority since they describe the state at time of writing.

### Verification

- [x] `python3 -m schema.validate rules/` — 0 failures
- [x] `grep -r 'rhel9_v2:' rules/` — 0 results
- [x] `grep -r 'rhel8_v4:' rules/` — 0 results
- [x] `grep -r 'rhel9_v2r7:' rules/` — 0 results
- [x] `grep -r 'rhel8_v2r6:' rules/` — 0 results
- [x] Mapping files have `version:` metadata field
- [x] NIST, PCI-DSS, FedRAMP unchanged

---

## 2. CIS Baseline Alignment Plan

**Source:** `docs/CIS_BASELINE_ALIGNMENT_PLAN.md`
**Goal:** Align CIS RHEL 8/9 mappings to verified SOT baselines.
**Merged in:** PR #151

| Part | Description | Status | PR |
|------|-------------|--------|-----|
| A | RHEL 8: Add 11 missing controls, fix 3 errors | Done | #151 |
| B PR1 | RHEL 9: Remove 53 phantoms, remap 15 renumbers | Done | #151 |
| B PR2 | RHEL 9: Add 17 new SOT controls (mapped or unimplemented) | Done | #151 |
| B PR3 | RHEL 9: Clean up 31 superseded rules (optional) | Not done | — |

### Part B PR 3 — superseded rule cleanup

31 old rules (e.g., `audit-network-changes`, `service-disable-samba`) were replaced by correct-name counterparts at SOT target IDs. These old rules still exist in `rules/` but are no longer referenced by CIS RHEL 9. Options:

- Add `conflicts_with:` to old rules
- Remove stale `rhel9:` references from old rules
- Deprecate rules with no remaining framework references

This is optional cleanup. The critical alignment work is complete.

### Current CIS coverage

| Mapping | SOT controls | Mapped | Unimplemented | Coverage |
|---------|-------------|--------|---------------|----------|
| CIS RHEL 8 | 322 | 293 | 29 | 91.0% |
| CIS RHEL 9 | 297 | ~280 | ~17 | ~94.3% |

---

## 3. Typed Mechanism Migration Plan

**Source:** `docs/TYPED_MECHANISM_MIGRATION_PLAN.md`
**Goal:** Migrate 176 escape-hatch remediations to typed mechanisms, raising typed coverage from 63.6% to 92.6%.
**Merged in:** PRs #151 and #152

### Phase status

| Phase | Description | Planned | Done | Status | PR |
|-------|-------------|---------|------|--------|-----|
| 1 | file_permissions bulk (33 rules) | 33 | 33 | Done | #151 |
| 2 | config_set + config_append (33 rules) | 33 | 33 | Done | #151 |
| 3 | PAM rules (30 rules) | 30 | 11 | **Partial** | #152 |
| 4 | GDM dconf (15 rules) | 15 | 21 | **Exceeded** | #152 |
| 5 | System utilities (9 rules) | 9 | 5 | **Partial** | #152 |
| 6 | File content (7 rules, 5 overlap Phase 4) | 2 | 0 | Not started | — |
| **Total** | | **176** | **~103** | | |

### Current remediation mechanism breakdown

As of 2026-03-13 (744 total remediation steps):

| Mechanism | Count | % |
|-----------|-------|---|
| Typed/declarative | 591 | 79.4% |
| manual | 114 | 15.3% |
| command_exec | 39 | 5.2% |

Started at 63.6% typed → now at **79.4%**. Target is 92.6%.

### Phase 3 — PAM remaining (19 rules)

**Done (11):** pam-faillock-enabled, pam-faillock-password-auth, pam-faillock-system-auth, pam-faillock-silent, pam-pwhistory-enabled, pam-pwquality-enabled, pam-pwquality-password-auth, pam-pwquality-system-auth, pam-unix-enabled, su-require-wheel, pam-wheel-su

**Not done (19):** These are PAM arg-modification rules (e.g., add/remove module arguments like `nullok`, `remember=`, `use_authtok`). Converting them risks losing existing module args without a more sophisticated handler that parses and manipulates PAM config arg lists.

Key remaining:
- pam-unix-no-nullok, pam-unix-no-remember, pam-unix-use-authtok
- pam-sha512-rounds-password-auth, pam-sha512-rounds-system-auth
- pam-faillock-even-deny-root, pam-faillock-deny, pam-faillock-fail-interval, pam-faillock-unlock-time
- pam-pwquality-dcredit, pam-pwquality-lcredit, pam-pwquality-minclass, pam-pwquality-minlen, pam-pwquality-ocredit, pam-pwquality-ucredit
- authselect-profile-pam
- pam-pwhistory-root, pam-pwhistory-use-authtok (cmd_exec impl)
- pam-maxlogins

### Phase 4 — GDM dconf (exceeded target)

Converted 21 rules (plan targeted 15 in `system/` only). Also converted `services/` GDM rules. New `dconf_set` handler created with spec, capture, and rollback support.

**Not converted (by design):**
- gdm-graphical-banner — org-specific banner text, stays manual
- gdm-xdmcp-disabled — edits /etc/gdm/custom.conf, not dconf
- gdm-dconf-database-current — simple `dconf update` command

### Phase 5 — System utilities remaining (4 rules)

**Done (5):** coredump-socket-disabled (→ service_masked), pkg-abrt-absent (→ package_absent), crypto-policy-fips, crypto-policy-no-weak, crypto-policy-disable-sha1-signatures (first impl)

**Not done (4):**
- no-graphical-target — `systemctl set-default`, no handler exists
- crypto-policy-strong-macs — dynamic subpolicy appending to unknown base policy
- crypto-policy-no-cbc-ssh — same dynamic pattern
- crypto-policy-no-sha1 step 2 — same dynamic pattern

### Phase 6 — file_content (2 rules)

- banner-ssh-dod — org-specific DoD banner text
- motd-configured — empty or org-specific content

Both may be better left as manual due to org-specific content requirements.

### New handlers created

| Handler | Spec | Tests | Capture | Rollback | Risk class |
|---------|------|-------|---------|----------|------------|
| config_append | Yes | Yes | Yes | Yes | medium |
| dconf_set | Yes | Yes | Yes | Yes | medium |
| crypto_policy_set | Yes | Yes | Yes | Yes | medium |

---

## 4. Gap Closure Plan

**Source:** `docs/GAP_CLOSURE_PLAN.md`
**Goal:** Close the gap from pilot-ready to broad GA-ready product.

### Phase 1 — Trust and Launch Hygiene

| # | Workstream | Status | Notes |
|---|-----------|--------|-------|
| 1 | Fix public claim accuracy | **Done** | All customer-facing docs audited and corrected (README, QUICKSTART, ADMIN_GUIDE, MARKETING). |
| 2 | Publish strict support boundary | **Done** | `docs/SUPPORT_MATRIX.md` created with platform tiers, framework coverage, terminology. |
| 3 | Make buyer trust a tested surface | **Done** | 8 spec-derived tests: rule count, mechanism count, coverage %, handler registry validation. |

### Phase 2 — Product Hardening

| # | Workstream | Status | Notes |
|---|-----------|--------|-------|
| 4 | Eliminate Python 3.12 warnings | **Done** | Registered explicit datetime adapter/converter in `runner/storage.py`. 45 storage tests pass with `-W error::DeprecationWarning`. |
| 5 | Productize release/packaging | **Done** | 19 packaging smoke tests: CLI entry points, subcommands, data files, version consistency. |
| 6 | Tighten safety guarantees | **Done** | `docs/REMEDIATION_SAFETY.md` created with risk tiers, rollback safety, CLI options, recommendations. |
| 7 | Strengthen coverage semantics | **Done** | CoverageReport extended with automated/remediable/typed_remediable/rollback_safe. CLI and JSON output updated. |

### Phase 3 — GA Readiness

| # | Workstream | Status | Notes |
|---|-----------|--------|-------|
| 8 | Reduce manual/command_exec | **Substantial** | Typed migration PRs #151-#152 (63.6% → 79.4% typed). Inventory created in migration plan. |
| 9 | Formalize rule engineering | **Partial** | Rule validator now checks handler existence (warnings). CI catches unknown methods/mechanisms. |
| 10 | Expand platform strategy | Not started | RHEL-only. Strategic decision needed on next platform. |
| 11 | Upgrade customer-facing reporting | Not started | Strategic decision needed on report features. |

### Launch gates

| Gate | Description | Status |
|------|-------------|--------|
| A | Pilot-Ready | **Effectively reached** |
| B | Early Commercial Launch Ready | **Phase 1-2 complete** |
| C | Broad GA Ready | Phases 2-3 largely not started |

---

## Next priorities

### High value, ready to execute

1. **Typed Migration Phase 3 remainder** — Assess whether a PAM arg-manipulation sub-handler is worth building for the 19 remaining rules (medium effort, high coverage gain)
2. **Phase 5 crypto dynamic subpolicy** — 3 rules need a handler that reads current policy and appends subpolicy (small handler addition)
3. **Phase 6 file_content** — 2 rules, low effort if org-specific content is parameterized via variables

### Gap Closure Phase 3 — GA Readiness

4. **Reduce manual/command_exec** (Workstream 8) — Substantial progress via Typed Migration (63.6% → 79.4%); next gains from Phase 3/5/6 above
5. **Formalize rule engineering** (Workstream 9) — Rule validator checks handler existence. Extend with more structural checks.
6. **Platform expansion** (Workstream 10) — Strategic decision needed on next platform
7. **Customer-facing reporting** (Workstream 11) — Strategic decision needed on report features

### Deferred

8. **CIS RHEL 9 superseded rule cleanup** (CIS Plan Part B PR3) — optional, no user impact
9. **Framework Simplification Phase 5** — historical doc updates, no functional impact
