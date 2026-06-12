# Kensa Backlog

Items are ordered roughly by priority within each section. No commitment to scheduling until promoted to a milestone.

---

## Capability Detection

### Ubuntu/Debian probe support — COMPLETE (2026-04-15)

**Shipped:** 6 new Ubuntu probes (`dpkg`, `apt`, `apparmor`, `ufw`,
`apt_unattended_upgrades`, `ubuntu_advantage`) + `fips_mode` universal
fallback + distro-aware `package_installed`/`package_absent` (rpm-or-dpkg)
+ new `dpkg_installed`, `dpkg_absent`, `apparmor_state` check methods.

`apt_present` / `apt_absent` Go handlers + Python runner handlers added.
77 corpus rules patched with `when: apt` implementation blocks via
`scripts/add_ubuntu_pkg_impls.py`.  `rule.schema.json`, `REMEDIATION_HANDLERS`,
and `CAPABILITY_PROBES` all updated and committed.

Live result on `.217`: 13/31 caps detected (was 7/25).

**Remaining (lower priority):**
- ~~`pam_tally2` probe for older Ubuntu (pam_faillock may not be present).~~
  — **SHIPPED 2026-06-04** (v0.2.2). `internal/detect/detect.go` probes for
  the pam_tally2 CLI or module `.so`; added to `rule.KnownCapabilities`.
  Rules don't yet gate on it — that's part of the deferred service-name
  work below.
- **Service rules where the Ubuntu service name differs from RHEL** (e.g.
  `chronyd` → `chrony`). **DEFERRED out of v0.2.2** to a dedicated effort
  (2026-06-04). This is not a mechanical rename: the ~11–17 affected rules
  in `rules/services/` are `family: rhel`-only today, so the work is
  *extending* them to Debian/Ubuntu with the correct per-distro service
  name (via `when: apt` gates, the pattern already in
  `chrony-installed.yml`). It can't be CI-verified — `kensa-validate` is
  schema-only — so it needs real-host validation on the Ubuntu test-fleet
  box. A first-pass mapping survey also turned up at least one wrong entry
  (`kdump` → `crash`; the real Ubuntu unit is `kdump-tools`) and an
  uncertain one (`rngd` → `rng-tools`), so each rule needs its actual unit
  name verified rather than table-applied. Affected families: chrony,
  `crond`→`cron`, `httpd`→`apache2`, `named`→`bind9`,
  `nfs-server`→`nfs-kernel-server`, plus the two uncertain ones above.

---

## Handlers

All four mechanisms originally listed here have **shipped** (29 handlers
total now — see `CLAUDE.md` § "Shipped Handlers"):

- ~~`audit_rule_set` — implementation pending.~~ **SHIPPED** — capturable,
  `cli-best-effort` shell-out version. The `AUDIT_NETLINK` "Phase 5"
  variant (transaction-phase events via `elastic/go-libaudit`) remains the
  v1.0 quality bar; tracked in `docs/roadmap/DELIVERABLES.md`.
- ~~`grub_parameter_set` — non-capturable, needs a deadman guard.~~
  **SHIPPED** via #15 / #21 — bootguard-staged, Option-B one-shot trial +
  saved-default auto-fallback. RHEL 8 `$kernelopts` capture (S-009) is the
  remaining gated piece.
- ~~`command_exec` — generic escape hatch.~~ **SHIPPED** (non-capturable;
  `transactional: false` enforced by engine AC-07).
- ~~`manual` — marks a rule as requiring human intervention.~~ **SHIPPED**
  (non-capturable; engine records `StatusSkipped` with a note).

~~**Remaining:** `commandexec`, `manual`, `grubparameterset`,
`grubparameterremove`, and `cryptopolicysubpolicy` are shipped but
**untested**.~~ **RESOLVED** — all five carry spec-driven Apply +
interface-compliance tests (since PR #13; grub set/remove extended by
#15/#21) and pass the strict coverage gate at their tier. All 29 handler
packages have passing tests.

**Open (post-v0.3.0):**

- **Founder real-host atomicity validation for `pam_module_configure`
  (#54) and `mount_option_set` (#56)** — the F1 param-alignment PRs merged
  with unit/spec coverage but without per-handler live-host tests (the
  2026-06-10 live validation covered kmod/config_set/audit/sysctl/cron).
  Run the kensa-fuzz matrix on a dedicated host for these two before
  claiming them at the same confidence tier.
- **`RemediationResult` compliance-verdict surface** — `Remediate` still
  reports only transaction statuses; its already-compliant entries reuse
  `StatusCommitted` with a synthetic "check" step (the overload #62/#63
  removed from `Scan`). Flagged on the `RemediationResult` doc comment;
  needs an `Outcomes`-style additive surface in a future `api/` minor.

---

## CLI / UX

- `--inventory` flag for `check`, `detect`, `remediate` — parse Ansible-style `inventory.ini` and fan out across hosts.
- Machine-readable scan output suitable for OpenWatch ingestion (JSON Lines per host).

---

## OpenWatch integration follow-ups (v0.3.0)

- **OpenWatch should import `api.ComplianceStatus` directly** instead of
  declaring its own `ResultStatus` with matching string values — turns the
  pass/fail/skipped/error parity from convention into a compile-time
  guarantee (or at minimum add a drift test on the OpenWatch side when the
  live `Scan` binding replaces `unwiredScanFunc`).
- **Confirm the "skipped vs absent" not-applicable contract with
  OpenWatch.** Kensa's `ComplianceSkipped` fires for platform-gated and
  no-default rules; OpenWatch's kensa-executor spec expects rules whose
  capability gate didn't match to be *absent*. Both currently hold, but
  the boundary should be ratified before OpenWatch persists `skipped`
  rows into `host_rule_state`.

---

## Infrastructure

- `scripts/bench_aggregate.go` — aggregate benchmark across a rule corpus.
- FIPS-mode enforcement option for the SSH transport (reject connections when `fips_mode` is false on target).

---

## Dependabot PRs — RESOLVED 2026-06-10/11 (kept for the triage record)

All four PRs from the 2026-06-08 triage are closed. The per-PR rule stands
for future Dependabot PRs: review individually, do NOT blind-merge; they
are **not** covered by the auto-merge-on-green rule.

- **#31 — `actions/checkout` 5 → 6.** MERGED (as triaged: low risk, green).
- **#33 — gomod minor-and-patch group.** Closed by dependabot, recreated as
  **#58** (4 updates: godbus v5.2.2, x/sys v0.46, x/term v0.44, modernc
  sqlite v1.52) — MERGED after review; pure-Go SQLite preserved
  (portability CI green).
- **#28 — `actions/upload-artifact` 4 → 7.** MERGED after the CAUTION
  review (behavior + node runtime checked against `action.yml`).
- **#29 — `golangci-lint-action` 6 → 9.** CLOSED as triaged ("DO NOT MERGE
  as-is" was correct), then **superseded by #60**, which did the deliberate
  golangci-lint **v2.12.2** migration (config schema `version: "2"`,
  staticcheck SA*-parity then S*/ST*/QF* tiers via #61) together with the
  action v9 bump. The Lint job also gained `GOTOOLCHAIN: local` (#59) after
  the v1-era linter was found being auto-built with go1.25 — the root cause
  of a repo-wide SA5011 false-positive storm (poisoned action caches were
  purged).

Residual note: the Node-20 deprecation churn concern from the v0.2.2 A2
work (#35) did not materialize — #28/#31/#60 all landed green on node24
majors.

---

## Review follow-ups — v0.2.2 multi-agent review (2026-06-04)

Lower-severity items from the adversarial review of the v0.2.2 PRs. The
two MEDIUM findings (postinst `getent`→`/etc/group`; built-artifact
mode+owner CI assertion) were fixed directly; these are the LOW/NIT
residue, deferred by the founder.

- **LOW (security, defense-in-depth):** `cmd/kensa-systemd-helper/main.go`
  `euidCheck` honors `KENSA_HELPER_EUID_OVERRIDE` unconditionally (no
  build-tag guard; the code comment already flags the lock as deferred).
  Now that the package ships this binary as the *sanctioned* sudo
  escalation target, lock the override behind a `//go:build test` tag so
  the released helper ignores the env var entirely. Currently mitigated:
  the shipped sudoers fragment sets no `env_keep`/`setenv`, so sudo's
  default `env_reset` strips the var on the sanctioned path — residual
  risk is a future `env_keep` regression or a non-sudo root caller only.
- **NIT (docs):** `.github/workflows/ci.yml` secret-scan step comment
  says CI and pre-commit "agree byte-for-byte" — overstated. They share
  one exclude policy, but CI scans the full tracked tree each run while
  pre-commit scans staged files incrementally. Reword when next touching
  the file.

---

## Architecture review findings

These items came from a code review of whether Kensa's implementation
fully supports the atomic remediation, auditability, and evidence claims.

- **Post-apply rule validation** — `internal/engine/validate.go` does not
  re-run the selected rule check after remediation. A successful handler
  `Apply` can currently commit when no injected or built-in validator runs.
  Wire `api.Rule.Implementations[selected].Check` through the transaction
  path and make the VALIDATE phase independently confirm desired state.
- **Terminal persistence errors are ignored** — `internal/engine/commit.go`
  discards `e.store.PersistResult(...)` errors. Return or surface terminal
  store failures so callers cannot observe `committed`/`rolled_back` results
  that are missing from durable history.
- **Errored transactions are not durably recorded by SQLite** —
  `engine.errored()` builds a `TransactionResult` without an evidence
  envelope, while `store.SQLite.PersistResult` rejects nil envelopes. Add an
  errored-envelope path or relax the store contract so preflight/capture/store
  failures appear in history.
- **Remediation evidence host ID can be empty** — scanner-built remediation
  transactions do not populate `Transaction.HostID`, and the evidence
  envelope copies `HostID` from the transaction. Thread host identity into
  `internal/scan.Runner.Remediate` / transaction construction so every signed
  remediation envelope identifies the target host.
- **Control-channel risk classification is too coarse** — deadman arming uses
  a static mechanism-level map. Generic mechanisms such as `config_set`,
  `config_set_dropin`, `file_content`, and `sysctl_set` can affect SSH,
  networking, PAM, or firewall state depending on params/path. Add per-rule
  or per-handler risk metadata so risky parameterized changes arm the
  deadman reliably.
- **Post-state evidence is not captured** — committed evidence envelopes set
  `PostStateBundle` to nil. Add post-apply/post-rollback recapture where
  feasible so evidence can prove both pre-state and resulting state, not only
  the attempted apply steps.

---

## Rule corpus review findings

These items came from reviewing how the `rules/` corpus is validated,
selected, ordered, and applied. On 2026-06-05,
`kensa-validate --rules-dir rules --cap-check --strict` reported 539 files,
96 capability-reference errors, and 1 lint warning.

- **Unify capability vocabulary** — `internal/detect` and
  `internal/rule.KnownCapabilities` maintain separate capability sets.
  Detection includes `apt`, while strict validation rejects it. Derive
  validation and CLI override vocabularies from one canonical registry so
  the checked corpus and runtime selector cannot drift.
- **Implement or remove unprobed capability gates** — rules reference `gdm`,
  `nftables_active`, and `rsyslog_active`, but runtime detection does not
  produce those capabilities. Add probes with tests or replace the gates
  with existing capabilities. Until fixed, those implementations are
  unreachable without manual overrides.
- **Make capability fallbacks non-destructive** — several GDM configuration
  rules select package-removal defaults when the unprobed `gdm` gate is
  false. For example, `gdm-login-banner` can choose `apt_absent` or
  `package_absent` instead of configuring an installed GDM. A missing or
  unknown capability must skip/not-applicable rather than select a
  destructive fallback.
- **Re-detect capabilities across dependency boundaries** — remediation
  detects capabilities once before processing the ordered rule set.
  Dependencies can install packages or enable services that change later
  selection decisions. Re-evaluate affected capabilities after successful
  dependency remediation, or select each rule immediately before execution.
  `service-enable-firewalld` followed by `nftables-service-disabled` is a
  concrete failure case.
- **Use runtime handler metadata for atomicity validation** — the validator's
  static non-capturable mechanism list omits `crypto_policy_subpolicy`, even
  though the registered handler reports non-capturable. As a result,
  `crypto-policy-no-cbc-ssh`, `crypto-policy-strong-macs`, and
  `crypto-policy-no-sha1` validate but are rejected by engine preflight.
  Share handler capability metadata with validation and correct those rule
  declarations.
- **Enforce or resolve rule conflicts before remediation** —
  `conflicts_with` currently produces an advisory warning while both rules
  remain executable. Add a deterministic exclusion, policy choice, or hard
  remediation error for contradictory controls such as GDM configuration
  rules loaded alongside `gdm-removed`.
- ~~**Enforce platform applicability**~~ — **DONE 2026-06-11** (v0.3.0,
  PR #64). `detect.AppliesTo` gates both `check` and `remediate` on
  family/min/max-version (rhel/redhat aliased; EL derivatives honored)
  before capability selection; out-of-platform rules render `SKIP`
  (`ComplianceSkipped` on `ScanResult.Outcomes`) and never reach
  `engine.Run`. Lenient rails: no-`platforms` rules run everywhere;
  an undetectable host OS gates nothing. Spec `scan-compliance-outcome`
  C-07/AC-07/AC-08.
- **Reduce and test arbitrary command checks** — many findings rely on
  `method: command`, whose shell semantics cannot be validated by the rule
  schema. Prefer structured check methods where possible and add corpus
  tests or real-host fixtures for remaining command checks, including
  expected exit/output behavior and check/remediation convergence.
- **Resolve strict lint warning for SELinux policy** —
  `system/selinux-policy-targeted.yml` checks only
  `/etc/selinux/config`. Clarify that this is a next-boot configuration
  control or add an effective/runtime policy check so the finding does not
  overstate the host's current SELinux state.

---

## Spec coverage gaps (surfaced by Specter)

These are kensa implementation items required to remove `t.Skip` from existing spec tests.

- **deadman AC-07** — `Armer.Extend(ctx, transport, txnID)` keep-alive that re-schedules the job +60s every 30s during long-running applies. Failed keep-alive must abort the transaction.
- **deadman AC-10** — Clock skew detection in `Armer.Arm()`: compare host `date` before and after script upload; extend timer window if skew >30s.
- **engine AC-03** — Add `engine.WithFakeValidator(fn)` test hook so a failing post-apply validator can be injected; verifies `Status=RolledBack` on validator failure.
- **engine AC-04** — Crash-recovery integration test: kill the engine process after CAPTURE persistence but before APPLY; verify `kensa rollback` restores host state from the persisted pre-states.
- **engine AC-06** — Wire `engine.WithDeadman(recordingArmer)` and a `ControlChannelSensitive=true` FakeTransport into engine tests; verify `Arm` is called before apply and `Cancel` after commit.
- **store AC-07** — Implement `store.SQLite.Prune(preStateMaxAge, txnMaxAge)` and `RunRetention(interval)` background task.
- **store AC-09** — Add `store.SQLite.DB() *sql.DB` (or `InspectIndexes() []string`) accessor to allow schema index inspection in tests.
- **evidence-envelope AC-07** — Add `go:generate` that emits `internal/evidence/envelope-v1.json` from `api.EvidenceEnvelope` via a JSON Schema generator; add roundtrip validator test.
- **evidence-envelope AC-10** — CI step that compares `kensa-spec/specs/evidence/envelope-v1.yaml` against the Go struct to fail the build on mismatch.
