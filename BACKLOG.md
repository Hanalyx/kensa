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

- `audit_rule_set` — handler stub exists; implementation pending (Week 6 partial).
- `grub_parameter_set` — non-capturable; requires deadman-guarded write to `/etc/default/grub` + `grub2-mkconfig`.
- `command_exec` — generic escape hatch for one-off remediation commands not covered by a structured handler.
- `manual` — mechanism that marks a rule as requiring human intervention; engine records it as `StatusSkipped` with a note.

---

## CLI / UX

- `--inventory` flag for `check`, `detect`, `remediate` — parse Ansible-style `inventory.ini` and fan out across hosts.
- Machine-readable scan output suitable for OpenWatch ingestion (JSON Lines per host).

---

## Infrastructure

- `scripts/bench_aggregate.go` — aggregate benchmark across a rule corpus.
- FIPS-mode enforcement option for the SSH transport (reject connections when `fips_mode` is false on target).

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
