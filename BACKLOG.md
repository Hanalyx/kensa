# Kensa-go Backlog

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
- `pam_tally2` probe for older Ubuntu (pam_faillock may not be present).
- Service rules where Ubuntu service name differs from RHEL (e.g. `chronyd` → `chrony`).

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

## Spec coverage gaps (surfaced by Specter)

These are kensa-go implementation items required to remove `t.Skip` from existing spec tests.

- **deadman AC-07** — `Armer.Extend(ctx, transport, txnID)` keep-alive that re-schedules the job +60s every 30s during long-running applies. Failed keep-alive must abort the transaction.
- **deadman AC-10** — Clock skew detection in `Armer.Arm()`: compare host `date` before and after script upload; extend timer window if skew >30s.
- **engine AC-03** — Add `engine.WithFakeValidator(fn)` test hook so a failing post-apply validator can be injected; verifies `Status=RolledBack` on validator failure.
- **engine AC-04** — Crash-recovery integration test: kill the engine process after CAPTURE persistence but before APPLY; verify `kensa rollback` restores host state from the persisted pre-states.
- **engine AC-06** — Wire `engine.WithDeadman(recordingArmer)` and a `ControlChannelSensitive=true` FakeTransport into engine tests; verify `Arm` is called before apply and `Cancel` after commit.
- **store AC-07** — Implement `store.SQLite.Prune(preStateMaxAge, txnMaxAge)` and `RunRetention(interval)` background task.
- **store AC-09** — Add `store.SQLite.DB() *sql.DB` (or `InspectIndexes() []string`) accessor to allow schema index inspection in tests.
- **evidence-envelope AC-07** — Add `go:generate` that emits `internal/evidence/envelope-v1.json` from `api.EvidenceEnvelope` via a JSON Schema generator; add roundtrip validator test.
- **evidence-envelope AC-10** — CI step that compares `kensa-spec/specs/evidence/envelope-v1.yaml` against the Go struct to fail the build on mismatch.
