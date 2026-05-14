# Kensa-go Testing Documentation

**Purpose.** This directory is the founder-facing test inventory for kensa-go. Every meaningful surface — CLI subcommands, engine atomicity, SSH transport, rule corpus, output formats, security model, build discipline — has a dedicated document with current state, what's tested today, what's NOT tested, and the verification protocol a founder can run to sign off on a release.

This is not a how-to-use document — that's `docs/QUICKSTART.md` (Python kensa) and the per-subcommand `--help`. This is *how to verify the thing actually does what it claims*, file by file, gate by gate.

## Index

| Document | What it covers |
|---|---|
| [`cli/`](cli/) | Per-subcommand state: detect, check, remediate, plan, rollback, history, version, coverage. All Phase 1..3.5 flag wiring. |
| [`engine.md`](engine.md) | Capture→Apply→Validate→Commit/Rollback transaction contract. Per-handler capture-sufficiency status. Deadman timer. |
| [`transport.md`](transport.md) | SSH ControlMaster, sshpass routing, host-key policy, password handling, connection lifecycle. |
| [`rules.md`](rules.md) | Rule schema (V1), parser, validator, capability gating, framework mappings, variable substitution (Phase 3.5). |
| [`output.md`](output.md) | Output formats: table, json, jsonl, csv, pdf, evidence, oscal, markdown. Fan-out, file-per-spec semantics. |
| [`security.md`](security.md) | Known limits a founder must accept before shipping: signer absence, password handling, capability override risk, host-key default. |
| [`live.md`](live.md) | Live-host verification protocol. Inventory.ini fixture. Real-host atomicity tests (kensa-fuzz). |
| [`build.md`](build.md) | Static-binary discipline (CGO_ENABLED=0 + -tags netgo). Specter pipeline. CI gates. All five binaries (kensa, kensa-fuzz, kensa-validate, kensa-keygen, kensa-systemd-helper). |

**Historical references:**

| Document | What it covers |
|---|---|
| [`../roadmap/PHASE-4-CLOSE.md`](../roadmap/PHASE-4-CLOSE.md) | LL Phase 4 (systemd D-Bus) close write-up: deliverable history, Option C privilege model rationale, scope-correction story, sudoers fragment template. |
| [`../roadmap/BUG-FIX-LOG-2026-05-13.md`](../roadmap/BUG-FIX-LOG-2026-05-13.md) | Post-Phase-4 bug-fix sweep: B1 (agent bootstrap), B2 (rollback no-op), B4 (db parent dir), B6 (applied-vs-compliant), B7 (--version), plus three confirmed false positives. |

## How to use this

For each release candidate:

1. **Skim the index.** Each document has a "Current state" section at the top stating what's verified end-to-end vs. what's documented limitation.
2. **Run the gates.** Each document has a "Verification protocol" section with the exact commands. Most are no-network (unit tests, smoke, specter). Some require a reachable host (the `live.md` protocol).
3. **Sign off on known-limits.** Anything in `security.md` and the "NOT tested" sections of other documents is a deliberate exclusion. The founder's job is to confirm those exclusions are still acceptable.

## Test inventory at a glance (as of 2026-05-13)

| Layer | Count | Source |
|---|---|---|
| Go unit tests | 56 packages, all green | `go test ./...` |
| cli-smoke.sh scenarios | 225 | `make cli-smoke` |
| Specter strict-coverage | 86 specs, 86/86 PASS (tier thresholds: T1=100% / T2=80% / T3=50%) | `make spec-coverage-strict` |
| Live read-only (detect/check) | manual | `live.md` protocol |
| Live atomicity (kensa-fuzz) | manual | `engine.md` + real host with `KENSA_TEST_SSH_HOST` |
| Live agent-mode remediate + rollback | manual | `live.md` Stage 2.5 (added 2026-05-13 after B1/B2 bug fix) |

## Phase status (2026-05-13)

| Phase | Status |
|---|---|
| M1..M6 (engine + handlers) | DONE |
| M7 (production hardening, v1.0.0) | IN PROGRESS — Ed25519 signer shipped (M-012 + C-060, 2026-05-10); atomicity contract restored end-to-end after B1+B2 fix (2026-05-13). See `security.md` for remaining limits. |
| CLI Phase 1..5 (pflag through manpage) | DONE — all 56 deliverables shipped 2026-05-08..05-10 |
| LL Phase 0 (build discipline) | DONE (2026-05-08) |
| LL Phase 1 (multi-call agent binary) | DONE (2026-05-11) |
| LL Phase 2 (file atomicity primitives) | DONE (2026-05-11, corrected re-merge) |
| LL Phase 3 (deadman timer rebuild) | DONE (2026-05-12) |
| LL Phase 4 (systemd D-Bus migration) | **DONE 2026-05-13** — D-Bus primitive layer via `kensa-systemd-helper`; handler-port consumption deferred to v1.x backlog per Option 3 rescoping. See `docs/roadmap/PHASE-4-CLOSE.md`. |
| Bug-fix sweep post-Phase-4 | **DONE 2026-05-13** — 5 real fixes (B1, B2, B4, B6, B7) + 3 false positives confirmed (B3, B5, B8). See `docs/roadmap/BUG-FIX-LOG-2026-05-13.md`. |
| LL Phase 5 (AUDIT_NETLINK) | NOT STARTED (sketch only) |
| LL Phase 6 (direct kernel IO) | NOT STARTED (sketch only) |
| LL Phase 7 (SELinux + dconf) | NOT STARTED (sketch only) |

## Binaries shipped

The kensa-rpm packages five binaries as of 2026-05-13:
- `kensa` — main CLI (~36 MB statically linked)
- `kensa-fuzz` — failure-injection atomicity harness
- `kensa-validate` — rule schema validator
- `kensa-keygen` — Ed25519 keypair generator (M-012)
- `kensa-systemd-helper` — privileged systemd D-Bus helper (Phase 4 D-007)

All five accept `--version` / `-V` (B7 fix 2026-05-13; consistency across the suite).

## Founder-verification quick-list (release sign-off)

A pre-release verification run looks like:

```bash
# 1. Build clean, statically linked. All five binaries.
make build && for b in kensa kensa-fuzz kensa-validate kensa-keygen kensa-systemd-helper; do
  file ./bin/$b | grep -q "statically linked" && echo "$b: OK" || echo "$b: NOT STATIC"
done

# 2. All gates green.
go test ./...                          # currently 56/56 packages
make cli-smoke                          # currently 225/225
specter check --strict                  # currently 86/86 specs structurally clean
make spec-coverage-strict               # currently 86/86 passing at tier thresholds

# 3. Live host smoke (read-only). Replace HOST with a fixture.
KENSA_TEST_SSH_HOST=192.168.1.211 \
KENSA_TEST_SSH_USER=owadmin \
go test ./internal/transport/ssh/... -timeout 5m

# 4. Live agent-mode remediate + rollback round-trip. Added 2026-05-13
#    after the B1/B2 fix; this is the load-bearing atomicity validation
#    for the production code path. See live.md Stage 2.5.
#    Pick a low-blast-radius rule (file_permissions on a non-critical
#    file is ideal; var-log-messages-permissions is the documented
#    fixture).

# 5. Atomicity verification on a throwaway host.
KENSA_TEST_SSH_HOST=<throwaway> \
KENSA_TEST_SSH_USER=root \
go test ./cmd/kensa-fuzz/... -v -timeout 10m

# 6. Static-analysis gates (lint).
export PATH="$HOME/go/bin:$PATH"
golangci-lint run --config=.golangci.yml ./...
```

If all six pass and the known-limits in `security.md` are acceptable for the target deployment, the build is releasable.

**Note on the agent-mode rollback live test.** Pre-2026-05-13, the
agent-mode-with-sudo path was broken (bootstrap failed to land the
binary at a sudo-accessible location), AND manual rollback silently
no-op'd (the persisted apply-Steps weren't loaded back). Both bugs
surfaced only via live testing; unit tests passed. The post-fix
verification (Stage 4 above) exercises the full round-trip end-to-end
on a real host and is the only gate that confirms the documented
atomicity contract holds in production code paths.
