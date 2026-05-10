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
| [`build.md`](build.md) | Static-binary discipline (CGO_ENABLED=0 + -tags netgo). Specter pipeline. CI gates. |

## How to use this

For each release candidate:

1. **Skim the index.** Each document has a "Current state" section at the top stating what's verified end-to-end vs. what's documented limitation.
2. **Run the gates.** Each document has a "Verification protocol" section with the exact commands. Most are no-network (unit tests, smoke, specter). Some require a reachable host (the `live.md` protocol).
3. **Sign off on known-limits.** Anything in `security.md` and the "NOT tested" sections of other documents is a deliberate exclusion. The founder's job is to confirm those exclusions are still acceptable.

## Test inventory at a glance (as of 2026-05-09)

| Layer | Count | Source |
|---|---|---|
| Go unit tests | ~340+ | `go test ./...` |
| cli-smoke.sh scenarios | 99 | `make cli-smoke` |
| Specter Tier-1 specs | 48 | `specter check --strict` |
| Live read-only (detect/check) | manual | `live.md` protocol |
| Live atomicity (kensa-fuzz) | manual | `engine.md` + real host with `KENSA_TEST_SSH_HOST` |

## Phase status (2026-05-09)

| Phase | Status |
|---|---|
| M1..M6 (engine + handlers) | DONE |
| M7 (production hardening, v1.0.0) | IN PROGRESS — Ed25519 signer landed (M-012 + C-060, 2026-05-10); see `security.md` for remaining limits |
| CLI Phase 1 (pflag + GNU/POSIX exit codes) | DONE |
| CLI Phase 2 (--output FORMAT[:PATH]) | DONE |
| CLI Phase 2.5 (operator UX refresh) | DONE |
| CLI Phase 3 (target_options + rule_options parity) | DONE (13/13; 2 deferred to 3.5) |
| CLI Phase 3.5 (variable substitution: --var, --config-dir) | DONE |
| CLI Phase 3.6 (variable per-host/per-group/conf.d tiers) | DONE (single-host full 5-tier; inventory 3-tier with warning) |
| CLI Phase 3.7 (per-host vars active in inventory mode) | DONE — full 5-tier in both single-host and inventory modes |
| Embedded defaults + --config-dir auto-detect | DONE — fresh `kensa check` resolves all ~30 corpus templates out of the box |
| CLI Phase 4 (session model + missing subcommands) | NOT STARTED |
| CLI Phase 5 (kensa-go-specific surfaces, manpage) | NOT STARTED |

## Founder-verification quick-list (release sign-off)

A pre-release verification run looks like:

```bash
# 1. Build clean, statically linked.
make build && file ./bin/kensa | grep -q "statically linked" && echo OK

# 2. All gates green.
go test ./...
make cli-smoke                  # currently 99/99
specter check --strict          # currently 48/48 specs

# 3. Live host smoke (read-only). Replace HOST with a fixture.
KENSA_TEST_SSH_HOST=192.168.1.211 \
KENSA_TEST_SSH_USER=owadmin \
go test ./internal/transport/ssh/... -timeout 5m

# 4. Atomicity verification on a throwaway host.
KENSA_TEST_SSH_HOST=<throwaway> \
KENSA_TEST_SSH_USER=root \
go test ./cmd/kensa-fuzz/... -v -timeout 10m

# 5. Static-analysis gates (lint).
export PATH="$HOME/go/bin:$PATH"
golangci-lint run --config=.golangci.yml ./...
```

If all five pass and the known-limits in `security.md` are acceptable for the target deployment, the build is releasable.
