# CLAUDE.md — Kensa Go

Orientation for AI agents working in this repo. Read this before touching any code.

---

## What This Repo Is

**Kensa Go** is the production Go implementation of Hanalyx's Kensa compliance and
atomicity engine. Every Linux configuration change runs as a four-phase transaction:
**Capture → Apply → Validate → Commit/Rollback**. That atomicity contract is the
product. The compliance rules are the first application of it.

Sister repos:
- `/home/rracine/hanalyx/kensa` — Python reference implementation (corpus of 539 rules, shared)
- `/home/rracine/hanalyx/openwatch` — fleet control plane; imports `kensa-go/api`

Module: `github.com/Hanalyx/kensa-go`

---

## Authorship Model

**AI writes the code. The founder reviews and tests every change.**

This is not optional. Every PR that touches `internal/engine/`, any handler's
`capture.go`, or any handler's `rollback.go` requires a human-authored failure-mode
analysis in the commit body answering:

1. What could this change do wrong in production?
2. Is the captured state sufficient to fully restore the system on rollback?
3. What edge case is this change *not* safe for, and is it documented and gated?

Rollback handlers additionally require two-human review and a real-host atomicity
test via `cmd/kensa-fuzz`. See `CONTRIBUTING.md` for the full discipline.

---

## Milestone Status (as of 2026-04-21)

| Milestone | Scope | Status |
|---|---|---|
| M1 | Engine, SSH transport, SQLite store, full `api/` surface | **COMPLETE** |
| M2 | `file_permissions` handler end-to-end with atomicity | **COMPLETE** |
| M3 | 10 core capturable handlers | **COMPLETE** |
| M4 | Control-channel handlers + deadman timer | **COMPLETE** (deadman timer shipped) |
| M5 | Rule parser, CLI, `Plan`/`Execute`, event stream | **COMPLETE** |
| M6 | Handler parity with Python Kensa, OpenWatch API wired | **COMPLETE** |
| M7 | Production hardening, v1.0.0 | **IN PROGRESS** |

Open items before M7 ships:
- Ed25519 signer (task #12) — `noopSigner` still in `internal/engine/stubs.go`
- `audit_rule_set` handler — stub only, no implementation
- `grub_parameter_set` — needs deadman guard before it's safe
- 10 handlers have no tests: `authselectfeatureenable`, `commandexec`, `configappend`,
  `cryptopolicyset`, `cryptopolicysubpolicy`, `dconfset`, `grubparameterremove`,
  `grubparameterset`, `manual`, `pammodulearg` — these need first-principles
  integration tests. Python kensa is an internal-only prototype with no production
  users and is being phased out, so the previously-planned parity sweep against
  Python output is retired as a v1.0 ship blocker.
- `internal/rules/paths.go` — default path resolution (`/usr/share/kensa/rules`)
  not yet implemented; `--rules-dir` is required at runtime

---

## Repository Layout

```
api/                    PUBLIC contract — frozen v1 semver; OpenWatch imports this
pkg/kensa/              Assembly layer — Default() factory
internal/
  engine/               Transaction coordinator (Capture→Apply→Validate→Commit/Rollback)
  handler/              Global handler registry (singular — infrastructure only)
  handlers/<mechanism>/ One package per mechanism: Apply, Capture, Rollback, register, tests
  check/                Check method implementations (package_state, file_exists, etc.)
  detect/               Capability probe runner (ssh, apt, selinux, apparmor, etc.)
  deadman/              Deadman timer subsystem
  evidence/             Evidence envelope + signing
  mappings/             Framework mapping loader (CIS, NIST 800-53, STIG)
  rule/                 Rule YAML parser, validator, capability selector
  scan/                 Multi-rule scan orchestration
  store/                SQLite transaction log
  transport/ssh/        SSH transport with ControlMaster
cmd/
  kensa/                CLI binary (detect, check, remediate, rollback, history, plan)
  kensa-fuzz/           Failure injection harness for atomicity verification
  kensa-validate/       Rule + spec validator
specs/                  Specter .spec.yaml files (22 specs, all Tier 1 at 100% coverage)
scripts/
  add_ubuntu_pkg_impls.py   Patches corpus rules with when:apt implementations
  bench_aggregate.go        Benchmark aggregation across rule corpus
  parity_check.go           Go vs Python Kensa output comparison
```

---

## Build, Test, Lint

```bash
# Test
go test ./...

# Lint (requires golangci-lint in PATH)
export PATH="$HOME/go/bin:$PATH"
golangci-lint run --config=.golangci.yml ./...

# Specter spec pipeline (requires specter in PATH)
export PATH="/home/rracine/.specter/bin:$PATH"
specter doctor          # pre-flight health check
specter sync            # full pipeline: parse + resolve + check + coverage
specter check --strict  # type-check, warnings as errors

# Real-host SSH integration tests (skipped without env var)
KENSA_TEST_SSH_HOST=<host> KENSA_TEST_SSH_USER=root \
  go test ./internal/transport/ssh/...

# Fuzz/atomicity harness against real host
KENSA_TEST_SSH_HOST=<host> KENSA_TEST_SSH_USER=root \
  go test ./cmd/kensa-fuzz/... -v -timeout 10m
```

Current state: `go test ./...` — all green. `specter sync` — 22/22 specs, 100% Tier 1.

---

## Handler Anatomy

Every handler lives in `internal/handlers/<mechanism>/` and has:

| File | Purpose |
|---|---|
| `<mechanism>.go` | `Apply`, `Capture`, `Rollback`, `Name`, `Capturable` |
| `register.go` | `init()` calls `handler.Default().Register(New())` |
| `<mechanism>_test.go` | Tests for Apply, Capture, Rollback, no-op paths, interface compliance |

The registry (`internal/handler/registry.go`) is separate from the implementations.
The engine imports `internal/handler` only; individual handler packages are pulled in
via blank imports in `cmd/kensa/main.go`.

**Capturable handlers** record `PreState` in SQLite before Apply. Rollback reads that
`PreState` to undo the change. **Non-capturable handlers** (`transactional: false` in
rule YAML) have no Capture/Rollback — the engine marks them `StatusSkipped` for
rollback.

**Capture completeness is the reviewer's responsibility.** Capture must record every
piece of state that Apply touches. If Apply touches state that Capture doesn't record,
rollback will be incomplete. The `CONTRIBUTING.md` capture-sufficiency checklist
enforces this at review time.

---

## Shipped Handlers (29 total)

**Capturable (full Apply/Capture/Rollback) — by atomicity basis:**

| Atomicity basis | Available under | Handlers |
|---|---|---|
| `kernel-atomic` | agent mode only (`KENSA_USE_AGENT=1`); direct-SSH falls back to shell-best-effort | `filecontent`, `fileabsent`, `configset`, `configsetdropin` |
| `kernel-atomic` (always) | both transports | `filepermissions` |
| `daemon-atomic` (systemd) | both transports | `servicedisabled`, `serviceenabled`, `servicemasked` |
| `kernel-runtime + file-persistence` | both transports | `sysctlset`, `mountoptionset`, `selinuxbooleanset`, `kernelmoduledisable` |
| `cli-best-effort` | both transports | `aptabsent`, `aptpresent`, `auditruleset`, `cronjob`, `packageabsent`, `packagepresent`, `pammoduleconfigure` |

The kernel-atomic file-mechanism handlers landed via the
`fix/phase-2-rework` drop (originally Phase 2 P-001..P-005, reworked
after a multi-agent review surfaced three P0 security findings in the
first cut). See `internal/agent/fsatomic/` for the primitives and
`docs/TRANSACTION_CONTRACT_V1.md §2.6` for the external commitment.

**Non-capturable stubs** (`transactional: false`):
`authselectfeatureenable`, `commandexec`, `configappend`, `cryptopolicyset`,
`cryptopolicysubpolicy`, `dconfset`, `grubparameterremove`, `grubparameterset`,
`manual`, `pammodulearg`

---

## Rules and Corpus

Rules live in the sister repo at `/home/rracine/hanalyx/kensa/rules/` (539 YAML files).
They are **not bundled** in this binary. At runtime the CLI requires `--rules-dir`:

```bash
kensa check --rules-dir /home/rracine/hanalyx/kensa/rules <host>
```

`internal/rules/paths.go` with a default `/usr/share/kensa/rules` fallback is not yet
implemented — `--rules-dir` is currently mandatory.

Packaging plan: `kensa` binary RPM and `kensa-rules` noarch RPM ship separately so
rules can update without a binary release. The tarball bundles both for air-gapped
installs.

---

## Capability Probes

`internal/detect/detect.go` holds all probes. The `when:` field in rule YAML gates
which implementation runs based on detected capabilities.

Key Ubuntu/Debian probes added: `dpkg`, `apt`, `apparmor`, `ufw`,
`apt_unattended_upgrades`, `ubuntu_advantage`.

---

## Specter

Specter version: **0.10.2** (at `/home/rracine/.specter/bin/specter`).
CI pins `SPECTER_VERSION: v0.10.2` in `.github/workflows/ci.yml` and fetches the
GoReleaser tarball, falling back to `go install` if the release URL is unreachable.

Commands worth using:
- `specter diff` — semantic spec diff between git revisions (useful in PR review)
- `specter reverse` — drafts `.spec.yaml` from existing source (useful for the 10
  untested handlers)
- `specter ingest` — converts `go test -json` or JUnit XML into `.specter-results.json`.
  Run `make spec-ingest` to populate it locally. CI runs this after `specter sync`.
- `specter coverage --strict` — gates coverage on actual test outcome (not just
  annotation existence). **Not yet enabled** in CI or Makefile: every `@spec`/`@ac`
  in kensa-go today is a source comment, and `specter ingest` only sees runner-visible
  surfaces (subtest names or `t.Log` output). Turning `--strict` on today would demote
  every annotated AC. Migrate tests to Convention A (`t.Run("spec-id/AC-NN ...", ...)`)
  or Convention B (`t.Log("// @spec ...")` + `t.Log("// @ac ...")`) first. Stage the
  rollout with `specter coverage --strict --scope <domain>`, starting with `core`.

---

## Key Design Decisions

- **`api/` is the public contract.** Never move types out of `api/` without a semver
  bump. OpenWatch depends on it.
- **OpenWatch is to Kensa as GitHub is to git.** OpenWatch presents and orchestrates;
  it never re-implements what Kensa does for a single host.
- **System OpenSSH, not a Go SSH library.** The transport uses `ssh` + ControlMaster
  subprocess. This is intentional — system SSH handles key agents, jump hosts, and
  known_hosts correctly.
- **`noopSigner` is a placeholder.** The Ed25519 signer has not been implemented.
  Evidence envelopes are produced but signatures are empty until task #12 lands.
- **Rules are runtime input, not compiled-in.** The binary has no embedded corpus.

---

## Related Documents

All in `docs/`:
- `KENSA_VISION.md` — mission and category framing
- `TRANSACTION_CONTRACT_V1.md` — the customer-facing atomicity commitment
- `TECHNICAL_REMEDIATION_MP_V1.md` — seven principles, three-layer architecture
- `CANONICAL_RULE_SCHEMA_V1.md` — rule YAML contract
- `KENSA_GO_DAY1_PLAN.md` — architectural contract and 40-week build sequence
- `HANALYX_MISSION_AND_ROADMAP.md` — seven trust moats and human-review commitment
- `NEW_SESSION_LOG.md` — handoff prompt for fresh AI sessions
