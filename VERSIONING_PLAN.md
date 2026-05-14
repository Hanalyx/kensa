# Kensa Versioning Plan

**Document Version**: v0.0.1
**Created**: 2026-05-13
**Status**: Active

---

## Overview

Kensa uses **Semantic Versioning 2.0.0** (SemVer) with a single source of
truth (`VERSION` file) and codenames for major releases. The `api/` package
is held to a stricter contract — it is the public Go API consumed by
OpenWatch and is frozen under v1 semver discipline independent of the
binary version (see [API Versioning](#api-versioning)).

---

## Version Format

### Standard Format

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

**Examples**:

- `0.1.0` — Initial development release
- `0.2.0` — New features added
- `0.2.1` — Bug fix
- `1.0.0-alpha.1` — First alpha of production release
- `1.0.0-beta.2` — Second beta
- `1.0.0-rc.1` — Release candidate
- `1.0.0` — Production release

### Version Components

| Component      | Description            | When to Increment                                                                                  |
| -------------- | ---------------------- | -------------------------------------------------------------------------------------------------- |
| **MAJOR**      | Breaking changes       | `api/` signature change, atomicity-contract change, rule-schema break, CLI flag removal            |
| **MINOR**      | New features           | New handler, new CLI subcommand, new output format, new capability probe (backward-compatible)     |
| **PATCH**      | Bug fixes              | Backward-compatible bug fixes, security patches, doc-only corrections                              |
| **PRERELEASE** | Pre-release identifier | `alpha.N`, `beta.N`, `rc.N` for testing phases                                                     |
| **BUILD**      | Build metadata         | Optional: build date, commit SHA, CI build number (injected via `-ldflags`)                        |

**Atomicity-contract changes are always MAJOR.** A change to the
`Capture → Apply → Validate → Commit/Rollback` semantics — including a
change to which handler is `Capturable: true`, a change to what `PreState`
records, or a change to evidence-envelope shape — is a breaking change
even if no Go signature moves.

---

## Current Version

| Property         | Value             |
| ---------------- | ----------------- |
| **Version**      | `0.1.0`           |
| **Codename**     | Sentinel          |
| **Status**       | Development       |
| **Release Date** | 2026-05-13        |

---

## Codenames

Major releases (X.0.0) receive codenames for marketing and easy reference.
The theme is **guardianship / protective infrastructure**, reflecting
Kensa's role as the compliance and atomicity guardian of a Linux fleet.

| Version | Codename     | Theme                                | Status        |
| ------- | ------------ | ------------------------------------ | ------------- |
| 0.x.x   | **Sentinel** | The watchful guardian — dev cycle    | Current       |
| 1.0.0   | TBD          | -                                    | Planned       |
| 2.0.0   | TBD          | -                                    | Future        |

**Codename Guidelines**:

- Names should evoke protection, watchfulness, or durable defensive
  infrastructure (matching the product purpose)
- Single word, easy to pronounce
- No trademark conflicts in the security / compliance / infrastructure space
- Alphabetical progression encouraged (but not required)

**Suggested Future Codenames** (guardianship theme):

- Aegis, Anchor, Bastion, Beacon, Bulwark, Citadel, Fortress, Ironclad,
  Keep, Rampart, Stronghold, Tower, Vanguard, Vault, Watchtower

---

## Single Source of Truth

### VERSION File

The canonical version is stored in `/VERSION` at the repository root.

**Format**:

```
0.1.0
```

The file contains the version string followed by a single trailing
newline (POSIX text-file convention). Shell command substitution
(`$(cat VERSION)`) strips the trailing newline, so the `-ldflags`
injection and `git tag -a "v$(cat VERSION)"` produce a clean version
token without further processing.

### Version Propagation

All other version references are derived from the `VERSION` file at build
time. Kensa ships **five binaries** (`kensa`, `kensa-fuzz`,
`kensa-validate`, `kensa-keygen`, `kensa-systemd-helper`) and all five
report the same version string from `--version` / `-V`:

| Location                                  | How Updated                                                                |
| ----------------------------------------- | -------------------------------------------------------------------------- |
| `VERSION`                                 | Manual edit (source of truth)                                              |
| `cmd/kensa/main.go` (`version` var)       | `-ldflags "-X main.version=$(cat VERSION)"` injection at `go build`        |
| `cmd/kensa-fuzz/main.go` (`version` var)  | same                                                                       |
| `cmd/kensa-validate/main.go`              | same                                                                       |
| `cmd/kensa-keygen/main.go`                | same                                                                       |
| `cmd/kensa-systemd-helper/main.go`        | same                                                                       |
| Git tags                                  | Created from VERSION content (`v$(cat VERSION)`)                           |
| RPM `kensa-$(cat VERSION)-N.fcXX.rpm`     | RPM spec reads VERSION                                                     |
| Tarball `kensa-$(cat VERSION).tar.gz`     | Make target reads VERSION                                                  |
| `kensa --version` output                  | Injected at build; falls back to `dev` if `-ldflags` not used (local dev)  |
| Evidence envelope `KensaVersion` field    | Injected at build; reads same `main.version` symbol                        |

### Reading Version in Code

**Go** (per-binary `cmd/*/main.go`):

```go
// version is set by -ldflags "-X main.version=$(cat VERSION)".
// Default "dev" lets `go run ./cmd/kensa` work for local development
// without invoking make.
var version = "dev"

func printVersion() { fmt.Printf("kensa %s\n", version) }
```

**Shell / Makefile**:

```bash
VERSION := $(shell cat VERSION)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
    CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa ./cmd/kensa
    CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa-fuzz ./cmd/kensa-fuzz
    CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa-validate ./cmd/kensa-validate
    CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa-keygen ./cmd/kensa-keygen
    CGO_ENABLED=0 go build -tags netgo $(LDFLAGS) -o bin/kensa-systemd-helper ./cmd/kensa-systemd-helper
```

---

## Pre-release Versions

### Alpha (`-alpha.N`)

- **Purpose**: Internal testing, feature incomplete
- **Stability**: Unstable, frequent breaking changes
- **Audience**: Hanalyx engineers + sister-repo (OpenWatch) integrators only
- **Example**: `0.2.0-alpha.1`, `0.2.0-alpha.2`

### Beta (`-beta.N`)

- **Purpose**: External testing on throwaway fleets, feature complete
- **Stability**: Atomicity contract holds; cosmetic bugs expected
- **Audience**: Design partners with explicit Hanalyx engagement
- **Example**: `0.2.0-beta.1`, `0.2.0-beta.2`

### Release Candidate (`-rc.N`)

- **Purpose**: Final testing before release
- **Stability**: Production-ready candidate; atomicity contract verified
  end-to-end on real hosts via `kensa-fuzz`
- **Audience**: All users willing to test
- **Example**: `0.2.0-rc.1`, `0.2.0-rc.2`

### Pre-release Progression

```
0.1.0 (current stable)
  |
  v
0.2.0-alpha.1 --> 0.2.0-alpha.2 --> 0.2.0-alpha.N
  |
  v
0.2.0-beta.1 --> 0.2.0-beta.2 --> 0.2.0-beta.N
  |
  v
0.2.0-rc.1 --> 0.2.0-rc.2
  |
  v
0.2.0 (new stable)
```

---

## Version Lifecycle

### Development Phase (0.x.x) — Sentinel

Current phase. Indicates:

- Active development; M7 (production hardening) in progress
- `api/` is frozen at v1 semver for OpenWatch consumption (see [API
  Versioning](#api-versioning) below); the rest of the surface may
  evolve
- Rule schema, CLI flags, and output formats may change between MINOR
  versions with deprecation warnings
- Not yet recommended for unsupervised production fleets; design-partner
  deployments only

**Rules during 0.x.x**:

- MINOR bump for new handlers, new CLI subcommands, new output formats,
  new capability probes
- PATCH for bug fixes only
- Breaking changes to non-`api/` surface allowed in MINOR bumps **with
  CHANGELOG entry and one-version deprecation warning**
- Breaking changes to `api/` require a major bump (`1.0.0` or later); the
  `api/` contract is the load-bearing commitment to OpenWatch
- No long-term support commitment for 0.x lines

### Production Phase (1.x.x+)

Indicates production-ready software:

- Stable `api/`, rule schema, evidence envelope, CLI flag surface
- Atomicity contract verified end-to-end and published in the operator
  guide
- Breaking changes only in MAJOR versions
- Security patches backported to previous MINOR for at least 12 months
- Clear deprecation policy with minimum 2-MINOR-version notice

**Rules for 1.x.x+**:

- MAJOR: Breaking changes (with migration guide + spec diff)
- MINOR: New features (backward compatible)
- PATCH: Bug fixes and security patches
- Deprecation warnings before removal

---

## Release Process

### Tagging

Kensa releases are git tags of the form `v$(cat VERSION)`:

```bash
# Bump VERSION
printf '0.2.0' > VERSION

# Update CHANGELOG.md with the new version's notes
$EDITOR CHANGELOG.md

# Commit + tag
git add VERSION CHANGELOG.md
git commit -m "chore(release): v0.2.0"
git tag -a "v0.2.0" -m "Release v0.2.0 — Sentinel"
git push origin main --tags
```

The push triggers the GoReleaser workflow which builds all five binaries
statically (CGO_ENABLED=0, `-tags netgo`), assembles the kensa-rpm and
kensa-rules packages, attaches them to a GitHub Release, and publishes
checksums + Ed25519 signatures (M-012).

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types that imply releases:**

| Type        | Release | Example                                                            |
| ----------- | ------- | ------------------------------------------------------------------ |
| `feat`      | MINOR   | `feat(handler/auditruleset): add capture + rollback`               |
| `fix`       | PATCH   | `fix(engine): persist apply Steps so rollback can find them`       |
| `perf`      | PATCH   | `perf(scan): parallelize rule evaluation`                          |
| `feat!:`    | MAJOR   | `feat(api)!: rename ScanResult.Hosts → ScanResult.Results`         |

**Types that DO NOT trigger releases:**

- `docs`, `style`, `chore`, `refactor`, `test`, `build`, `ci`

**Breaking changes** (always MAJOR, regardless of type):

```
feat(api)!: drop deprecated TransactionResult.Detail field

BREAKING CHANGE: api.TransactionResult.Detail removed in v1.0.0.
Callers must read per-step detail from TransactionResult.Steps[i].Detail.
```

Atomicity-contract-affecting changes (engine, capture, rollback, or any
handler's `Capturable: true` claim) require human-authored failure-mode
analysis in the commit body per `CONTRIBUTING.md`. The commit type
alone does not determine the version bump — a `fix:` commit that
narrows the atomicity contract is still a MAJOR bump.

### Hotfix Process

For critical fixes to released versions:

```bash
# Create hotfix branch from tag
git checkout -b hotfix/0.1.1 v0.1.0

# Make fix; bump patch version
printf '0.1.1' > VERSION

# Commit + tag
git add VERSION
git commit -am "fix(engine): critical atomicity bug — pre-state not loaded for capturable handlers"
git tag -a "v0.1.1" -m "Hotfix v0.1.1"

# Merge back to main, push tags
git checkout main
git merge hotfix/0.1.1
git push origin main --tags
```

---

## API Versioning

The Go package `api/` (`github.com/Hanalyx/kensa/api`) is the public
contract consumed by **OpenWatch** and any future fleet-orchestration
layer. It is held to a stricter discipline than the binary version:

| Property                              | Rule                                                                   |
| ------------------------------------- | ---------------------------------------------------------------------- |
| Module path                           | `github.com/Hanalyx/kensa/api`                                         |
| Stability commitment                  | Frozen at v1 semver from kensa 0.1.0 onward                            |
| Breaking change → kensa version bump  | Always MAJOR (kensa 1.0.0+ for any `api/` removal or signature change) |
| Additive change                       | MINOR — new fields with zero-value-safe defaults, new types, new methods |
| Internal packages (`internal/*`)      | No stability commitment; refactor freely                               |

OpenWatch pins to a kensa minor line and follows the kensa CHANGELOG for
deprecation notices. A kensa MAJOR bump signals that OpenWatch needs an
explicit migration before consuming the new version.

The CLI flag surface is **separately versioned** from `api/`. CLI
breakages are also MAJOR but the `api/` package is the load-bearing
external contract.

### Evidence Envelope

The signed evidence envelope (`api.EvidenceEnvelope`) has its own
schema-version field (`SchemaVersion`) which is independent of the
kensa version. Today the envelope schema is `1`. A schema bump is a
kensa MAJOR.

### Rule Schema

The canonical rule YAML schema is at `V1` (see `docs/guide/06-rule-authoring.md`
and the `kensa-validate` binary). A rule-schema break is a kensa MAJOR.

---

## Version Display

### CLI

All five binaries support `--version` and `-V`:

```
$ kensa --version
kensa 0.1.0

$ kensa-fuzz --version
kensa-fuzz 0.1.0

$ kensa-validate --version
kensa-validate 0.1.0

$ kensa-keygen --version
kensa-keygen 0.1.0

$ kensa-systemd-helper --version
kensa-systemd-helper 0.1.0
```

Verbose form (with build metadata when injected):

```
$ kensa --version --verbose
kensa 0.1.0
  build:   2026-05-13T14:22:01Z
  commit:  402eded4
  go:      go1.26.1 linux/amd64
  tags:    netgo
```

### Evidence Envelope

Every signed evidence envelope records `KensaVersion` so audit trails
identify which binary produced the result:

```json
{
  "SchemaVersion": 1,
  "KensaVersion": "0.1.0",
  ...
}
```

### `kensa info`

The `kensa info` subcommand prints the runtime version, build flags,
configured signing key fingerprint, and rule-corpus path. Operators
include `kensa info` output in support bundles.

---

## Compatibility Matrix

| Kensa Version | Go Toolchain | Target Linux                         | Build Constraints                  | OpenWatch Compat        |
| ------------- | ------------ | ------------------------------------ | ---------------------------------- | ----------------------- |
| 0.1.x         | Go 1.26.1+   | RHEL 8/9/10, Ubuntu 22.04/24.04, Alpine 3+ | `CGO_ENABLED=0`, `-tags netgo` | Any 0.x line (api/ v1)  |
| 1.0.x         | TBD          | TBD                                  | `CGO_ENABLED=0`, `-tags netgo`     | api/ v1 (frozen)        |

Static linkage discipline (no glibc floor, runs on musl) is enforced by
the `build-static-verify`, `build-portability-glibc228`, and
`build-portability-alpine` CI jobs and is part of the version
commitment, not negotiable per-release.

---

## Breaking Change Policy

### What Constitutes a Breaking Change

- **Atomicity contract**: change to capture sufficiency, rollback
  semantics, or what state a `Capturable: true` handler records
- **`api/` package**: any signature change, type removal, or behavior
  change visible to OpenWatch
- **Rule schema**: any new required field, removed field, or changed
  field semantics in CANONICAL_RULE_SCHEMA
- **Evidence envelope**: any change to signed fields or signature
  algorithm
- **CLI flag removal**: removing a flag, changing a flag's type, or
  changing a subcommand's exit-code semantics
- **Default behavior**: changing what happens with no flags set (e.g.,
  default rules directory, default output format)
- **Wire protocol**: protobuf message changes that break the agent
  handshake

### Deprecation Process

1. **Announce**: CHANGELOG entry + stderr warning when deprecated path used
2. **Warn**: One full MINOR cycle of stderr warnings
3. **Duration**: Minimum 2 MINOR versions before removal
4. **Remove**: Only in next MAJOR version

Example deprecation timeline:

```
v0.3.0 — `--format` deprecated in favor of `--output` (warning added)
v0.4.0 — `--format` still works (warning continues)
v0.5.0 — `--format` still works (warning continues, last MINOR with it)
v1.0.0 — `--format` removed
```

Operators can suppress deprecation warnings with
`KENSA_NO_DEPRECATION_WARNINGS=1`.

---

## Planned Releases

| Version | Codename | Target  | Key Features                                                                                       |
| ------- | -------- | ------- | -------------------------------------------------------------------------------------------------- |
| 0.1.0   | Sentinel | 2026-05-13 | First versioned release after rename from `kensa-go`. M1..M6 complete; M7 in progress. End-to-end atomicity validated on RHEL 9.6. Five binaries shipped, all statically linked. |
| 0.2.0   | Sentinel | TBD     | `--rules-dir` default-resolution (`/usr/share/kensa/rules`); grub deadman wiring; Phase 4 handler ports onto `kensa-systemd-helper` D-Bus primitives; first-principles tests for the ten currently-untested handlers. |
| 0.3.0   | Sentinel | TBD     | LL Phase 5 (AUDIT_NETLINK), LL Phase 6 (direct kernel IO sketches), expanded capability probes.    |
| 1.0.0   | TBD      | TBD     | Production-ready: atomicity contract published + signed, full rule corpus parity verified, OpenWatch v1 integration GA, multi-host orchestration. |

---

## Version History

| Version | Codename | Date       | Notes                                                                                              |
| ------- | -------- | ---------- | -------------------------------------------------------------------------------------------------- |
| 0.1.0   | Sentinel | 2026-05-13 | Initial versioned release. Module path renamed from `github.com/Hanalyx/kensa-go` to `github.com/Hanalyx/kensa`. Five binaries (`kensa`, `kensa-fuzz`, `kensa-validate`, `kensa-keygen`, `kensa-systemd-helper`). 56 Go test packages, 86 Specter specs at tier-threshold coverage, 225 CLI smoke scenarios. |

---

## References

- [Semantic Versioning 2.0.0](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- `docs/guide/` — operator guide (atomicity contract, rule schema, CLI reference)
- `CHANGELOG.md` — per-release notes

---

## Document History

| Version | Date       | Author | Changes                                                                                |
| ------- | ---------- | ------ | -------------------------------------------------------------------------------------- |
| v0.0.1  | 2026-05-13 | Claude | Initial versioning plan, modeled on the JWTMS template; adapted for kensa multi-binary suite, frozen `api/` v1 contract, and atomicity-contract change discipline. |
