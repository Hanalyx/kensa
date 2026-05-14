# Build Discipline

## Purpose

kensa-go is shipped as a single static Linux binary. No CGO, no shared libraries, no runtime dependencies beyond the system OpenSSH client (and `sshpass` if `--password` is used). This is non-negotiable for the kensa product — the binary must drop into a tarball or RPM and run on RHEL 8/9/10 + Ubuntu 22.04+ without surprises.

## Current state

DONE. Verified by `make build` followed by `file ./bin/kensa | grep "statically linked"`. CI gate enforces.

## Build matrix

| Target | Tool | Output | Discipline | Shipped |
|---|---|---|---|---|
| `kensa` | `cmd/kensa` | `bin/kensa` | CGO_ENABLED=0 + `-tags netgo` | M1 |
| `kensa-fuzz` | `cmd/kensa-fuzz` | `bin/kensa-fuzz` | same | M5 |
| `kensa-validate` | `cmd/kensa-validate` | `bin/kensa-validate` | same | M5 |
| `kensa-keygen` | `cmd/kensa-keygen` | `bin/kensa-keygen` | same | M-012 (2026-05-10) |
| `kensa-systemd-helper` | `cmd/kensa-systemd-helper` | `bin/kensa-systemd-helper` | same | Phase 4 D-007 (2026-05-13) |

All five binaries accept `--version` / `-V` (B7 fix, 2026-05-13). Each prints `<binary-name> <version>` on stdout and exits 0.

## Verification protocol

```bash
# 1. Clean build.
make build

# 2. Confirm static linkage on every binary.
for b in bin/kensa bin/kensa-fuzz bin/kensa-validate bin/kensa-keygen bin/kensa-systemd-helper; do
    if file "$b" | grep -q "statically linked"; then
        echo "OK  $b"
    else
        echo "FAIL $b"
        ldd "$b"   # diagnostic; should report "not a dynamic executable"
    fi
done

# 2b. Confirm --version works on every binary (B7 fix, 2026-05-13).
for b in bin/kensa bin/kensa-fuzz bin/kensa-validate bin/kensa-keygen bin/kensa-systemd-helper; do
    echo -n "$b: "; $b --version
done

# 3. Confirm no CGO.
go build -v ./cmd/kensa 2>&1 | grep -i "cgo" && echo "FAIL: cgo present"

# 4. Confirm netgo build tag honored.
go build -tags netgo -v ./cmd/kensa 2>&1 | grep -i "net/cgo" && echo "FAIL: cgo netresolver leaked"

# 5. Lint.
export PATH="$HOME/go/bin:$PATH"
golangci-lint run --config=.golangci.yml ./...

# 6. Specter pipeline.
export PATH="/home/rracine/.specter/bin:$PATH"
specter doctor       # pre-flight health check
specter check --strict
specter sync          # parse + resolve + check + coverage (warnings expected for engine specs)
```

## Specter pipeline state

| Stage | Status | Notes |
|---|---|---|
| `specter check --strict` | 48/48 PASS | All Tier-1 specs structural |
| `specter sync` | parse: PASS, resolve: PASS, check: PASS, coverage: WARN | Coverage warnings on engine-transaction, deadman-timer, transaction-log, evidence-envelope are pre-existing baseline (the M7 signer absence affects evidence coverage); no new warnings introduced by Phase 3..3.5 |
| `specter coverage --strict` | NOT YET ENABLED | Per CLAUDE.md, would demote every annotated AC because tests use Convention-Plain naming. Migration to Convention A or B is queued. |

## Dependency hygiene

```bash
# 1. List external deps.
go list -m all | grep -v "^github.com/Hanalyx/kensa-go" | head -20

# 2. Audit for known vulnerabilities.
go list -json -deps ./... | go run golang.org/x/vuln/cmd/govulncheck ./...
# OR if not installed:
go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
```

Notable deps:
- `github.com/spf13/pflag` — CLI parsing.
- `github.com/google/uuid` — transaction UUIDs.
- `github.com/jmoiron/sqlx` (or similar) — SQLite store.
- `github.com/johnfercher/maroto/v2` — PDF builder.
- `gopkg.in/yaml.v3` — YAML parser.
- `golang.org/x/term` — TTY detection (C-026 password prompt).

## CI gates

`.github/workflows/ci.yml` (per CLAUDE.md):

| Step | Gate |
|---|---|
| `go test ./...` | All tests pass |
| `make cli-smoke` | 99/99 |
| `golangci-lint run` | No findings |
| `specter sync` | parse / resolve / check pass |
| `make build` | Static linkage check |

## Known limits

- **No cross-compilation matrix.** kensa-go is built for linux/amd64. ARM64 / macOS / Windows builds aren't part of the CI matrix; operators wanting them must build from source.
- **No reproducible builds.** Build embeds `time.Now()` for the version string; two builds from the same commit produce different binaries. A future reproducible-build effort would strip the timestamp or use SOURCE_DATE_EPOCH.
- **No SBOM generation.** `go list -m all` is the closest we have. Operators wanting CycloneDX / SPDX SBOM must run `cyclonedx-gomod` or similar themselves.
- **`govulncheck` not in CI.** Manual run as part of release verification. Adding to CI is queued.
- **`specter coverage --strict` disabled.** Per CLAUDE.md.
- **No release-tag automation.** `make build` produces a `bin/` but no tarball / RPM / deb. Packaging is downstream.
